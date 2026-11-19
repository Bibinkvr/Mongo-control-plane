import { constants } from "node:fs";
import { access, chmod, mkdtemp, realpath, rm, stat, writeFile } from "node:fs/promises";
import { spawn, type ChildProcess } from "node:child_process";
import { tmpdir } from "node:os";
import { isAbsolute, join } from "node:path";
import { parseMongoConnectionUri, type EncryptionKeyring } from "../connections/crypto.js";
import {
  deleteEncryptedBackup,
  writeEncryptedBackup,
  type EncryptedBackupMetadata,
} from "./encrypted-storage.js";

export class DatabaseToolsError extends Error {
  constructor(
    public readonly code: "TOOL_UNAVAILABLE" | "TOOL_VERSION_UNSUPPORTED" | "TOOL_TIMEOUT" | "TOOL_FAILED" | "BACKUP_CANCELLED",
    message: string,
    public readonly diagnosticCode?: string,
    public readonly diagnosticMessage?: string,
  ) {
    super(message);
    this.name = "DatabaseToolsError";
  }
}

type ExitResult = { code: number | null; signal: NodeJS.Signals | null };

function childExit(child: ChildProcess): Promise<ExitResult> {
  return new Promise((resolve, reject) => {
    child.once("error", reject);
    child.once("close", (code, signal) => resolve({ code, signal }));
  });
}

async function resolveExecutable(path: string): Promise<string> {
  if (!isAbsolute(path)) throw new DatabaseToolsError("TOOL_UNAVAILABLE", "Database Tools executable path must be absolute.");
  try {
    const resolved = await realpath(path);
    const info = await stat(resolved);
    if (!info.isFile()) throw new Error("not a file");
    await access(resolved, constants.X_OK);
    return resolved;
  } catch {
    throw new DatabaseToolsError("TOOL_UNAVAILABLE", "The configured mongodump executable is unavailable.");
  }
}

async function verifyMongodumpVersion(executable: string): Promise<void> {
  const child = spawn(executable, ["--version"], {
    shell: false,
    windowsHide: true,
    stdio: ["ignore", "pipe", "ignore"],
    env: { PATH: process.env["PATH"] ?? "", LANG: "C", LC_ALL: "C" },
  });
  const exit = childExit(child);
  let output = "";
  child.stdout?.setEncoding("utf8");
  child.stdout?.on("data", (chunk: string) => {
    output = (output + chunk).slice(-4096);
  });
  const timeout = setTimeout(() => child.kill("SIGKILL"), 10_000);
  timeout.unref();
  let result: ExitResult;
  try {
    result = await exit;
  } catch {
    throw new DatabaseToolsError("TOOL_UNAVAILABLE", "Could not execute mongodump.");
  } finally {
    clearTimeout(timeout);
  }
  const match = /mongodump version:\s*(\d+)\.(\d+)\.(\d+)/i.exec(output);
  if (result.code !== 0 || !match) {
    throw new DatabaseToolsError("TOOL_VERSION_UNSUPPORTED", "mongodump must report a supported Database Tools version.");
  }
  const version = match.slice(1).map(Number);
  if (version[0]! < 100 || (version[0] === 100 && version[1]! < 3)) {
    throw new DatabaseToolsError("TOOL_VERSION_UNSUPPORTED", "mongodump 100.3.0 or newer is required for protected URI configuration files.");
  }
}

export async function runMongodumpToEncryptedStorage(input: {
  executablePath: string;
  uri: string;
  databaseName: string;
  storageRoot: string;
  projectId: string;
  backupId: string;
  keyring: EncryptionKeyring;
  maxBytes: number;
  timeoutMs: number;
  signal?: AbortSignal;
}): Promise<EncryptedBackupMetadata> {
  if (!/^mcp_[a-f0-9]{16}_[a-f0-9]{16}$/.test(input.databaseName)) {
    throw new DatabaseToolsError("TOOL_FAILED", "Backup target database name is invalid.");
  }
  if (!Number.isSafeInteger(input.timeoutMs) || input.timeoutMs < 1_000 || input.timeoutMs > 86_400_000) {
    throw new DatabaseToolsError("TOOL_FAILED", "Backup execution timeout is invalid.");
  }
  if (input.signal?.aborted) throw new DatabaseToolsError("BACKUP_CANCELLED", "Backup execution was cancelled.");
  parseMongoConnectionUri(input.uri);
  const uriOptions = new URLSearchParams(input.uri.split("?")[1] ?? "");
  if (uriOptions.get("tls") !== "true" && uriOptions.get("ssl") !== "true") {
    throw new DatabaseToolsError("TOOL_FAILED", "Backup connections must explicitly enable TLS.");
  }

  const executable = await resolveExecutable(input.executablePath);
  await verifyMongodumpVersion(executable);

  const configDirectory = await mkdtemp(join(tmpdir(), "mcp-mongodump-"));
  const configPath = join(configDirectory, "mongodump.yaml");

  let child: ChildProcess | undefined;
  let exitPromise: Promise<ExitResult> | undefined;
  let killTimer: NodeJS.Timeout | undefined;
  let timeoutTimer: NodeJS.Timeout | undefined;
  let metadata: EncryptedBackupMetadata | undefined;
  let timedOut = false;
  let cancelled = false;
  const terminate = () => {
    if (!child || child.killed) return;
    child.kill("SIGTERM");
    killTimer ??= setTimeout(() => child?.kill("SIGKILL"), 5_000);
    killTimer.unref();
  };
  const onAbort = () => {
    cancelled = true;
    terminate();
  };

  try {
    await chmod(configDirectory, 0o700);
    const yaml = `uri: ${JSON.stringify(input.uri)}\n`;
    await writeFile(configPath, yaml, { encoding: "utf8", mode: 0o600, flag: "wx" });
    child = spawn(executable, [
      "--config", configPath,
      "--archive",
      "--gzip",
      "--nsInclude", `${input.databaseName}.*`,
    ], {
      shell: false,
      windowsHide: true,
      cwd: configDirectory,
      stdio: ["ignore", "pipe", "ignore"],
      env: { PATH: process.env["PATH"] ?? "", LANG: "C", LC_ALL: "C" },
    });
    exitPromise = childExit(child);
    if (!child.stdout) throw new DatabaseToolsError("TOOL_FAILED", "mongodump did not provide an archive stream.");

    timeoutTimer = setTimeout(() => {
      timedOut = true;
      terminate();
    }, input.timeoutMs);
    timeoutTimer.unref();
    input.signal?.addEventListener("abort", onAbort, { once: true });

    const storagePromise = writeEncryptedBackup(
      input.storageRoot,
      input.projectId,
      input.backupId,
      child.stdout,
      input.keyring,
      input.maxBytes,
    ).then((result) => {
      metadata = result;
      return result;
    });
    const [stored, exit] = await Promise.all([storagePromise, exitPromise]);
    if (timedOut) throw new DatabaseToolsError("TOOL_TIMEOUT", "mongodump exceeded its execution deadline.");
    if (cancelled) throw new DatabaseToolsError("BACKUP_CANCELLED", "Backup execution was cancelled.");
    if (exit.code !== 0) throw new DatabaseToolsError("TOOL_FAILED", "mongodump exited unsuccessfully.", `EXIT_${exit.code ?? "UNKNOWN"}`);
    return stored;
  } catch (error) {
    terminate();
    if (exitPromise) await exitPromise.catch(() => undefined);
    if (metadata) {
      await deleteEncryptedBackup(input.storageRoot, input.projectId, input.backupId).catch(() => undefined);
    }
    if (error instanceof DatabaseToolsError) throw error;
    if (timedOut) throw new DatabaseToolsError("TOOL_TIMEOUT", "mongodump exceeded its execution deadline.");
    if (cancelled) throw new DatabaseToolsError("BACKUP_CANCELLED", "Backup execution was cancelled.");
    const diagnosticCode = typeof error === "object" && error !== null && "code" in error
      && typeof error.code === "string" ? error.code
      : error instanceof Error ? error.name : "UNKNOWN";
    const diagnosticMessage = error instanceof Error
      ? error.message.replace(/mongodb(?:\+srv)?:\/\/[^\s]+/gi, "<redacted-uri>").slice(0, 120)
      : "Unknown adapter failure";
    throw new DatabaseToolsError("TOOL_FAILED", "mongodump or encrypted storage failed.", diagnosticCode, diagnosticMessage);
  } finally {
    if (timeoutTimer) clearTimeout(timeoutTimer);
    if (killTimer) clearTimeout(killTimer);
    input.signal?.removeEventListener("abort", onAbort);
    await rm(configDirectory, { recursive: true, force: true });
  }
}
