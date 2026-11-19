import { chmod, mkdtemp, readFile, readdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { randomBytes } from "node:crypto";
import { decryptBackupToTemporaryFile } from "../src/backups/encrypted-storage.js";
import { DatabaseToolsError, runMongodumpToEncryptedStorage } from "../src/backups/database-tools.js";

const projectId = "11111111-1111-4111-8111-111111111111";
const backupId = "22222222-2222-4222-8222-222222222222";
const databaseName = "mcp_aaaaaaaaaaaaaaaa_bbbbbbbbbbbbbbbb";
const keyring = { currentVersion: 1, keys: new Map([[1, randomBytes(32)]]) };
const uri = "mongodb://backup-user:backup-secret@localhost:27017/app?tls=true";

describe("mongodump adapter", () => {
  const roots: string[] = [];
  afterEach(async () => {
    await Promise.all(roots.splice(0).map((root) => rm(root, { recursive: true, force: true })));
  });

  async function makeRoot(): Promise<string> {
    const root = await mkdtemp(join(tmpdir(), "mcp-mongodump-test-"));
    roots.push(root);
    return root;
  }

  async function makeFakeMongodump(exitCode = 0): Promise<string> {
    const directory = await mkdtemp(join(tmpdir(), "mcp-mongodump-bin-"));
    roots.push(directory);
    const executable = join(directory, "mongodump");
    const script = `#!/usr/bin/env node
const fs = require("node:fs");
if (process.argv[2] === "--version") {
  process.stdout.write("mongodump version: 100.3.0\\n");
  process.exit(0);
}
const args = process.argv.slice(2);
const config = fs.readFileSync(args[1], "utf8");
if (args[0] !== "--config" || !config.startsWith('uri: "mongodb://')) process.exit(11);
if (args[2] !== "--archive" || args[3] !== "--gzip") process.exit(12);
if (args[4] !== "--nsInclude" || args[5] !== "${databaseName}.*") process.exit(13);
process.stdout.write("test-archive-payload");
process.exit(${exitCode});
`;
    await writeFile(executable, script, { encoding: "utf8", mode: 0o700 });
    await chmod(executable, 0o700);
    return executable;
  }

  it("uses a protected URI config, fixed namespace filter and encrypted archive output", async () => {
    const root = await makeRoot();
    const executablePath = await makeFakeMongodump();
    const metadata = await runMongodumpToEncryptedStorage({
      executablePath, uri, databaseName, storageRoot: root, projectId, backupId,
      keyring, maxBytes: 1_000_000, timeoutMs: 10_000,
    });
    const restored = await decryptBackupToTemporaryFile(root, projectId, backupId, metadata, keyring);
    try {
      expect(await readFile(restored.path, "utf8")).toBe("test-archive-payload");
    } finally {
      await restored.cleanup();
    }
  });

  it("deletes the encrypted object when mongodump exits unsuccessfully", async () => {
    const root = await makeRoot();
    const executablePath = await makeFakeMongodump(9);
    await expect(runMongodumpToEncryptedStorage({
      executablePath, uri, databaseName, storageRoot: root, projectId, backupId,
      keyring, maxBytes: 1_000_000, timeoutMs: 10_000,
    })).rejects.toMatchObject({ code: "TOOL_FAILED" });
    expect(await readdir(join(root, projectId))).toEqual([]);
  });

  it("rejects unsupported Database Tools versions before starting a dump", async () => {
    const root = await makeRoot();
    const directory = await mkdtemp(join(tmpdir(), "mcp-mongodump-old-"));
    roots.push(directory);
    const executablePath = join(directory, "mongodump");
    await writeFile(executablePath, '#!/bin/sh\necho "mongodump version: 100.2.9"\n', { mode: 0o700 });
    await chmod(executablePath, 0o700);
    await expect(runMongodumpToEncryptedStorage({
      executablePath, uri, databaseName, storageRoot: root, projectId, backupId,
      keyring, maxBytes: 1_000_000, timeoutMs: 10_000,
    })).rejects.toBeInstanceOf(DatabaseToolsError);
  });

  it("rejects unsafe database names and non-absolute executable paths", async () => {
    const root = await makeRoot();
    await expect(runMongodumpToEncryptedStorage({
      executablePath: "mongodump", uri, databaseName: "admin", storageRoot: root, projectId, backupId,
      keyring, maxBytes: 1_000_000, timeoutMs: 10_000,
    })).rejects.toMatchObject({ code: "TOOL_FAILED" });
  });
});
