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
    const script = `#!/bin/sh
if [ "$1" = "--version" ]; then
  echo "mongodump version: 100.3.0"
  exit 0
fi
[ "$1" = "--config" ] || exit 11
[ -f "$2" ] || exit 12
grep -q '^uri: "mongodb://' "$2" || exit 13
shift 2
[ "$1" = "--archive" ] || exit 14
[ "$2" = "--gzip" ] || exit 15
[ "$3" = "--nsInclude" ] || exit 16
[ "$4" = "${databaseName}.*" ] || exit 17
printf "test-archive-payload"
exit ${exitCode}
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
    await expect(readdir(join(root, projectId))).rejects.toMatchObject({ code: "ENOENT" });
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
