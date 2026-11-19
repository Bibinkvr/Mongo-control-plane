import { randomBytes } from "node:crypto";
import { mkdtemp, open, readFile, readdir, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Readable } from "node:stream";
import { afterEach, describe, expect, it } from "vitest";
import {
  deleteEncryptedBackup,
  decryptBackupToTemporaryFile,
  writeEncryptedBackup,
} from "../src/backups/encrypted-storage.js";

const projectId = "11111111-1111-4111-8111-111111111111";
const backupId = "22222222-2222-4222-8222-222222222222";
const keyring = { currentVersion: 1, keys: new Map([[1, randomBytes(32)]]) };

describe("encrypted backup storage", () => {
  const roots: string[] = [];
  afterEach(async () => {
    await Promise.all(roots.splice(0).map((root) => rm(root, { recursive: true, force: true })));
  });

  async function createRoot(): Promise<string> {
    const root = await mkdtemp(join(tmpdir(), "mcp-backup-test-"));
    roots.push(root);
    return root;
  }

  it("encrypts a streamed archive and verifies it before exposing restore plaintext", async () => {
    const root = await createRoot();
    const payload = Buffer.from("BSON archive test payload\n".repeat(100));
    const metadata = await writeEncryptedBackup(root, projectId, backupId, Readable.from(payload), keyring);

    expect(metadata.plaintextBytes).toBe(payload.length);
    expect(metadata.sha256).toMatch(/^[a-f0-9]{64}$/);
    expect(metadata.storageKey).toBe(`${projectId}/${backupId}.mcpbackup`);

    const restored = await decryptBackupToTemporaryFile(root, projectId, backupId, metadata, keyring);
    try {
      expect(await readFile(restored.path)).toEqual(payload);
    } finally {
      await restored.cleanup();
    }

    await deleteEncryptedBackup(root, projectId, backupId);
    expect(await readdir(join(root, projectId))).toEqual([]);
  });

  it("rejects modified ciphertext and removes incomplete restore plaintext", async () => {
    const root = await createRoot();
    const payload = Buffer.from("sensitive archive content");
    const metadata = await writeEncryptedBackup(root, projectId, backupId, Readable.from(payload), keyring);
    const filePath = join(root, projectId, `${backupId}.mcpbackup`);
    const file = await open(filePath, "r+");
    try {
      const byte = Buffer.alloc(1);
      await file.read(byte, 0, 1, 20);
      byte[0] = (byte[0] ?? 0) ^ 1;
      await file.write(byte, 0, 1, 20);
      await file.sync();
    } finally {
      await file.close();
    }

    await expect(decryptBackupToTemporaryFile(root, projectId, backupId, metadata, keyring)).rejects.toThrow();
  });

  it("rejects cross-project and cross-backup metadata substitution", async () => {
    const root = await createRoot();
    const metadata = await writeEncryptedBackup(root, projectId, backupId, Readable.from(Buffer.from("backup")), keyring);
    await expect(decryptBackupToTemporaryFile(
      root,
      "33333333-3333-4333-8333-333333333333",
      backupId,
      metadata,
      keyring,
    )).rejects.toThrow();
    await expect(decryptBackupToTemporaryFile(
      root,
      projectId,
      "44444444-4444-4444-8444-444444444444",
      metadata,
      keyring,
    )).rejects.toThrow();
  });

  it("enforces a size limit and removes partial objects on failure", async () => {
    const root = await createRoot();
    await expect(writeEncryptedBackup(
      root,
      projectId,
      backupId,
      Readable.from(Buffer.from("123456")),
      keyring,
      5,
    )).rejects.toThrow(/BACKUP_SIZE_LIMIT_EXCEEDED/);
    await expect(readdir(join(root, projectId))).rejects.toMatchObject({ code: "ENOENT" });
  });

  it("rejects non-UUID identifiers before touching storage", async () => {
    const root = await createRoot();
    await expect(writeEncryptedBackup(
      root,
      "../outside",
      backupId,
      Readable.from(Buffer.from("x")),
      keyring,
    )).rejects.toThrow(/UUID/);
  });
});
