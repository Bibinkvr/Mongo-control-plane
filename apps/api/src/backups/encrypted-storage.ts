import { createCipheriv, createDecipheriv, createHash, randomBytes, timingSafeEqual } from "node:crypto";
import { createReadStream, createWriteStream } from "node:fs";
import { appendFile, chmod, link, lstat, mkdir, mkdtemp, open, realpath, rm, unlink } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, parse, relative, resolve, sep } from "node:path";
import { Transform, type Readable } from "node:stream";
import { pipeline } from "node:stream/promises";
import type { EncryptionKeyring } from "../connections/crypto.js";

const MAGIC = Buffer.from("MCPBACK1", "ascii");
const NONCE_BYTES = 12;
const TAG_BYTES = 16;
const HEADER_BYTES = MAGIC.length + NONCE_BYTES;
const KEY_BYTES = 32;
const DEFAULT_MAX_BACKUP_BYTES = 20 * 1024 * 1024 * 1024;
const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

export type EncryptedBackupMetadata = {
  storageKey: string;
  nonce: Buffer;
  authTag: Buffer;
  wrappedDek: Buffer;
  wrapNonce: Buffer;
  wrapAuthTag: Buffer;
  keyVersion: number;
  plaintextBytes: number;
  sha256: string;
};

function assertIds(projectId: string, backupId: string): void {
  if (!UUID_PATTERN.test(projectId) || !UUID_PATTERN.test(backupId)) {
    throw new Error("Backup project and backup IDs must be UUIDs.");
  }
}

function getKey(keyring: EncryptionKeyring, version: number): Buffer {
  if (!Number.isSafeInteger(version) || version < 1) throw new Error("Backup encryption key version is invalid.");
  const key = keyring.keys.get(version);
  if (!key || key.length !== KEY_BYTES) throw new Error("Backup encryption key version is unavailable or invalid.");
  return key;
}

function payloadAad(projectId: string, backupId: string): Buffer {
  return Buffer.from(`mongo-control-plane:backup:payload:v1:project:${projectId}:backup:${backupId}`, "utf8");
}

function wrapAad(projectId: string, backupId: string, version: number): Buffer {
  return Buffer.from(`mongo-control-plane:backup:dek:v1:project:${projectId}:backup:${backupId}:key:${version}`, "utf8");
}

async function ensurePrivateDirectory(path: string): Promise<string> {
  const absolutePath = resolve(path);
  if (absolutePath === parse(absolutePath).root || absolutePath === resolve(process.cwd())) {
    throw new Error("Backup storage root must be a dedicated directory.");
  }
  await mkdir(absolutePath, { recursive: true, mode: 0o700 });
  const info = await lstat(path);
  if (!info.isDirectory() || info.isSymbolicLink()) {
    throw new Error("Backup storage path must be a real directory, not a symbolic link.");
  }
  await chmod(path, 0o700);
  return realpath(path);
}

function assertWithinRoot(root: string, target: string): void {
  const rel = relative(root, target);
  if (!rel || rel === ".." || rel.startsWith(`..${sep}`) || resolve(root, rel) !== target) {
    throw new Error("Backup storage path escaped its configured root.");
  }
}

async function readExactAt(handle: Awaited<ReturnType<typeof open>>, buffer: Buffer, position: number): Promise<void> {
  let offset = 0;
  while (offset < buffer.length) {
    const result = await handle.read(buffer, offset, buffer.length - offset, position + offset);
    if (result.bytesRead === 0) throw new Error("Backup file is truncated.");
    offset += result.bytesRead;
  }
}

async function syncDirectory(path: string): Promise<void> {
  if (process.platform === "win32") return;
  const handle = await open(path, "r");
  try { await handle.sync(); } finally { await handle.close(); }
}

/**
 * Encrypts a backup stream with a random per-backup DEK and publishes it atomically.
 * The returned envelope metadata must be committed to PostgreSQL before the backup
 * is considered available. The storage key is always derived from UUIDs.
 */
export async function writeEncryptedBackup(
  storageRoot: string,
  projectId: string,
  backupId: string,
  source: Readable,
  keyring: EncryptionKeyring,
  maxBytes = DEFAULT_MAX_BACKUP_BYTES,
): Promise<EncryptedBackupMetadata> {
  assertIds(projectId, backupId);
  if (!Number.isSafeInteger(maxBytes) || maxBytes < 1 || maxBytes > DEFAULT_MAX_BACKUP_BYTES) {
    throw new Error("Backup size limit is invalid.");
  }

  if (!storageRoot.trim()) throw new Error("Backup storage root is required.");
  const root = await ensurePrivateDirectory(resolve(storageRoot));
  const projectDirectory = await ensurePrivateDirectory(join(root, projectId));
  const finalPath = resolve(projectDirectory, `${backupId}.mcpbackup`);
  const temporaryPath = `${finalPath}.partial`;
  assertWithinRoot(root, finalPath);
  assertWithinRoot(root, temporaryPath);

  const keyVersion = keyring.currentVersion;
  const kek = getKey(keyring, keyVersion);
  const dek = randomBytes(KEY_BYTES);
  const nonce = randomBytes(NONCE_BYTES);
  const wrapNonce = randomBytes(NONCE_BYTES);
  const cipher = createCipheriv("aes-256-gcm", dek, nonce);
  cipher.setAAD(payloadAad(projectId, backupId));
  const wrapCipher = createCipheriv("aes-256-gcm", kek, wrapNonce);
  wrapCipher.setAAD(wrapAad(projectId, backupId, keyVersion));
  const wrappedDek = Buffer.concat([wrapCipher.update(dek), wrapCipher.final()]);
  const wrapAuthTag = wrapCipher.getAuthTag();

  const hash = createHash("sha256");
  let plaintextBytes = 0;
  let published = false;
  try {
    const output = createWriteStream(temporaryPath, { flags: "wx", mode: 0o600 });
    output.write(MAGIC);
    output.write(nonce);
    const meter = new Transform({
      transform(chunk: Buffer, _encoding, callback) {
        plaintextBytes += chunk.length;
        if (plaintextBytes > maxBytes) {
          callback(new Error("BACKUP_SIZE_LIMIT_EXCEEDED"));
          return;
        }
        hash.update(chunk);
        callback(null, chunk);
      },
    });
    await pipeline(source, meter, cipher, output);
    if (plaintextBytes === 0) throw new Error("BACKUP_EMPTY");
    const authTag = cipher.getAuthTag();
    await appendFile(temporaryPath, authTag, { mode: 0o600 });
    const fileHandle = await open(temporaryPath, "r+");
    try { await fileHandle.sync(); } finally { await fileHandle.close(); }
    await link(temporaryPath, finalPath);
    published = true;
    await unlink(temporaryPath);
    await syncDirectory(projectDirectory);

    return {
      storageKey: `${projectId}/${backupId}.mcpbackup`,
      nonce,
      authTag,
      wrappedDek,
      wrapNonce,
      wrapAuthTag,
      keyVersion,
      plaintextBytes,
      sha256: hash.digest("hex"),
    };
  } catch (error) {
    await rm(temporaryPath, { force: true }).catch(() => undefined);
    if (published) await rm(finalPath, { force: true }).catch(() => undefined);
    throw error;
  } finally {
    dek.fill(0);
  }
}

/**
 * Decrypts and authenticates the complete backup into a private temporary file.
 * Restore tools must not consume plaintext until this function resolves, because
 * AES-GCM authentication is only established after the final block is processed.
 */
export async function decryptBackupToTemporaryFile(
  storageRoot: string,
  projectId: string,
  backupId: string,
  metadata: EncryptedBackupMetadata,
  keyring: EncryptionKeyring,
): Promise<{ path: string; cleanup: () => Promise<void> }> {
  assertIds(projectId, backupId);
  const expectedStorageKey = `${projectId}/${backupId}.mcpbackup`;
  if (metadata.storageKey !== expectedStorageKey) throw new Error("Backup storage key does not match its owner.");
  if (metadata.nonce.length !== NONCE_BYTES || metadata.authTag.length !== TAG_BYTES
    || metadata.wrapNonce.length !== NONCE_BYTES || metadata.wrapAuthTag.length !== TAG_BYTES
    || !Number.isSafeInteger(metadata.plaintextBytes) || metadata.plaintextBytes < 1 || metadata.plaintextBytes > DEFAULT_MAX_BACKUP_BYTES
    || !/^[a-f0-9]{64}$/.test(metadata.sha256)) {
    throw new Error("Backup encryption metadata is invalid.");
  }

  const root = await ensurePrivateDirectory(resolve(storageRoot));
  const projectDirectory = resolve(root, projectId);
  const projectInfo = await lstat(projectDirectory);
  if (!projectInfo.isDirectory() || projectInfo.isSymbolicLink()) throw new Error("Backup project directory is invalid.");
  const filePath = resolve(projectDirectory, `${backupId}.mcpbackup`);
  assertWithinRoot(root, filePath);
  const fileInfo = await lstat(filePath);
  if (!fileInfo.isFile() || fileInfo.isSymbolicLink() || fileInfo.size <= HEADER_BYTES + TAG_BYTES
    || fileInfo.size - HEADER_BYTES - TAG_BYTES !== metadata.plaintextBytes) {
    throw new Error("Backup object is missing or invalid.");
  }

  const handle = await open(filePath, "r");
  let header: Buffer;
  let footer: Buffer;
  try {
    header = Buffer.alloc(HEADER_BYTES);
    footer = Buffer.alloc(TAG_BYTES);
    await readExactAt(handle, header, 0);
    await readExactAt(handle, footer, fileInfo.size - TAG_BYTES);
  } finally {
    await handle.close();
  }
  if (!header.subarray(0, MAGIC.length).equals(MAGIC)
    || !timingSafeEqual(header.subarray(MAGIC.length), metadata.nonce)
    || !timingSafeEqual(footer, metadata.authTag)) {
    throw new Error("Backup file header or authentication metadata does not match.");
  }

  const kek = getKey(keyring, metadata.keyVersion);
  const dek = createDecipheriv("aes-256-gcm", kek, metadata.wrapNonce);
  dek.setAAD(wrapAad(projectId, backupId, metadata.keyVersion));
  dek.setAuthTag(metadata.wrapAuthTag);
  const dataKey = Buffer.concat([dek.update(metadata.wrappedDek), dek.final()]);
  if (dataKey.length !== KEY_BYTES) {
    dataKey.fill(0);
    throw new Error("Backup data key is invalid.");
  }

  const decipher = createDecipheriv("aes-256-gcm", dataKey, metadata.nonce);
  decipher.setAAD(payloadAad(projectId, backupId));
  decipher.setAuthTag(metadata.authTag);
  const hash = createHash("sha256");
  let plaintextBytes = 0;
  const meter = new Transform({
    transform(chunk: Buffer, _encoding, callback) {
      plaintextBytes += chunk.length;
      hash.update(chunk);
      callback(null, chunk);
    },
  });

  let temporaryDirectory: string | undefined;
  try {
    temporaryDirectory = await mkdtemp(join(tmpdir(), "mcp-backup-"));
    await chmod(temporaryDirectory, 0o700);
    const plaintextPath = join(temporaryDirectory, "restore.archive");
    await pipeline(
      createReadStream(filePath, { start: HEADER_BYTES, end: fileInfo.size - TAG_BYTES - 1 }),
      decipher,
      meter,
      createWriteStream(plaintextPath, { flags: "wx", mode: 0o600 }),
    );
    const actualHash = Buffer.from(hash.digest("hex"), "hex");
    const expectedHash = Buffer.from(metadata.sha256, "hex");
    if (plaintextBytes !== metadata.plaintextBytes || !timingSafeEqual(actualHash, expectedHash)) {
      throw new Error("Backup integrity verification failed.");
    }
    return {
      path: plaintextPath,
      cleanup: async () => rm(temporaryDirectory!, { recursive: true, force: true }),
    };
  } catch (error) {
    if (temporaryDirectory) await rm(temporaryDirectory, { recursive: true, force: true }).catch(() => undefined);
    throw error;
  } finally {
    dataKey.fill(0);
  }
}

/** Deletes only the canonical object for a project-owned backup ID. */
export async function deleteEncryptedBackup(
  storageRoot: string,
  projectId: string,
  backupId: string,
): Promise<void> {
  assertIds(projectId, backupId);
  const root = await ensurePrivateDirectory(resolve(storageRoot));
  const projectDirectory = resolve(root, projectId);
  try {
    const projectInfo = await lstat(projectDirectory);
    if (!projectInfo.isDirectory() || projectInfo.isSymbolicLink()) throw new Error("Backup project directory is invalid.");
    const filePath = resolve(projectDirectory, `${backupId}.mcpbackup`);
    assertWithinRoot(root, filePath);
    const fileInfo = await lstat(filePath);
    if (!fileInfo.isFile() || fileInfo.isSymbolicLink()) throw new Error("Backup object is invalid.");
    await unlink(filePath);
    await syncDirectory(projectDirectory);
  } catch (error) {
    if (typeof error === "object" && error !== null && "code" in error && error.code === "ENOENT") return;
    throw error;
  }
}
