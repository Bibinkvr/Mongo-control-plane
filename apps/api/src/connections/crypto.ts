import { createCipheriv, createDecipheriv, randomBytes } from "node:crypto";

export type EncryptionKeyring = {
  currentVersion: number;
  keys: ReadonlyMap<number, Buffer>;
};

export type EncryptedConnectionSecret = {
  ciphertext: Buffer;
  nonce: Buffer;
  authTag: Buffer;
  wrappedDek: Buffer;
  wrapNonce: Buffer;
  wrapAuthTag: Buffer;
  keyVersion: number;
};

const ALGORITHM = "aes-256-gcm";
const NONCE_BYTES = 12;
const KEY_BYTES = 32;

function aad(purpose: "secret" | "dek", version: number): Buffer {
  return Buffer.from(
    purpose === "secret"
      ? "mongo-control-plane:connection:secret:v1"
      : "mongo-control-plane:connection:dek:v1:key:" + version,
    "utf8",
  );
}

function getKey(keyring: EncryptionKeyring, version: number): Buffer {
  const key = keyring.keys.get(version);
  if (!key || key.length !== KEY_BYTES) throw new Error(`Encryption key version ${version} is unavailable or invalid.`);
  return key;
}

function encrypt(data: Buffer, key: Buffer, associatedData: Buffer) {
  const nonce = randomBytes(NONCE_BYTES);
  const cipher = createCipheriv(ALGORITHM, key, nonce);
  cipher.setAAD(associatedData);
  const ciphertext = Buffer.concat([cipher.update(data), cipher.final()]);
  return { ciphertext, nonce, authTag: cipher.getAuthTag() };
}

function decrypt(ciphertext: Buffer, nonce: Buffer, authTag: Buffer, key: Buffer, associatedData: Buffer): Buffer {
  if (nonce.length !== NONCE_BYTES || authTag.length !== 16) throw new Error("Encrypted secret metadata is invalid.");
  const decipher = createDecipheriv(ALGORITHM, key, nonce);
  decipher.setAAD(associatedData);
  decipher.setAuthTag(authTag);
  return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
}

export function parseMongoConnectionUri(uri: string): { hostLabel: string } {
  if (uri.length < 10 || uri.length > 16_384 || /[\r\n\0]/.test(uri)) {
    throw new Error("MongoDB connection URI is invalid.");
  }
  let parsed: URL;
  try {
    parsed = new URL(uri);
  } catch {
    throw new Error("MongoDB connection URI is invalid.");
  }
  if (parsed.protocol !== "mongodb:" && parsed.protocol !== "mongodb+srv:") {
    throw new Error("Only mongodb:// and mongodb+srv:// connection URIs are supported.");
  }
  if (!parsed.hostname || parsed.hostname.length > 253) throw new Error("MongoDB connection URI must include a valid host.");
  if (parsed.protocol === "mongodb+srv:" && parsed.port) throw new Error("mongodb+srv:// URIs must not specify a port.");
  return { hostLabel: parsed.hostname.toLowerCase() };
}

export function encryptConnectionUri(uri: string, keyring: EncryptionKeyring): EncryptedConnectionSecret {
  parseMongoConnectionUri(uri);
  const version = keyring.currentVersion;
  const kek = getKey(keyring, version);
  const dek = randomBytes(KEY_BYTES);
  const secret = encrypt(Buffer.from(uri, "utf8"), dek, aad("secret", version));
  const wrapped = encrypt(dek, kek, aad("dek", version));
  dek.fill(0);
  return {
    ciphertext: secret.ciphertext,
    nonce: secret.nonce,
    authTag: secret.authTag,
    wrappedDek: wrapped.ciphertext,
    wrapNonce: wrapped.nonce,
    wrapAuthTag: wrapped.authTag,
    keyVersion: version,
  };
}

export function decryptConnectionUri(secret: EncryptedConnectionSecret, keyring: EncryptionKeyring): string {
  const kek = getKey(keyring, secret.keyVersion);
  const dek = decrypt(secret.wrappedDek, secret.wrapNonce, secret.wrapAuthTag, kek, aad("dek", secret.keyVersion));
  try {
    const plaintext = decrypt(secret.ciphertext, secret.nonce, secret.authTag, dek, aad("secret", secret.keyVersion));
    const uri = plaintext.toString("utf8");
    parseMongoConnectionUri(uri);
    return uri;
  } finally {
    dek.fill(0);
  }
}

/** Re-wraps the data-encryption key only; the MongoDB URI is never decrypted into application strings. */
export function rewrapConnectionSecret(secret: EncryptedConnectionSecret, keyring: EncryptionKeyring): EncryptedConnectionSecret {
  const targetVersion = keyring.currentVersion;
  if (secret.keyVersion === targetVersion) return secret;
  const oldKek = getKey(keyring, secret.keyVersion);
  const newKek = getKey(keyring, targetVersion);
  const dek = decrypt(secret.wrappedDek, secret.wrapNonce, secret.wrapAuthTag, oldKek, aad("dek", secret.keyVersion));
  try {
    const wrapped = encrypt(dek, newKek, aad("dek", targetVersion));
    return {
      ...secret,
      wrappedDek: wrapped.ciphertext,
      wrapNonce: wrapped.nonce,
      wrapAuthTag: wrapped.authTag,
      keyVersion: targetVersion,
    };
  } finally {
    dek.fill(0);
  }
}

export function parseEncryptionKeyring(raw: string | undefined, currentVersionRaw: string | undefined): EncryptionKeyring | undefined {
  if (!raw && !currentVersionRaw) return undefined;
  if (!raw || !currentVersionRaw || !/^\d+$/.test(currentVersionRaw)) {
    throw new Error("CONNECTION_ENCRYPTION_KEYS and CONNECTION_ENCRYPTION_CURRENT_VERSION must be configured together.");
  }
  let parsed: unknown;
  try { parsed = JSON.parse(raw); } catch { throw new Error("CONNECTION_ENCRYPTION_KEYS must be a JSON object of base64 keys."); }
  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
    throw new Error("CONNECTION_ENCRYPTION_KEYS must be a JSON object of base64 keys.");
  }
  const keys = new Map<number, Buffer>();
  for (const [versionText, value] of Object.entries(parsed)) {
    if (!/^\\d+$/.test(versionText) || typeof value !== "string") throw new Error("Encryption keyring entries must map numeric versions to base64 strings.");
    const key = Buffer.from(value, "base64");
    if (key.length !== KEY_BYTES || key.toString("base64") !== value) throw new Error(`Encryption key version ${versionText} must be canonical base64 for exactly 32 bytes.`);
    keys.set(Number(versionText), key);
  }
  const currentVersion = Number(currentVersionRaw);
  if (!Number.isSafeInteger(currentVersion) || currentVersion < 1 || !keys.has(currentVersion)) throw new Error("The current encryption key version must exist in the keyring.");
  return { currentVersion, keys };
}
