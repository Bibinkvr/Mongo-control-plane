import { createCipheriv, createDecipheriv, randomBytes } from "node:crypto";
import { isIP } from "node:net";
import { domainToASCII } from "node:url";

export type EncryptionKeyring = { currentVersion: number; keys: ReadonlyMap<number, Buffer> };
export type ConnectionSecretContext = { projectId: string; connectionId: string };
export type EncryptedConnectionSecret = {
  ciphertext: Buffer; nonce: Buffer; authTag: Buffer; wrappedDek: Buffer;
  wrapNonce: Buffer; wrapAuthTag: Buffer; keyVersion: number;
  encryptionContextVersion: 1 | 2;
};
const ALGORITHM = "aes-256-gcm";
const NONCE_BYTES = 12;
const KEY_BYTES = 32;
const LEGACY_SECRET_AAD = Buffer.from("mongo-control-plane:connection:secret:v1", "utf8");
function dekAad(version: number): Buffer { return Buffer.from(`mongo-control-plane:connection:dek:v1:key:${version}`, "utf8"); }
function contextAad(purpose: "secret" | "dek", version: number, context: ConnectionSecretContext): Buffer {
  return Buffer.from(`mongo-control-plane:connection:${purpose}:v2:project:${context.projectId}:connection:${context.connectionId}${purpose === "dek" ? `:key:${version}` : ""}`, "utf8");
}
function getKey(keyring: EncryptionKeyring, version: number): Buffer {
  const key = keyring.keys.get(version);
  if (!key || key.length !== KEY_BYTES) throw new Error(`Encryption key version ${version} is unavailable or invalid.`);
  return key;
}
function encrypt(data: Buffer, key: Buffer, associatedData: Buffer) {
  const nonce = randomBytes(NONCE_BYTES); const cipher = createCipheriv(ALGORITHM, key, nonce);
  cipher.setAAD(associatedData); const ciphertext = Buffer.concat([cipher.update(data), cipher.final()]);
  return { ciphertext, nonce, authTag: cipher.getAuthTag() };
}
function decrypt(ciphertext: Buffer, nonce: Buffer, authTag: Buffer, key: Buffer, associatedData: Buffer): Buffer {
  if (nonce.length !== NONCE_BYTES || authTag.length !== 16) throw new Error("Encrypted secret metadata is invalid.");
  const decipher = createDecipheriv(ALGORITHM, key, nonce); decipher.setAAD(associatedData); decipher.setAuthTag(authTag);
  return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
}
function parseMongoHost(hostEntry: string, srv: boolean): string {
  let hostname = hostEntry;
  let port: string | undefined;
  let bracketedIpv6 = false;
  if (hostEntry.startsWith("[")) {
    const closing = hostEntry.indexOf("]");
    if (closing < 0) throw new Error("MongoDB IPv6 hosts must use brackets.");
    hostname = hostEntry.slice(1, closing);
    const suffix = hostEntry.slice(closing + 1);
    if (suffix) {
      if (!suffix.startsWith(":")) throw new Error("MongoDB host port is invalid.");
      port = suffix.slice(1);
    }
    bracketedIpv6 = true;
    if (isIP(hostname) !== 6) throw new Error("MongoDB bracketed hosts must be IPv6 addresses.");
  } else {
    const firstColon = hostEntry.indexOf(":");
    const lastColon = hostEntry.lastIndexOf(":");
    if (firstColon >= 0) {
      if (firstColon !== lastColon) throw new Error("MongoDB IPv6 hosts must use brackets.");
      hostname = hostEntry.slice(0, firstColon);
      port = hostEntry.slice(firstColon + 1);
    }
  }
  if (port !== undefined && (!/^\d+$/.test(port) || Number(port) < 1 || Number(port) > 65_535)) {
    throw new Error("MongoDB host port is invalid.");
  }
  if (srv && (port !== undefined || isIP(hostname) !== 0)) {
    throw new Error("mongodb+srv:// requires a DNS hostname and must not specify a port.");
  }
  if (bracketedIpv6) return `[${hostname.toLowerCase()}]`;
  if (isIP(hostname) === 4) return hostname;
  if (isIP(hostname) !== 0) throw new Error("MongoDB IP address syntax is invalid.");
  const ascii = domainToASCII(hostname).toLowerCase();
  const normalized = ascii.endsWith(".") ? ascii.slice(0, -1) : ascii;
  if (!normalized || normalized.length > 253) throw new Error("MongoDB hostname is invalid.");
  const labels = normalized.split(".");
  if (labels.some((label) => label.length < 1 || label.length > 63 || !/^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/.test(label))) {
    throw new Error("MongoDB hostname is invalid.");
  }
  return ascii;
}

export function parseMongoConnectionUri(uri: string): { hostLabel: string } {
  if (uri.length < 10 || uri.length > 16_384 || /[\r\n\0]/.test(uri)) throw new Error("MongoDB connection URI is invalid.");
  const match = /^(mongodb(?:\+srv)?:\/\/)([^/?#]+)(?:\/[^?#]*)?(?:\?([^#]*))?$/i.exec(uri);
  if (!match) throw new Error("MongoDB connection URI is invalid.");
  const srv = match[1]!.toLowerCase() === "mongodb+srv://";
  const authority = match[2]!;
  const at = authority.lastIndexOf("@");
  const hostList = at >= 0 ? authority.slice(at + 1) : authority;
  const entries = hostList.split(",");
  if (entries.length < 1 || entries.length > 64 || entries.some((entry) => entry.length === 0)) {
    throw new Error("MongoDB connection URI must include a valid host list.");
  }
  const hosts = entries.map((entry) => parseMongoHost(entry, srv));
  for (const [key, value] of new URLSearchParams(match[3] ?? "").entries()) {
    const normalizedKey = key.toLowerCase();
    const normalizedValue = value.toLowerCase();
    if ((normalizedKey === "tls" || normalizedKey === "ssl") && normalizedValue === "false") {
      throw new Error("MongoDB connection URIs must not disable TLS.");
    }
    if (["tlsinsecure", "tlsallowinvalidcertificates", "tlsallowinvalidhostnames"].includes(normalizedKey) && normalizedValue === "true") {
      throw new Error("MongoDB connection URIs must not disable TLS certificate or hostname validation.");
    }
  }
  return { hostLabel: hosts[0]!.toLowerCase() };
}mport { createCipheriv, createDecipheriv, randomBytes } from "node:crypto";
import { isIP } from "node:net";
import { domainToASCII } from "node:url";

export type EncryptionKeyring = { currentVersion: number; keys: ReadonlyMap<number, Buffer> };
export type ConnectionSecretContext = { projectId: string; connectionId: string };
export type EncryptedConnectionSecret = {
  ciphertext: Buffer; nonce: Buffer; authTag: Buffer; wrappedDek: Buffer;
  wrapNonce: Buffer; wrapAuthTag: Buffer; keyVersion: number;
  encryptionContextVersion: 1 | 2;
};
const ALGORITHM = "aes-256-gcm";
const NONCE_BYTES = 12;
const KEY_BYTES = 32;
const LEGACY_SECRET_AAD = Buffer.from("mongo-control-plane:connection:secret:v1", "utf8");
function dekAad(version: number): Buffer { return Buffer.from(`mongo-control-plane:connection:dek:v1:key:${version}`, "utf8"); }
function contextAad(purpose: "secret" | "dek", version: number, context: ConnectionSecretContext): Buffer {
  return Buffer.from(`mongo-control-plane:connection:${purpose}:v2:project:${context.projectId}:connection:${context.connectionId}${purpose === "dek" ? `:key:${version}` : ""}`, "utf8");
}
function getKey(keyring: EncryptionKeyring, version: number): Buffer {
  const key = keyring.keys.get(version);
  if (!key || key.length !== KEY_BYTES) throw new Error(`Encryption key version ${version} is unavailable or invalid.`);
  return key;
}
function encrypt(data: Buffer, key: Buffer, associatedData: Buffer) {
  const nonce = randomBytes(NONCE_BYTES); const cipher = createCipheriv(ALGORITHM, key, nonce);
  cipher.setAAD(associatedData); const ciphertext = Buffer.concat([cipher.update(data), cipher.final()]);
  return { ciphertext, nonce, authTag: cipher.getAuthTag() };
}
function decrypt(ciphertext: Buffer, nonce: Buffer, authTag: Buffer, key: Buffer, associatedData: Buffer): Buffer {
  if (nonce.length !== NONCE_BYTES || authTag.length !== 16) throw new Error("Encrypted secret metadata is invalid.");
  const decipher = createDecipheriv(ALGORITHM, key, nonce); decipher.setAAD(associatedData); decipher.setAuthTag(authTag);
  return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
}
export function parseMongoConnectionUri(uri: string): { hostLabel: string } {
  if (uri.length < 10 || uri.length > 16_384 || /[\r\n\0]/.test(uri)) throw new Error("MongoDB connection URI is invalid.");
  let parsed: URL; try { parsed = new URL(uri); } catch { throw new Error("MongoDB connection URI is invalid."); }
  if (parsed.protocol !== "mongodb:" && parsed.protocol !== "mongodb+srv:") throw new Error("Only mongodb:// and mongodb+srv:// connection URIs are supported.");
  if (!parsed.hostname || parsed.hostname.length > 253 || parsed.hash) throw new Error("MongoDB connection URI must include a valid host and no fragment.");
  if (parsed.protocol === "mongodb+srv:" && parsed.port) throw new Error("mongodb+srv:// URIs must not specify a port.");
  for (const [key, value] of parsed.searchParams.entries()) {
    const normalizedKey = key.toLowerCase();
    const normalizedValue = value.toLowerCase();
    if ((normalizedKey === "tls" || normalizedKey === "ssl") && normalizedValue === "false") {
      throw new Error("MongoDB connection URIs must not disable TLS.");
    }
    if (["tlsinsecure", "tlsallowinvalidcertificates", "tlsallowinvalidhostnames"].includes(normalizedKey) && normalizedValue === "true") {
      throw new Error("MongoDB connection URIs must not disable TLS certificate or hostname validation.");
    }
  }
  return { hostLabel: parsed.hostname.toLowerCase() };
}
export function encryptSecretString(value: string, keyring: EncryptionKeyring, context: ConnectionSecretContext): EncryptedConnectionSecret {
  if (!value || Buffer.byteLength(value, "utf8") > 16_384) throw new Error("Secret value is empty or too large.");
  const version = keyring.currentVersion;
  const kek = getKey(keyring, version);
  const dek = randomBytes(KEY_BYTES);
  const plaintext = Buffer.from(value, "utf8");
  try {
    const secret = encrypt(plaintext, dek, contextAad("secret", version, context));
    const wrapped = encrypt(dek, kek, contextAad("dek", version, context));
    return { ciphertext: secret.ciphertext, nonce: secret.nonce, authTag: secret.authTag,
      wrappedDek: wrapped.ciphertext, wrapNonce: wrapped.nonce, wrapAuthTag: wrapped.authTag,
      keyVersion: version, encryptionContextVersion: 2 };
  } finally { plaintext.fill(0); dek.fill(0); }
}
export function decryptSecretString(secret: EncryptedConnectionSecret, keyring: EncryptionKeyring, context: ConnectionSecretContext): string {
  if (secret.encryptionContextVersion !== 2) throw new Error("Legacy secret format is not supported.");
  const kek = getKey(keyring, secret.keyVersion);
  const dek = decrypt(secret.wrappedDek, secret.wrapNonce, secret.wrapAuthTag, kek, contextAad("dek", secret.keyVersion, context));
  let plaintext: Buffer | undefined;
  try {
    plaintext = decrypt(secret.ciphertext, secret.nonce, secret.authTag, dek, contextAad("secret", secret.keyVersion, context));
    const value = plaintext.toString("utf8");
    if (!value) throw new Error("Decrypted secret is empty.");
    return value;
  } finally { plaintext?.fill(0); dek.fill(0); }
}

export function encryptConnectionUri(uri: string, keyring: EncryptionKeyring, context: ConnectionSecretContext): EncryptedConnectionSecret {
  parseMongoConnectionUri(uri);
  return encryptSecretString(uri, keyring, context);
}
export function decryptConnectionUri(secret: EncryptedConnectionSecret, keyring: EncryptionKeyring, context: ConnectionSecretContext): string {
  const kek = getKey(keyring, secret.keyVersion); const legacy = secret.encryptionContextVersion === 1;
  const dek = decrypt(secret.wrappedDek, secret.wrapNonce, secret.wrapAuthTag, kek,
    legacy ? dekAad(secret.keyVersion) : contextAad("dek", secret.keyVersion, context));
  let plaintext: Buffer | undefined;
  try {
    plaintext = decrypt(secret.ciphertext, secret.nonce, secret.authTag, dek,
      legacy ? LEGACY_SECRET_AAD : contextAad("secret", secret.keyVersion, context));
    const uri = plaintext.toString("utf8"); parseMongoConnectionUri(uri); return uri;
  } finally { plaintext?.fill(0); dek.fill(0); }
}
export function rewrapConnectionSecret(secret: EncryptedConnectionSecret, keyring: EncryptionKeyring, context: ConnectionSecretContext): EncryptedConnectionSecret {
  const targetVersion = keyring.currentVersion; if (secret.keyVersion === targetVersion) return secret;
  const oldKek = getKey(keyring, secret.keyVersion); const newKek = getKey(keyring, targetVersion);
  const legacy = secret.encryptionContextVersion === 1;
  const oldAad = legacy ? dekAad(secret.keyVersion) : contextAad("dek", secret.keyVersion, context);
  const newAad = legacy ? dekAad(targetVersion) : contextAad("dek", targetVersion, context);
  const dek = decrypt(secret.wrappedDek, secret.wrapNonce, secret.wrapAuthTag, oldKek, oldAad);
  try {
    const wrapped = encrypt(dek, newKek, newAad);
    return { ...secret, wrappedDek: wrapped.ciphertext, wrapNonce: wrapped.nonce, wrapAuthTag: wrapped.authTag, keyVersion: targetVersion };
  } finally { dek.fill(0); }
}
export function parseEncryptionKeyring(raw: string | undefined, currentVersionRaw: string | undefined): EncryptionKeyring | undefined {
  if (!raw && !currentVersionRaw) return undefined;
  if (!raw || !currentVersionRaw || !/^\d+$/.test(currentVersionRaw)) throw new Error("CONNECTION_ENCRYPTION_KEYS and CONNECTION_ENCRYPTION_CURRENT_VERSION must be configured together.");
  let parsed: unknown; try { parsed = JSON.parse(raw); } catch { throw new Error("CONNECTION_ENCRYPTION_KEYS must be a JSON object of base64 keys."); }
  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) throw new Error("CONNECTION_ENCRYPTION_KEYS must be a JSON object of base64 keys.");
  const keys = new Map<number, Buffer>();
  for (const [versionText, value] of Object.entries(parsed)) {
    if (!/^\d+$/.test(versionText) || typeof value !== "string") throw new Error("Encryption keyring entries must map numeric versions to base64 strings.");
    const version = Number(versionText); if (!Number.isSafeInteger(version) || version < 1) throw new Error("Encryption key versions must be positive safe integers.");
    const key = Buffer.from(value, "base64");
    if (key.length !== KEY_BYTES || key.toString("base64") !== value) throw new Error(`Encryption key version ${versionText} must be canonical base64 for exactly 32 bytes.`);
    keys.set(version, key);
  }
  const currentVersion = Number(currentVersionRaw);
  if (!Number.isSafeInteger(currentVersion) || currentVersion < 1 || !keys.has(currentVersion)) throw new Error("The current encryption key version must exist in the keyring.");
  return { currentVersion, keys };
}
