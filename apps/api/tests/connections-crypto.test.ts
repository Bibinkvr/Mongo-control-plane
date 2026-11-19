import { createCipheriv, randomBytes } from "node:crypto";
import { describe, expect, it } from "vitest";
import {
  decryptConnectionUri, encryptConnectionUri, parseEncryptionKeyring,
  parseMongoConnectionUri, rewrapConnectionSecret,
} from "../src/connections/crypto.js";

const oldKey = randomBytes(32);
const newKey = randomBytes(32);
const oldRing = { currentVersion: 1, keys: new Map([[1, oldKey]]) };
const rotatedRing = { currentVersion: 2, keys: new Map([[1, oldKey], [2, newKey]]) };
const uri = "mongodb://user:secret@db.example.com:27017/app?retryWrites=true";
const context = { projectId: "11111111-1111-4111-8111-111111111111", connectionId: "22222222-2222-4222-8222-222222222222" };

describe("connection secret envelope encryption", () => {
  it("encrypts and decrypts a MongoDB URI without storing plaintext", () => {
    const encrypted = encryptConnectionUri(uri, oldRing, context);
    expect(encrypted.ciphertext.includes(Buffer.from("secret"))).toBe(false);
    expect(decryptConnectionUri(encrypted, oldRing, context)).toBe(uri);
  });

  it("rejects moving an encrypted envelope to another project or connection", () => {
    const encrypted = encryptConnectionUri(uri, oldRing, context);
    expect(() => decryptConnectionUri(encrypted, oldRing, { ...context, projectId: "33333333-3333-4333-8333-333333333333" })).toThrow();
    expect(() => decryptConnectionUri(encrypted, oldRing, { ...context, connectionId: "44444444-4444-4444-8444-444444444444" })).toThrow();
  });

  it("detects ciphertext and authentication-tag tampering", () => {
    const encrypted = encryptConnectionUri(uri, oldRing, context);
    const tampered = { ...encrypted, ciphertext: Buffer.from(encrypted.ciphertext) };
    tampered.ciphertext[0] = (tampered.ciphertext[0] ?? 0) ^ 1;
    expect(() => decryptConnectionUri(tampered, oldRing, context)).toThrow();
  });

  it("rejects a missing decryption key", () => {
    const encrypted = encryptConnectionUri(uri, oldRing, context);
    expect(() => decryptConnectionUri(encrypted, { currentVersion: 2, keys: new Map([[2, newKey]]) }, context)).toThrow(/unavailable/);
  });

  it("keeps legacy version-1 secrets decryptable and rewrappable", () => {
    const dek = randomBytes(32);
    const secretNonce = randomBytes(12);
    const secretCipher = createCipheriv("aes-256-gcm", dek, secretNonce);
    secretCipher.setAAD(Buffer.from("mongo-control-plane:connection:secret:v1", "utf8"));
    const ciphertext = Buffer.concat([secretCipher.update(Buffer.from(uri, "utf8")), secretCipher.final()]);

    const wrapNonce = randomBytes(12);
    const wrapCipher = createCipheriv("aes-256-gcm", oldKey, wrapNonce);
    wrapCipher.setAAD(Buffer.from("mongo-control-plane:connection:dek:v1:key:1", "utf8"));
    const wrappedDek = Buffer.concat([wrapCipher.update(dek), wrapCipher.final()]);
    const legacy = {
      ciphertext,
      nonce: secretNonce,
      authTag: secretCipher.getAuthTag(),
      wrappedDek,
      wrapNonce,
      wrapAuthTag: wrapCipher.getAuthTag(),
      keyVersion: 1,
      encryptionContextVersion: 1 as const,
    };

    expect(decryptConnectionUri(legacy, oldRing, context)).toBe(uri);
    const rotated = rewrapConnectionSecret(legacy, rotatedRing, context);
    expect(rotated.encryptionContextVersion).toBe(1);
    expect(rotated.keyVersion).toBe(2);
    expect(decryptConnectionUri(rotated, rotatedRing, context)).toBe(uri);
    dek.fill(0);
  });

  it("rotates the wrapped data key without changing URI ciphertext", () => {
    const encrypted = encryptConnectionUri(uri, oldRing, context);
    const rotated = rewrapConnectionSecret(encrypted, rotatedRing, context);
    expect(rotated.keyVersion).toBe(2);
    expect(rotated.ciphertext).toEqual(encrypted.ciphertext);
    expect(decryptConnectionUri(rotated, rotatedRing, context)).toBe(uri);
  });

  it("validates MongoDB URI schemes and SRV constraints", () => {
    expect(parseMongoConnectionUri("mongodb+srv://cluster.example.com/app").hostLabel).toBe("cluster.example.com");
    expect(() => parseMongoConnectionUri("https://example.com")).toThrow();
    expect(() => parseMongoConnectionUri("mongodb+srv://cluster.example.com:27017/app")).toThrow();
    expect(parseMongoConnectionUri("mongodb://node-a.example.com:27017,node-b.example.com:27017/app").hostLabel).toBe("node-a.example.com");
    expect(parseMongoConnectionUri("mongodb://[2001:4860:4860::8888]:27017/app").hostLabel).toBe("[2001:4860:4860::8888]");
    expect(() => parseMongoConnectionUri("mongodb+srv://a.example.com,b.example.com/app")).toThrow();
    expect(() => parseMongoConnectionUri("mongodb://db.example.com/app?tls=false")).toThrow(/disable TLS/);
    expect(() => parseMongoConnectionUri("mongodb://db.example.com/app?tlsAllowInvalidCertificates=true")).toThrow(/certificate/);
  });

  it("parses versioned base64 keyrings and rejects malformed keys", () => {
    const encoded = randomBytes(32).toString("base64");
    expect(parseEncryptionKeyring(JSON.stringify({ "3": encoded }), "3")?.currentVersion).toBe(3);
    expect(() => parseEncryptionKeyring(JSON.stringify({ "3": "short" }), "3")).toThrow();
  });
});
