import { randomBytes } from "node:crypto";
import { describe, expect, it } from "vitest";
import { decryptSecretString, encryptSecretString, rewrapConnectionSecret } from "../src/connections/crypto.js";

const context = {
  projectId: "11111111-1111-4111-8111-111111111111",
  connectionId: "22222222-2222-4222-8222-222222222222",
};
const oldKey = randomBytes(32);
const newKey = randomBytes(32);
const oldRing = { currentVersion: 1, keys: new Map([[1, oldKey]]) };
const nextRing = { currentVersion: 2, keys: new Map([[1, oldKey], [2, newKey]]) };

describe("generic encrypted resource credentials", () => {
  it("encrypts and decrypts a generated database password", () => {
    const value = "a-strong-secret-that-is-not-a-connection-uri";
    const encrypted = encryptSecretString(value, oldRing, context);
    expect(encrypted.ciphertext.includes(Buffer.from(value))).toBe(false);
    expect(decryptSecretString(encrypted, oldRing, context)).toBe(value);
  });
  it("rejects cross-resource envelope substitution", () => {
    const encrypted = encryptSecretString("resource-secret", oldRing, context);
    expect(() => decryptSecretString(encrypted, oldRing, {
      ...context, connectionId: "33333333-3333-4333-8333-333333333333",
    })).toThrow();
  });
  it("rewraps only the DEK during key rotation", () => {
    const encrypted = encryptSecretString("rotate-this-secret", oldRing, context);
    const rotated = rewrapConnectionSecret(encrypted, nextRing, context);
    expect(rotated.keyVersion).toBe(2);
    expect(rotated.ciphertext).toEqual(encrypted.ciphertext);
    expect(decryptSecretString(rotated, nextRing, context)).toBe("rotate-this-secret");
  });
  it("rejects empty and oversized secret values", () => {
    expect(() => encryptSecretString("", oldRing, context)).toThrow();
    expect(() => encryptSecretString("x".repeat(16_385), oldRing, context)).toThrow();
  });
});
