import { describe, expect, it } from "vitest";
import { hashPassword, verifyPassword } from "../src/auth/password.js";
import { createSessionToken, hashSessionToken, readSessionCookie } from "../src/auth/session.js";

describe("password hashing", () => {
  it("verifies the original password and rejects a different password", async () => {
    const encoded = await hashPassword("correct horse battery staple");
    expect(encoded.startsWith("scrypt$32768$")).toBe(true);
    await expect(verifyPassword("correct horse battery staple", encoded)).resolves.toBe(true);
    await expect(verifyPassword("wrong password", encoded)).resolves.toBe(false);
  });

  it("rejects malformed stored hashes", async () => {
    await expect(verifyPassword("password", "not-a-hash")).resolves.toBe(false);
  });
});

describe("session token helpers", () => {
  it("creates high-entropy opaque tokens and stores only a digest", () => {
    const token = createSessionToken();
    expect(token).toMatch(/^[A-Za-z0-9_-]{40,64}$/);
    expect(hashSessionToken(token)).toHaveLength(32);
    expect(hashSessionToken(token).toString("hex")).not.toBe(token);
  });

  it("extracts only the named, well-formed cookie", () => {
    const token = createSessionToken();
    expect(readSessionCookie(`other=x; mcp_session=${token}`, "mcp_session")).toBe(token);
    expect(readSessionCookie("mcp_session=bad.value", "mcp_session")).toBeNull();
    expect(readSessionCookie(undefined, "mcp_session")).toBeNull();
  });
});
