import { describe, expect, it } from "vitest";
import { buildDatabaseConnectionUri } from "../src/provisioning/credentials.js";

describe("database connection URI reveal", () => {
  it("replaces administrator credentials while preserving replica-set hosts and options", () => {
    const password = "A".repeat(43);
    const uri = buildDatabaseConnectionUri(
      "mongodb://root:admin-secret@mongo-a.example.com:27017,mongo-b.example.com:27017/admin?replicaSet=rs0&retryWrites=true&authSource=admin",
      "mcp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      password,
      "mcp_1111111111111111_2222222222222222",
    );
    expect(uri).toContain("mcp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa:${password}@mongo-a.example.com:27017,mongo-b.example.com:27017/");
    expect(uri).not.toContain("root");
    expect(uri).not.toContain("admin-secret");
    expect(uri).toContain("replicaSet=rs0");
    expect(uri).toContain("authSource=mcp_1111111111111111_2222222222222222");
    expect(uri).toContain("authMechanism=SCRAM-SHA-256");
    expect(uri).toContain("tls=true");
  });

  it("supports SRV connection strings and encodes credentials", () => {
    const uri = buildDatabaseConnectionUri(
      "mongodb+srv://cluster.example.com/admin?retryWrites=true",
      "mcp_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
      "secret@with:reserved/chars-12345678",
      "mcp_1111111111111111_2222222222222222",
    );
    expect(uri).toContain("mongodb+srv://mcp_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb:secret%40with%3Areserved%2Fchars-12345678@cluster.example.com/");
    expect(uri).toContain("tls=true");
  });

  it("rejects malformed or unsupported source URIs", () => {
    expect(() => buildDatabaseConnectionUri("https://example.com", "user", "password", "db")).toThrow();
  });
});
