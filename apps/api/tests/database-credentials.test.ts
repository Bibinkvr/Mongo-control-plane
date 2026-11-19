import { describe, expect, it } from "vitest";
import { buildDatabaseConnectionUri } from "../src/provisioning/credentials.js";

describe("database connection URI reveal", () => {
  it("replaces administrator credentials while preserving replica-set hosts and options", () => {
    const uri = buildDatabaseConnectionUri(
      "mongodb://root:admin-secret@mongo-a.example.com:27017,mongo-b.example.com:27017/admin?replicaSet=rs0&retryWrites=true&authSource=admin",
      "mcp_app_user",
      "application-password",
      "mcp_1111111111111111_2222222222222222",
    );
    expect(uri).toContain("mcp_app_user:application-password@mongo-a.example.com:27017,mongo-b.example.com:27017/");
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
      "app-user",
      "secret@with:reserved/chars",
      "mcp_1111111111111111_2222222222222222",
    );
    expect(uri).toContain("mongodb+srv://app-user:secret%40with%3Areserved%2Fchars@cluster.example.com/");
    expect(uri).toContain("tls=true");
  });

  it("rejects malformed or unsupported source URIs", () => {
    expect(() => buildDatabaseConnectionUri("https://example.com", "user", "password", "db")).toThrow();
  });
});
