import { describe, expect, it, vi } from "vitest";
import type { Db, Document, MongoClient } from "mongodb";
import {
  createSharedDatabaseIdentity,
  generateSharedDatabasePassword,
  provisionSharedDatabaseUser,
  removeSharedDatabaseUser,
} from "../src/provisioning/shared-mongodb.js";

const projectId = "11111111-1111-4111-8111-111111111111";
const resourceId = "22222222-2222-4222-8222-222222222222";
const identity = createSharedDatabaseIdentity(projectId, resourceId, "a".repeat(48));

function fakeAdminDb(initialUser?: unknown) {
  let user = initialUser;
  const commands: Document[] = [];
  const command = vi.fn(async (input: Document) => {
    commands.push(input);
    if ("usersInfo" in input) return { users: user === undefined ? [] : [user] };
    if ("createUser" in input) {
      user = { user: input["createUser"], customData: input["customData"] };
      return { ok: 1 };
    }
    if ("updateUser" in input) {
      user = { user: input["updateUser"], customData: input["customData"] };
      return { ok: 1 };
    }
    if ("dropUser" in input) {
      user = undefined;
      return { ok: 1 };
    }
    return { ok: 1 };
  });
  const target = { command } as unknown as Db;
  const admin = { db: vi.fn(() => target) } as unknown as MongoClient;
  return { admin, commands, command, getUser: () => user };
}

describe("shared MongoDB provisioning", () => {
  it("generates a high-entropy URL-safe password", () => {
    const password = generateSharedDatabasePassword();
    expect(password).toMatch(/^[A-Za-z0-9_-]{43}$/);
  });

  it("derives stable database and user names from UUIDs", () => {
    const result = createSharedDatabaseIdentity(projectId, resourceId, "p".repeat(48));
    expect(result.databaseName).toMatch(/^mcp_[a-f0-9]{16}_[a-f0-9]{16}$/);
    expect(result.username).toBe("mcp_22222222222242228222222222222222");
    expect(createSharedDatabaseIdentity(projectId, resourceId, "p".repeat(48))).toEqual(result);
  });

  it("creates a database-scoped SCRAM-SHA-256 readWrite user", async () => {
    const fake = fakeAdminDb();
    const result = await provisionSharedDatabaseUser(fake.admin, identity);
    expect(result.action).toBe("created");
    expect(fake.commands).toContainEqual(expect.objectContaining({
      createUser: identity.username,
      roles: [{ role: "readWrite", db: identity.databaseName }],
      mechanisms: ["SCRAM-SHA-256"],
      writeConcern: { w: "majority" },
    }));
    expect(fake.getUser()).toMatchObject({
      customData: { managedBy: "mongo-control-plane", projectId, resourceId },
    });
  });

  it("reconciles retries only for a user owned by this resource", async () => {
    const fake = fakeAdminDb({
      user: identity.username,
      customData: { managedBy: "mongo-control-plane", projectId, resourceId },
    });
    const result = await provisionSharedDatabaseUser(fake.admin, identity);
    expect(result.action).toBe("reconciled");
    expect(fake.commands.some((command) => "updateUser" in command)).toBe(true);
    expect(fake.commands.some((command) => "createUser" in command)).toBe(false);
  });

  it("recovers a concurrent create race by verifying ownership before reconciliation", async () => {
    let user: unknown;
    const commands: Document[] = [];
    const command = vi.fn(async (input: Document) => {
      commands.push(input);
      if ("usersInfo" in input) return { users: user === undefined ? [] : [user] };
      if ("createUser" in input) {
        user = { user: input["createUser"], customData: input["customData"] };
        throw Object.assign(new Error("UserAlreadyExists"), { code: 51003 });
      }
      if ("updateUser" in input) return { ok: 1 };
      return { ok: 1 };
    });
    const target = { command } as unknown as Db;
    const admin = { db: vi.fn(() => target) } as unknown as MongoClient;
    const result = await provisionSharedDatabaseUser(admin, identity);
    expect(result.action).toBe("reconciled");
    expect(commands.some((entry) => "updateUser" in entry)).toBe(true);
  });

  it("refuses to modify a user from another project", async () => {
    const fake = fakeAdminDb({
      user: identity.username,
      customData: { managedBy: "another-service", projectId, resourceId },
    });
    await expect(provisionSharedDatabaseUser(fake.admin, identity)).rejects.toThrow(/not owned/);
    expect(fake.commands.some((command) => "updateUser" in command)).toBe(false);
  });

  it("removes only a user carrying the matching ownership marker", async () => {
    const fake = fakeAdminDb({
      user: identity.username,
      customData: { managedBy: "mongo-control-plane", resourceId },
    });
    const result = await removeSharedDatabaseUser(fake.admin, identity);
    expect(result.removed).toBe(true);
    expect(fake.commands.some((command) => "dropUser" in command)).toBe(true);
  });

  it("treats removal of an already absent user as idempotent", async () => {
    const fake = fakeAdminDb();
    const result = await removeSharedDatabaseUser(fake.admin, identity);
    expect(result.removed).toBe(false);
  });

  it("rejects unsafe database names, user names, and short passwords", async () => {
    const fake = fakeAdminDb();
    await expect(provisionSharedDatabaseUser(fake.admin, { ...identity, databaseName: "admin" })).rejects.toThrow(/database name/);
    await expect(provisionSharedDatabaseUser(fake.admin, { ...identity, username: "root" })).rejects.toThrow(/username/);
    await expect(provisionSharedDatabaseUser(fake.admin, { ...identity, password: "short" })).rejects.toThrow(/password/);
  });
});
