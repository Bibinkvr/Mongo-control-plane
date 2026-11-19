import { randomUUID } from "node:crypto";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { MongoClient } from "mongodb";
import {
  createSharedDatabaseIdentity,
  generateSharedDatabasePassword,
  provisionSharedDatabaseUser,
  removeSharedDatabaseUser,
} from "../src/provisioning/shared-mongodb.js";

const adminUri = process.env["MONGODB_TEST_URI"] ?? "";
const integration = describe.skipIf(!adminUri);

integration("shared MongoDB provisioning integration", () => {
  let adminClient: MongoClient;

  beforeAll(async () => {
    adminClient = new MongoClient(adminUri, { serverSelectionTimeoutMS: 5_000 });
    await adminClient.connect();
  });

  afterAll(async () => {
    await adminClient?.close();
  });

  it("creates a least-privilege user, reconciles retries, and removes only owned users", async () => {
    const projectId = randomUUID();
    const resourceId = randomUUID();
    const identity = createSharedDatabaseIdentity(projectId, resourceId, generateSharedDatabasePassword());
    const adminDb = adminClient.db(identity.databaseName);
    let appClient: MongoClient | undefined;

    try {
      const created = await provisionSharedDatabaseUser(adminClient, identity);
      expect(created.action).toBe("created");

      const userInfo = await adminDb.command({ usersInfo: identity.username });
      expect(userInfo["users"]).toHaveLength(1);
      expect(userInfo["users"][0]).toMatchObject({
        user: identity.username,
        customData: { managedBy: "mongo-control-plane", resourceId },
        roles: [{ role: "readWrite", db: identity.databaseName }],
        mechanisms: ["SCRAM-SHA-256"],
      });

      const appUri = new URL(adminUri);
      appUri.username = identity.username;
      appUri.password = identity.password;
      appUri.pathname = `/${identity.databaseName}`;
      appUri.searchParams.set("authSource", identity.databaseName);
      appUri.searchParams.set("authMechanism", "SCRAM-SHA-256");
      appClient = new MongoClient(appUri.toString(), { serverSelectionTimeoutMS: 5_000 });
      await appClient.connect();

      const collection = appClient.db(identity.databaseName).collection("permission_probe");
      await collection.insertOne({ resourceId, verified: true });
      expect(await collection.countDocuments({ resourceId })).toBe(1);
      const visibleDatabases = await appClient.db("admin").command<{ databases: Array<{ name: string }> }>({
        listDatabases: 1, authorizedDatabases: true,
      });
      expect(visibleDatabases.databases.map((database) => database.name)).toContain(identity.databaseName);
      expect(visibleDatabases.databases.map((database) => database.name)).not.toContain("admin");
      await expect(appClient.db("another_project").collection("blocked").insertOne({ denied: true })).rejects.toThrow();

      const retried = await provisionSharedDatabaseUser(adminClient, identity);
      expect(retried.action).toBe("reconciled");
      expect(await collection.countDocuments({ resourceId })).toBe(1);

      const removed = await removeSharedDatabaseUser(adminClient, identity);
      expect(removed.removed).toBe(true);
      const afterRemoval = await adminDb.command({ usersInfo: identity.username });
      expect(afterRemoval["users"]).toHaveLength(0);

      const repeatedRemoval = await removeSharedDatabaseUser(adminClient, identity);
      expect(repeatedRemoval.removed).toBe(false);
    } finally {
      await appClient?.close();
      try {
        await removeSharedDatabaseUser(adminClient, identity);
      } catch {
        // Preserve the original test failure; the isolated test database is
        // dropped below by the privileged test client.
      }
      await adminDb.dropDatabase();
    }
  });
});
