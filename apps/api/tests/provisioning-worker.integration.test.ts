import { randomUUID } from "node:crypto";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { MongoClient } from "mongodb";
import { Pool } from "pg";
import { encryptConnectionUri, decryptSecretString, type EncryptedConnectionSecret } from "../src/connections/crypto.js";
import { createDatabaseProvisioningRequest } from "../src/provisioning/repository.js";
import { processNextProvisioningJob } from "../src/provisioning/worker.js";
import { removeSharedDatabaseUser } from "../src/provisioning/shared-mongodb.js";
import { revealDatabaseConnectionUri, rotateDatabaseCredentialKey } from "../src/provisioning/credentials.js";
import { hashPassword } from "../src/auth/password.js";
import { runMigrations } from "../src/db/migrations.js";

const databaseUrl = process.env["TEST_DATABASE_URL"] ?? "";
const mongoUri = process.env["MONGODB_TEST_URI"] ?? "";
const integration = describe.skipIf(!databaseUrl || !mongoUri);

integration("database provisioning worker integration", () => {
  let pool: Pool;
  const keyring = { currentVersion: 1, keys: new Map([[1, Buffer.alloc(32, 77)]]) };

  beforeAll(async () => {
    pool = new Pool({ connectionString: databaseUrl, max: 4 });
    await runMigrations(pool);
  });

  afterAll(async () => {
    await pool?.end();
  });

  it("persists an encrypted password, provisions a scoped MongoDB user, and recovers to ready", async () => {
    const suffix = randomUUID();
    const passwordHash = await hashPassword("provision worker integration password");
    const user = await pool.query<{ id: string }>(
      "INSERT INTO users (email,password_hash,display_name) VALUES ($1,$2,'Provision Worker') RETURNING id",
      [`worker-${suffix}@example.com`, passwordHash],
    );
    const project = await pool.query<{ id: string }>(
      "INSERT INTO projects (name,slug,created_by) VALUES ('Worker Test',$1,$2) RETURNING id",
      [`worker-${suffix}`, user.rows[0]!.id],
    );
    const projectId = project.rows[0]!.id;
    await pool.query(
      "INSERT INTO project_memberships (project_id,user_id,role,created_by) VALUES ($1,$2,'project_admin',$2)",
      [projectId, user.rows[0]!.id],
    );
    const connectionId = randomUUID();
    const encryptedUri = encryptConnectionUri(mongoUri, keyring, { projectId, connectionId });
    await pool.query(
      `INSERT INTO connection_targets
        (id,project_id,name,kind,host_label,secret_ciphertext,secret_nonce,secret_auth_tag,
         wrapped_dek,wrap_nonce,wrap_auth_tag,key_version,encryption_context_version,created_by)
       VALUES ($1,$2,'Worker Admin','shared','127.0.0.1',$3,$4,$5,$6,$7,$8,$9,2,$10)`,
      [connectionId, projectId, encryptedUri.ciphertext, encryptedUri.nonce, encryptedUri.authTag,
       encryptedUri.wrappedDek, encryptedUri.wrapNonce, encryptedUri.wrapAuthTag, encryptedUri.keyVersion, user.rows[0]!.id],
    );

    const resource = await createDatabaseProvisioningRequest(pool, keyring, {
      caller: { userId: user.rows[0]!.id, isPlatformAdmin: false },
      projectId,
      connectionId,
      name: "Worker Integration Resource",
    });
    const stored = await pool.query<EncryptedConnectionSecret>(
      `SELECT credential_ciphertext AS ciphertext,credential_nonce AS nonce,
              credential_auth_tag AS "authTag",wrapped_dek AS "wrappedDek",
              wrap_nonce AS "wrapNonce",wrap_auth_tag AS "wrapAuthTag",
              key_version AS "keyVersion",encryption_context_version AS "encryptionContextVersion"
         FROM database_resources WHERE id=$1`,
      [resource.id],
    );
    expect(stored.rows).toHaveLength(1);
    const password = decryptSecretString(stored.rows[0]!, keyring, { projectId, connectionId: resource.id });
    expect(password).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(await processNextProvisioningJob(pool, keyring, { tls: false, allowLoopback: true })).toBe(true);

    const status = await pool.query<{ status: string }>("SELECT status FROM database_resources WHERE id=$1", [resource.id]);
    expect(status.rows[0]?.status).toBe("ready");

    const rotatedKey = Buffer.alloc(32, 88);
    const rotatedRing = { currentVersion: 2, keys: new Map([[1, keyring.keys.get(1)!], [2, rotatedKey]]) };
    const beforeRotation = await pool.query<{ ciphertext: Buffer; wrappedDek: Buffer }>(
      'SELECT credential_ciphertext AS ciphertext, wrapped_dek AS "wrappedDek" FROM database_resources WHERE id=$1',
      [resource.id],
    );
    const rotation = await rotateDatabaseCredentialKey(pool, rotatedRing, {
      caller: { userId: user.rows[0]!.id, isPlatformAdmin: false }, projectId, databaseId: resource.id,
    });
    expect(rotation).toEqual({ keyVersion: 2, rotated: true });
    const afterRotation = await pool.query<{ ciphertext: Buffer; wrappedDek: Buffer }>(
      'SELECT credential_ciphertext AS ciphertext, wrapped_dek AS "wrappedDek" FROM database_resources WHERE id=$1',
      [resource.id],
    );
    expect(afterRotation.rows[0]!.ciphertext).toEqual(beforeRotation.rows[0]!.ciphertext);
    expect(afterRotation.rows[0]!.wrappedDek).not.toEqual(beforeRotation.rows[0]!.wrappedDek);

    const revealedUri = await revealDatabaseConnectionUri(pool, rotatedRing, {
      caller: { userId: user.rows[0]!.id, isPlatformAdmin: false }, projectId, databaseId: resource.id,
    });
    expect(revealedUri).toContain("authMechanism=SCRAM-SHA-256");
    expect(revealedUri).toContain("tls=true");
    expect(revealedUri).not.toContain("rootpassword");

    const adminClient = new MongoClient(mongoUri, { serverSelectionTimeoutMS: 5_000 });
    const appUri = new URL(mongoUri);
    appUri.username = resource.username;
    appUri.password = password;
    appUri.pathname = `/${resource.databaseName}`;
    appUri.searchParams.set("authSource", resource.databaseName);
    appUri.searchParams.set("authMechanism", "SCRAM-SHA-256");
    const appClient = new MongoClient(appUri.toString(), { serverSelectionTimeoutMS: 5_000 });
    try {
      await adminClient.connect();
      await appClient.connect();
      const collection = appClient.db(resource.databaseName).collection("access_probe");
      await collection.insertOne({ projectId, resourceId: resource.id });
      expect(await collection.countDocuments({ projectId })).toBe(1);
      const visibleDatabases = await appClient.db("admin").command({
        listDatabases: 1, authorizedDatabases: true,
      });
      const visibleNames = (visibleDatabases["databases"] as Array<{ name: string }>).map((database) => database.name);
      expect(visibleNames).toContain(resource.databaseName);
      expect(visibleNames).not.toContain("admin");
      await expect(appClient.db("another_project").collection("blocked").insertOne({ denied: true })).rejects.toThrow();
      await removeSharedDatabaseUser(adminClient, {
        projectId, resourceId: resource.id, databaseName: resource.databaseName,
        username: resource.username, password,
      });
      await adminClient.db(resource.databaseName).dropDatabase();
    } finally {
      await appClient.close();
      await adminClient.close();
      await pool.query("DELETE FROM provisioning_jobs WHERE resource_id=$1", [resource.id]);
      await pool.query("DELETE FROM database_resources WHERE id=$1", [resource.id]);
      await pool.query("DELETE FROM connection_targets WHERE id=$1", [connectionId]);
      await pool.query("DELETE FROM projects WHERE id=$1", [projectId]);
      await pool.query("DELETE FROM users WHERE id=$1", [user.rows[0]!.id]);
    }
  });
});
