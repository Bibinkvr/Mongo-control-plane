import { randomUUID } from "node:crypto";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { Pool } from "pg";
import request from "supertest";
import { createApp } from "../src/app.js";
import { hashPassword } from "../src/auth/password.js";
import { createSessionToken, hashSessionToken } from "../src/auth/session.js";
import { decryptConnectionUri } from "../src/connections/crypto.js";
import { loadConnectionCredential } from "../src/connections/credential-service.js";
import { runMigrations } from "../src/db/migrations.js";

const databaseUrl = process.env["TEST_DATABASE_URL"] ?? "";
const integration = describe.skipIf(!databaseUrl);
let pool: Pool | undefined;
const db = (): Pool => {
  if (!pool) throw new Error("TEST_DATABASE_URL is not configured.");
  return pool;
};

integration("PostgreSQL schema and tenant isolation", () => {
  beforeAll(async () => {
    pool = new Pool({ connectionString: databaseUrl, max: 3 });
    await runMigrations(db());
  });

  afterAll(async () => {
    await pool?.end();
  });

  it("applies migrations idempotently and verifies stored checksums", async () => {
    const results = await runMigrations(db());
    expect(results.length).toBeGreaterThan(0);
    expect(results.every((item) => item.outcome === "skipped")).toBe(true);
  });

  it("enforces case-insensitive unique user emails", async () => {
    const suffix = randomUUID();
    const email = `case-${suffix}@example.com`;
    const passwordHash = `scrypt$32768$${"a".repeat(32)}$${"b".repeat(128)}`;
    await db().query(
      "INSERT INTO users (email, password_hash, display_name) VALUES ($1, $2, $3)",
      [email, passwordHash, "Integration Test"],
    );
    await expect(db().query(
      "INSERT INTO users (email, password_hash, display_name) VALUES ($1, $2, $3)",
      [email.toUpperCase(), passwordHash, "Duplicate"],
    )).rejects.toMatchObject({ code: "23505" });
  });

  it("does not expose a project to a non-member", async () => {
    const suffix = randomUUID();
    const passwordHash = `scrypt$32768$${"c".repeat(32)}$${"d".repeat(128)}`;
    const owner = await db().query<{ id: string }>(
      "INSERT INTO users (email, password_hash, display_name) VALUES ($1, $2, 'Owner') RETURNING id",
      [`owner-${suffix}@example.com`, passwordHash],
    );
    const outsider = await db().query<{ id: string }>(
      "INSERT INTO users (email, password_hash, display_name) VALUES ($1, $2, 'Outsider') RETURNING id",
      [`outsider-${suffix}@example.com`, passwordHash],
    );
    const project = await db().query<{ id: string }>(
      "INSERT INTO projects (name, slug, created_by) VALUES ('Private Project', $1, $2) RETURNING id",
      [`private-${suffix}`, owner.rows[0]!.id],
    );
    await db().query(
      "INSERT INTO project_memberships (project_id, user_id, role, created_by) VALUES ($1, $2, 'project_admin', $2)",
      [project.rows[0]!.id, owner.rows[0]!.id],
    );

    const visibleToOutsider = await db().query(
      `SELECT p.id
         FROM projects p
         JOIN users u ON u.id = $2
         LEFT JOIN project_memberships pm ON pm.project_id = p.id AND pm.user_id = $2
        WHERE p.id = $1 AND (u.is_platform_admin = true OR pm.user_id = $2)
        LIMIT 1`,
      [project.rows[0]!.id, outsider.rows[0]!.id],
    );
    expect(visibleToOutsider.rows).toHaveLength(0);

    const outsiderToken = createSessionToken();
    await db().query(
      "INSERT INTO sessions (user_id, token_hash, expires_at) VALUES ($1, $2, now() + interval '1 hour')",
      [outsider.rows[0]!.id, hashSessionToken(outsiderToken)],
    );
    const outsiderApi = request(createApp({ pool: db() }));
    const outsiderCookie = `mcp_session=${outsiderToken}`;
    const hiddenProject = await outsiderApi.get(`/api/projects/${project.rows[0]!.id}`).set("Cookie", outsiderCookie);
    expect(hiddenProject.status).toBe(404);
    const hiddenMembership = await outsiderApi.post(`/api/projects/${project.rows[0]!.id}/members`)
      .set("Cookie", outsiderCookie)
      .send({ email: `owner-${suffix}@example.com`, role: "developer" });
    expect(hiddenMembership.status).toBe(404);
  });

  it("rejects updates to append-only audit events", async () => {
    const suffix = randomUUID();
    const passwordHash = `scrypt$32768$${"e".repeat(32)}$${"f".repeat(128)}`;
    const user = await db().query<{ id: string }>(
      "INSERT INTO users (email, password_hash, display_name) VALUES ($1, $2, 'Audit Actor') RETURNING id",
      [`audit-${suffix}@example.com`, passwordHash],
    );
    const event = await db().query<{ id: string }>(
      "INSERT INTO audit_events (actor_user_id, action, target_type) VALUES ($1, 'test.event', 'test') RETURNING id",
      [user.rows[0]!.id],
    );
    await expect(db().query(
      "UPDATE audit_events SET action = 'tampered' WHERE id = $1",
      [event.rows[0]!.id],
    )).rejects.toThrow(/audit_events is append-only/);
  });
  it("enforces project-admin membership changes and preserves a final administrator", async () => {
    const suffix = randomUUID();
    const passwordHash = await hashPassword("integration password long enough");
    const owner = await db().query<{ id: string }>(
      "INSERT INTO users (email, password_hash, display_name) VALUES ($1, $2, 'Project Owner') RETURNING id",
      [`member-owner-${suffix}@example.com`, passwordHash],
    );
    const target = await db().query<{ id: string }>(
      "INSERT INTO users (email, password_hash, display_name) VALUES ($1, $2, 'Project Member') RETURNING id",
      [`member-target-${suffix}@example.com`, passwordHash],
    );
    const project = await db().query<{ id: string }>(
      "INSERT INTO projects (name, slug, created_by) VALUES ('Membership Test', $1, $2) RETURNING id",
      [`membership-${suffix}`, owner.rows[0]!.id],
    );
    await db().query(
      "INSERT INTO project_memberships (project_id, user_id, role, created_by) VALUES ($1, $2, 'project_admin', $2)",
      [project.rows[0]!.id, owner.rows[0]!.id],
    );

    const token = createSessionToken();
    await db().query(
      "INSERT INTO sessions (user_id, token_hash, expires_at) VALUES ($1, $2, now() + interval '1 hour')",
      [owner.rows[0]!.id, hashSessionToken(token)],
    );
    const api = request(createApp({ pool: db() }));
    const cookie = `mcp_session=${token}`;
    const projectId = project.rows[0]!.id;
    const ownerId = owner.rows[0]!.id;
    const targetId = target.rows[0]!.id;

    const listed = await api.get(`/api/projects/${projectId}/members`).set("Cookie", cookie);
    expect(listed.status).toBe(200);
    expect(listed.body.members).toHaveLength(1);

    const added = await api.post(`/api/projects/${projectId}/members`).set("Cookie", cookie)
      .send({ email: `member-target-${suffix}@example.com`, role: "developer" });
    expect(added.status).toBe(201);
    expect(added.body.membership.role).toBe("developer");

    const blockedDowngrade = await api.patch(`/api/projects/${projectId}/members/${ownerId}`)
      .set("Cookie", cookie).send({ role: "developer" });
    expect(blockedDowngrade.status).toBe(409);
    expect(blockedDowngrade.body.error.code).toBe("LAST_PROJECT_ADMIN");

    const promoted = await api.patch(`/api/projects/${projectId}/members/${targetId}`)
      .set("Cookie", cookie).send({ role: "project_admin" });
    expect(promoted.status).toBe(200);
    expect(promoted.body.membership.role).toBe("project_admin");

    const targetToken = createSessionToken();
    await db().query(
      "INSERT INTO sessions (user_id, token_hash, expires_at) VALUES ($1, $2, now() + interval '1 hour')",
      [targetId, hashSessionToken(targetToken)],
    );
    const targetApi = request(createApp({ pool: db() }));
    const targetCookie = `mcp_session=${targetToken}`;

    const downgraded = await api.patch(`/api/projects/${projectId}/members/${ownerId}`)
      .set("Cookie", cookie).send({ role: "developer" });
    expect(downgraded.status).toBe(200);

    const removedOwner = await targetApi.delete(`/api/projects/${projectId}/members/${ownerId}`).set("Cookie", targetCookie);
    expect(removedOwner.status).toBe(204);

    const blockedRemoval = await targetApi.delete(`/api/projects/${projectId}/members/${targetId}`).set("Cookie", targetCookie);
    expect(blockedRemoval.status).toBe(409);
    expect(blockedRemoval.body.error.code).toBe("LAST_PROJECT_ADMIN");
  });

  it("stores connection URIs encrypted, enforces project permissions, and supports key rotation and lifecycle updates", async () => {
    const suffix = randomUUID();
    const passwordHash = await hashPassword("connection integration password");
    const owner = await db().query<{ id: string }>(
      "INSERT INTO users (email, password_hash, display_name) VALUES ($1, $2, 'Connection Owner') RETURNING id",
      [`connection-owner-${suffix}@example.com`, passwordHash],
    );
    const reader = await db().query<{ id: string }>(
      "INSERT INTO users (email, password_hash, display_name) VALUES ($1, $2, 'Connection Reader') RETURNING id",
      [`connection-reader-${suffix}@example.com`, passwordHash],
    );
    const outsider = await db().query<{ id: string }>(
      "INSERT INTO users (email, password_hash, display_name) VALUES ($1, $2, 'Connection Outsider') RETURNING id",
      [`connection-outsider-${suffix}@example.com`, passwordHash],
    );
    const project = await db().query<{ id: string }>(
      "INSERT INTO projects (name, slug, created_by) VALUES ('Connection Test', $1, $2) RETURNING id",
      [`connection-${suffix}`, owner.rows[0]!.id],
    );
    const projectId = project.rows[0]!.id;
    await db().query(
      "INSERT INTO project_memberships (project_id, user_id, role, created_by) VALUES ($1, $2, 'project_admin', $2), ($1, $3, 'read_only', $2)",
      [projectId, owner.rows[0]!.id, reader.rows[0]!.id],
    );

    const ownerToken = createSessionToken();
    const readerToken = createSessionToken();
    const outsiderToken = createSessionToken();
    for (const [userId, token] of [
      [owner.rows[0]!.id, ownerToken],
      [reader.rows[0]!.id, readerToken],
      [outsider.rows[0]!.id, outsiderToken],
    ] as const) {
      await db().query(
        "INSERT INTO sessions (user_id, token_hash, expires_at) VALUES ($1, $2, now() + interval '1 hour')",
        [userId, hashSessionToken(token)],
      );
    }

    const oldKey = Buffer.alloc(32, 11);
    const newKey = Buffer.alloc(32, 22);
    const oldRing = { currentVersion: 1, keys: new Map([[1, oldKey]]) };
    const rotatedRing = { currentVersion: 2, keys: new Map([[1, oldKey], [2, newKey]]) };
    const ownerApi = request(createApp({ pool: db(), encryptionKeyring: oldRing }));
    const readerApi = request(createApp({ pool: db(), encryptionKeyring: oldRing }));
    const outsiderApi = request(createApp({ pool: db(), encryptionKeyring: oldRing }));
    const ownerCookie = `mcp_session=${ownerToken}`;
    const readerCookie = `mcp_session=${readerToken}`;
    const outsiderCookie = `mcp_session=${outsiderToken}`;
    const uri = "mongodb://mcp_user:connection-secret-value@db.example.com:27017/app?retryWrites=true";

    const created = await ownerApi.post(`/api/projects/${projectId}/connections`)
      .set("Cookie", ownerCookie)
      .send({ name: "Primary", kind: "shared", uri });
    expect(created.status).toBe(201);
    expect(created.body.connection).toMatchObject({ name: "Primary", kind: "shared", hostLabel: "db.example.com", status: "configured" });
    expect(JSON.stringify(created.body)).not.toContain("connection-secret-value");
    const connectionId = created.body.connection.id as string;

    const stored = await db().query<{ secret_ciphertext: Buffer; secret_nonce: Buffer; secret_auth_tag: Buffer; wrapped_dek: Buffer; wrap_nonce: Buffer; wrap_auth_tag: Buffer; key_version: number }>(
      `SELECT secret_ciphertext, secret_nonce, secret_auth_tag, wrapped_dek, wrap_nonce, wrap_auth_tag, key_version
         FROM connection_targets WHERE id = $1 AND project_id = $2`,
      [connectionId, projectId],
    );
    expect(stored.rows[0]!.secret_ciphertext.includes(Buffer.from("connection-secret-value"))).toBe(false);
    expect(stored.rows[0]!.key_version).toBe(1);

    const listed = await readerApi.get(`/api/projects/${projectId}/connections`).set("Cookie", readerCookie);
    expect(listed.status).toBe(200);
    expect(JSON.stringify(listed.body)).not.toContain("connection-secret-value");
    expect(JSON.stringify(listed.body)).not.toContain("wrappedDek");
    const deniedCreate = await readerApi.post(`/api/projects/${projectId}/connections`)
      .set("Cookie", readerCookie).send({ name: "Forbidden", kind: "shared", uri });
    expect(deniedCreate.status).toBe(403);
    const hidden = await outsiderApi.get(`/api/projects/${projectId}/connections`).set("Cookie", outsiderCookie);
    expect(hidden.status).toBe(404);

    const rotateApi = request(createApp({ pool: db(), encryptionKeyring: rotatedRing }));
    const rotated = await rotateApi.post(`/api/projects/${projectId}/connections/${connectionId}/rotate-key`).set("Cookie", ownerCookie);
    expect(rotated.status).toBe(200);
    expect(rotated.body).toMatchObject({ keyVersion: 2, rotated: true });
    const afterRotation = await db().query<{
      secret_ciphertext: Buffer; secret_nonce: Buffer; secret_auth_tag: Buffer;
      wrapped_dek: Buffer; wrap_nonce: Buffer; wrap_auth_tag: Buffer; key_version: number;
    }>(
      `SELECT secret_ciphertext, secret_nonce, secret_auth_tag, wrapped_dek, wrap_nonce, wrap_auth_tag, key_version
         FROM connection_targets WHERE id = $1`, [connectionId],
    );
    expect(afterRotation.rows[0]!.key_version).toBe(2);
    expect(afterRotation.rows[0]!.secret_ciphertext).toEqual(stored.rows[0]!.secret_ciphertext);
    expect(decryptConnectionUri({
      ciphertext: afterRotation.rows[0]!.secret_ciphertext,
      nonce: afterRotation.rows[0]!.secret_nonce,
      authTag: afterRotation.rows[0]!.secret_auth_tag,
      wrappedDek: afterRotation.rows[0]!.wrapped_dek,
      wrapNonce: afterRotation.rows[0]!.wrap_nonce,
      wrapAuthTag: afterRotation.rows[0]!.wrap_auth_tag,
      keyVersion: afterRotation.rows[0]!.key_version,
      encryptionContextVersion: 2,
    }, rotatedRing, { projectId, connectionId })).toBe(uri);

    const credential = await loadConnectionCredential(db(), rotatedRing, {
      caller: { userId: owner.rows[0]!.id, isPlatformAdmin: false }, projectId, connectionId,
    });
    expect(credential).toBe(uri);
    const readerCredential = await loadConnectionCredential(db(), rotatedRing, {
      caller: { userId: reader.rows[0]!.id, isPlatformAdmin: false }, projectId, connectionId,
    });
    expect(readerCredential).toBe(uri);

    const renamed = await ownerApi.patch(`/api/projects/${projectId}/connections/${connectionId}`)
      .set("Cookie", ownerCookie).send({ name: "Primary Production", status: "disabled" });
    expect(renamed.status).toBe(200);
    expect(renamed.body.connection).toMatchObject({ name: "Primary Production", status: "disabled" });

    await expect(loadConnectionCredential(db(), rotatedRing, {
      caller: { userId: owner.rows[0]!.id, isPlatformAdmin: false }, projectId, connectionId,
    })).rejects.toMatchObject({ code: "CONNECTION_DISABLED" });

    const invalidUpdate = await ownerApi.patch(`/api/projects/${projectId}/connections/${connectionId}`)
      .set("Cookie", ownerCookie).send({});
    expect(invalidUpdate.status).toBe(400);

    const removed = await ownerApi.delete(`/api/projects/${projectId}/connections/${connectionId}`).set("Cookie", ownerCookie);
    expect(removed.status).toBe(204);
    const absent = await db().query("SELECT id FROM connection_targets WHERE id = $1", [connectionId]);
    expect(absent.rows).toHaveLength(0);
    const events = await db().query<{ action: string }>(
      "SELECT action FROM audit_events WHERE project_id = $1 AND target_id = $2 ORDER BY occurred_at",
      [projectId, connectionId],
    );
    expect(events.rows.map((event) => event.action)).toEqual([
      "connection.create", "connection.key.rotate", "connection.credential.use", "connection.update", "connection.delete",
    ]);
  });

});
