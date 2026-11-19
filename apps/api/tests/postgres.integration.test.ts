import { randomUUID } from "node:crypto";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { Pool } from "pg";
import request from "supertest";
import { createApp } from "../src/app.js";
import { hashPassword } from "../src/auth/password.js";
import { createSessionToken, hashSessionToken } from "../src/auth/session.js";
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

});
