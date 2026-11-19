import { randomUUID } from "node:crypto";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { Pool } from "pg";
import { runMigrations } from "../src/db/migrations.js";

const databaseUrl = process.env["TEST_DATABASE_URL"];
const integration = describe.skipIf(!databaseUrl);

integration("PostgreSQL schema and tenant isolation", () => {
  let pool: Pool;

  beforeAll(async () => {
    pool = new Pool({ connectionString: databaseUrl, max: 3 });
    await runMigrations(pool);
  });

  afterAll(async () => {
    await pool?.end();
  });

  it("applies migrations idempotently and verifies stored checksums", async () => {
    const results = await runMigrations(pool);
    expect(results.length).toBeGreaterThan(0);
    expect(results.every((item) => item.outcome === "skipped")).toBe(true);
  });

  it("enforces case-insensitive unique user emails", async () => {
    const suffix = randomUUID();
    const email = `case-${suffix}@example.com`;
    const passwordHash = `scrypt$32768$${"a".repeat(32)}$${"b".repeat(128)}`;
    await pool.query(
      "INSERT INTO users (email, password_hash, display_name) VALUES ($1, $2, $3)",
      [email, passwordHash, "Integration Test"],
    );
    await expect(pool.query(
      "INSERT INTO users (email, password_hash, display_name) VALUES ($1, $2, $3)",
      [email.toUpperCase(), passwordHash, "Duplicate"],
    )).rejects.toMatchObject({ code: "23505" });
  });

  it("does not expose a project to a non-member", async () => {
    const suffix = randomUUID();
    const passwordHash = `scrypt$32768$${"c".repeat(32)}$${"d".repeat(128)}`;
    const owner = await pool.query<{ id: string }>(
      "INSERT INTO users (email, password_hash, display_name) VALUES ($1, $2, 'Owner') RETURNING id",
      [`owner-${suffix}@example.com`, passwordHash],
    );
    const outsider = await pool.query<{ id: string }>(
      "INSERT INTO users (email, password_hash, display_name) VALUES ($1, $2, 'Outsider') RETURNING id",
      [`outsider-${suffix}@example.com`, passwordHash],
    );
    const project = await pool.query<{ id: string }>(
      "INSERT INTO projects (name, slug, created_by) VALUES ('Private Project', $1, $2) RETURNING id",
      [`private-${suffix}`, owner.rows[0]!.id],
    );
    await pool.query(
      "INSERT INTO project_memberships (project_id, user_id, role, created_by) VALUES ($1, $2, 'project_admin', $2)",
      [project.rows[0]!.id, owner.rows[0]!.id],
    );

    const visibleToOutsider = await pool.query(
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
    const user = await pool.query<{ id: string }>(
      "INSERT INTO users (email, password_hash, display_name) VALUES ($1, $2, 'Audit Actor') RETURNING id",
      [`audit-${suffix}@example.com`, passwordHash],
    );
    const event = await pool.query<{ id: string }>(
      "INSERT INTO audit_events (actor_user_id, action, target_type) VALUES ($1, 'test.event', 'test') RETURNING id",
      [user.rows[0]!.id],
    );
    await expect(pool.query(
      "UPDATE audit_events SET action = 'tampered' WHERE id = $1",
      [event.rows[0]!.id],
    )).rejects.toThrow(/audit_events is append-only/);
  });
});
