import { z } from "zod";
import { createDatabasePool } from "../db/pool.js";
import { hashPassword } from "../auth/password.js";

const inputSchema = z.object({
  DATABASE_URL: z.string().url().refine((value) => /^postgres(ql)?:\/\//i.test(value), "must be a PostgreSQL URL"),
  BOOTSTRAP_ADMIN_EMAIL: z.string().trim().email().max(254),
  BOOTSTRAP_ADMIN_PASSWORD: z.string().min(12).max(128),
  BOOTSTRAP_ADMIN_DISPLAY_NAME: z.string().trim().min(1).max(120),
});

async function main(): Promise<void> {
  const parsed = inputSchema.safeParse(process.env);
  if (!parsed.success) {
    process.stderr.write("Invalid bootstrap configuration. Set DATABASE_URL, BOOTSTRAP_ADMIN_EMAIL, BOOTSTRAP_ADMIN_PASSWORD (12-128 characters), and BOOTSTRAP_ADMIN_DISPLAY_NAME.\n");
    process.exitCode = 1;
    return;
  }

  const input = parsed.data;
  const pool = createDatabasePool(input.DATABASE_URL, { max: 1 });
  const client = await pool.connect();

  try {
    await client.query("BEGIN");
    await client.query("SELECT pg_advisory_xact_lock(hashtext($1))", ["mongo-control-plane:bootstrap-platform-admin"]);

    const existing = await client.query("SELECT id FROM users WHERE is_platform_admin = true LIMIT 1");
    if (existing.rowCount && existing.rowCount > 0) {
      throw new Error("A platform administrator already exists. Bootstrap is disabled.");
    }

    const passwordHash = await hashPassword(input.BOOTSTRAP_ADMIN_PASSWORD);
    const inserted = await client.query<{ id: string }>(
      `INSERT INTO users (email, password_hash, display_name, status, is_platform_admin)
       VALUES ($1, $2, $3, 'active', true)
       RETURNING id`,
      [input.BOOTSTRAP_ADMIN_EMAIL, passwordHash, input.BOOTSTRAP_ADMIN_DISPLAY_NAME],
    );
    const userId = inserted.rows[0]?.id;
    if (!userId) throw new Error("Admin creation did not return a user ID.");

    await client.query(
      `INSERT INTO audit_events (actor_user_id, action, target_type, target_id, metadata)
       VALUES ($1, 'auth.bootstrap_admin', 'user', $1, jsonb_build_object('method', 'one_time_cli'))`,
      [userId],
    );
    await client.query("COMMIT");
    process.stdout.write("Platform administrator created. Remove bootstrap credentials from the environment now.\n");
  } catch (error) {
    await client.query("ROLLBACK");
    const message = error instanceof Error ? error.message : "Unknown bootstrap failure.";
    process.stderr.write(`${message}\n`);
    process.exitCode = 1;
  } finally {
    client.release();
    await pool.end();
  }
}

await main();
