import { createHash } from "node:crypto";
import { readdir, readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import type { PoolClient } from "pg";
import { createDatabasePool } from "../db/pool.js";

const migrationDirectory = fileURLToPath(new URL("../../migrations/", import.meta.url));

async function applyMigration(client: PoolClient, filename: string, contents: string): Promise<"applied" | "skipped"> {
  const checksum = createHash("sha256").update(contents, "utf8").digest("hex");
  await client.query("BEGIN");
  try {
    await client.query("SELECT pg_advisory_xact_lock(hashtext($1))", ["mongo-control-plane:schema-migrations"]);
    const existing = await client.query<{ checksum: string }>(
      "SELECT checksum FROM schema_migrations WHERE filename = $1",
      [filename],
    );
    const applied = existing.rows[0];
    if (applied) {
      if (applied.checksum !== checksum) {
        throw new Error(`Applied migration ${filename} has changed. Create a new migration instead of editing it.`);
      }
      await client.query("COMMIT");
      return "skipped";
    }

    await client.query(contents);
    await client.query(
      "INSERT INTO schema_migrations (filename, checksum) VALUES ($1, $2)",
      [filename, checksum],
    );
    await client.query("COMMIT");
    return "applied";
  } catch (error) {
    await client.query("ROLLBACK");
    throw error;
  }
}

async function main(): Promise<void> {
  const connectionString = process.env["DATABASE_URL"];
  if (!connectionString || !/^postgres(ql)?:\/\//i.test(connectionString)) {
    throw new Error("DATABASE_URL must be set to a PostgreSQL connection string.");
  }

  const pool = createDatabasePool(connectionString, { max: 1 });
  try {
    const client = await pool.connect();
    try {
      await client.query(`CREATE TABLE IF NOT EXISTS schema_migrations (
        filename text PRIMARY KEY,
        checksum char(64) NOT NULL,
        applied_at timestamptz NOT NULL DEFAULT now()
      )`);

      const filenames = (await readdir(migrationDirectory))
        .filter((name) => /^\d+_[a-z0-9_]+\.sql$/.test(name))
        .sort((left, right) => left.localeCompare(right, "en"));

      for (const filename of filenames) {
        const contents = await readFile(new URL(filename, `file://${migrationDirectory}/`), "utf8");
        const outcome = await applyMigration(client, filename, contents);
        process.stdout.write(`${outcome === "applied" ? "Applied" : "Skipped"} ${filename}\n`);
      }
    } finally {
      client.release();
    }
  } finally {
    await pool.end();
  }
}

try {
  await main();
} catch (error) {
  process.stderr.write(`${error instanceof Error ? error.message : "Migration failed."}\n`);
  process.exitCode = 1;
}
