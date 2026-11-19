import { createHash } from "node:crypto";
import { readdir, readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import type { Pool, PoolClient } from "pg";

const defaultMigrationDirectory = fileURLToPath(new URL("../../migrations/", import.meta.url));

/** The runner owns the transaction; ignore legacy BEGIN/COMMIT wrappers in SQL files. */
function migrationBody(contents: string): string {
  return contents
    .replace(/^\s*(?:--[^\r\n]*\r?\n\s*)*(?:BEGIN|START TRANSACTION)\s*;\s*/i, "")
    .replace(/\s*(?:COMMIT|END)\s*;\s*(?:--[^\r\n]*\s*)*$/i, "");
}

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
      if (applied.checksum.trim() !== checksum) {
        throw new Error(`Applied migration ${filename} has changed. Create a new migration instead of editing it.`);
      }
      await client.query("COMMIT");
      return "skipped";
    }

    await client.query(migrationBody(contents));
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

export async function runMigrations(
  pool: Pool,
  migrationDirectory = defaultMigrationDirectory,
): Promise<Array<{ filename: string; outcome: "applied" | "skipped" }>> {
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

    const results: Array<{ filename: string; outcome: "applied" | "skipped" }> = [];
    for (const filename of filenames) {
      const contents = await readFile(`${migrationDirectory.replace(/[\/]$/, "")}/${filename}`, "utf8");
      const outcome = await applyMigration(client, filename, contents);
      results.push({ filename, outcome });
    }
    return results;
  } finally {
    client.release();
  }
}
