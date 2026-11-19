import { createDatabasePool } from "../db/pool.js";
import { runMigrations } from "../db/migrations.js";

async function main(): Promise<void> {
  const connectionString = process.env["DATABASE_URL"];
  if (!connectionString || !/^postgres(ql)?:\/\//i.test(connectionString)) {
    throw new Error("DATABASE_URL must be set to a PostgreSQL connection string.");
  }

  const pool = createDatabasePool(connectionString, { max: 1 });
  try {
    const results = await runMigrations(pool);
    for (const result of results) {
      process.stdout.write(`${result.outcome === "applied" ? "Applied" : "Skipped"} ${result.filename}\n`);
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
