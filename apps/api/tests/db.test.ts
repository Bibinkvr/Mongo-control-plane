import { afterEach, describe, expect, it, vi } from "vitest";
import { Pool } from "pg";
import { checkPostgres } from "../src/db/health.js";
import { createDatabasePool } from "../src/db/pool.js";

describe("PostgreSQL helpers", () => {
  let pool: Pool | undefined;

  afterEach(async () => {
    vi.restoreAllMocks();
    await pool?.end();
    pool = undefined;
  });

  it("rejects an empty connection string", () => {
    expect(() => createDatabasePool("  ")).toThrow("DATABASE_URL must not be empty.");
  });

  it("creates a node-postgres pool", () => {
    pool = createDatabasePool("postgres://user:password@127.0.0.1:5432/control_plane");
    expect(pool).toBeInstanceOf(Pool);
  });

  it("reports a healthy database when SELECT 1 succeeds", async () => {
    const fakePool = { query: vi.fn().mockResolvedValue({ rows: [{ "?column?": 1 }] }) };
    await expect(checkPostgres(fakePool as unknown as Pool)).resolves.toBe(true);
    expect(fakePool.query).toHaveBeenCalledWith("SELECT 1");
  });

  it("reports an unhealthy database without leaking the database error", async () => {
    const fakePool = { query: vi.fn().mockRejectedValue(new Error("sensitive connection detail")) };
    await expect(checkPostgres(fakePool as unknown as Pool)).resolves.toBe(false);
  });
});
