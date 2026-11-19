import { Pool, type PoolConfig } from "pg";

export function createDatabasePool(connectionString: string, options: Omit<PoolConfig, "connectionString"> = {}) {
  if (!connectionString.trim()) {
    throw new Error("DATABASE_URL must not be empty.");
  }

  return new Pool({
    connectionString,
    max: 10,
    idleTimeoutMillis: 30_000,
    connectionTimeoutMillis: 5_000,
    ...options,
  });
}
