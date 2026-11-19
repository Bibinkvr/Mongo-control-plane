import { parseEnv } from "../config/env.js";
import { parseEncryptionKeyring } from "../connections/crypto.js";
import { createDatabasePool } from "../db/pool.js";
import { runBackupWorker } from "../backups/worker.js";

const env = parseEnv(process.env);
if (!env.DATABASE_URL) throw new Error("DATABASE_URL is required by the backup worker.");
if (!env.BACKUP_WORKER_EGRESS_ISOLATED) {
  throw new Error("Backup worker startup is blocked until external network egress isolation is configured.");
}
if (!env.MONGODUMP_PATH || !env.BACKUP_STORAGE_ROOT) {
  throw new Error("MONGODUMP_PATH and BACKUP_STORAGE_ROOT are required by the backup worker.");
}
const keyring = parseEncryptionKeyring(env.CONNECTION_ENCRYPTION_KEYS, env.CONNECTION_ENCRYPTION_CURRENT_VERSION);
if (!keyring) throw new Error("Connection encryption keyring is required by the backup worker.");

const pool = createDatabasePool(env.DATABASE_URL, { max: 4, application_name: "mongo-control-plane-backup-worker" });
const abort = new AbortController();
const shutdown = () => abort.abort();
process.on("SIGTERM", shutdown);
process.on("SIGINT", shutdown);

try {
  await runBackupWorker(pool, keyring, {
    executablePath: env.MONGODUMP_PATH,
    storageRoot: env.BACKUP_STORAGE_ROOT,
    egressIsolationConfirmed: env.BACKUP_WORKER_EGRESS_ISOLATED,
    maxBytes: env.BACKUP_MAX_BYTES,
    timeoutMs: env.BACKUP_TIMEOUT_MS,
  }, abort.signal);
} finally {
  await pool.end();
}
