import { parseEnv } from "../config/env.js";
import { parseEncryptionKeyring } from "../connections/crypto.js";
import { createDatabasePool } from "../db/pool.js";
import { runProvisioningWorker } from "../provisioning/worker.js";

const env = parseEnv(process.env);
if (!env.DATABASE_URL) throw new Error("DATABASE_URL is required by the provisioning worker.");
const keyring = parseEncryptionKeyring(env.CONNECTION_ENCRYPTION_KEYS, env.CONNECTION_ENCRYPTION_CURRENT_VERSION);
if (!keyring) throw new Error("Connection encryption keyring is required by the provisioning worker.");
const pool = createDatabasePool(env.DATABASE_URL, { max: 5, application_name: "mongo-control-plane-provisioner" });
const abort = new AbortController();
const shutdown = () => abort.abort();
process.on("SIGTERM", shutdown);
process.on("SIGINT", shutdown);

try {
  await runProvisioningWorker(pool, keyring, { tls: true }, abort.signal);
} finally {
  await pool.end();
}
