import { createServer } from "node:http";
import { createApp } from "./app.js";
import { parseEnv } from "./config/env.js";
import { createDatabasePool } from "./db/pool.js";
import { parseEncryptionKeyring } from "./connections/crypto.js";
import { defaultMongoClientManager } from "./workspace/mongo-client-manager.js";

const env = parseEnv(process.env);
const pool = env.DATABASE_URL ? createDatabasePool(env.DATABASE_URL) : undefined;
const encryptionKeyring = parseEncryptionKeyring(env.CONNECTION_ENCRYPTION_KEYS, env.CONNECTION_ENCRYPTION_CURRENT_VERSION);
const app = createApp({
  pool,
  secureCookies: env.NODE_ENV === "production",
  ...(encryptionKeyring ? { encryptionKeyring } : {}),
  mongoNetworkPolicy: {
    allowPrivateNetworks: env.MONGODB_ALLOW_PRIVATE_NETWORKS,
    allowLoopback: env.MONGODB_ALLOW_LOOPBACK,
  },
});
const server = createServer(app);

server.listen(env.PORT, env.HOST, () => {
  process.stdout.write(`API listening on http://${env.HOST}:${env.PORT}\n`);
});

let shuttingDown = false;
function shutdown(signal: string) {
  if (shuttingDown) return;
  shuttingDown = true;
  process.stdout.write(`Received ${signal}; shutting down gracefully.\n`);
  const forceExit = setTimeout(() => {
    process.stderr.write("Graceful shutdown timed out. Forcing exit.\n");
    process.exit(1);
  }, 10_000);
  forceExit.unref();

  server.close(async (error) => {
    clearTimeout(forceExit);
    try {
      await defaultMongoClientManager.close();
      await pool?.end();
    } catch {
      process.stderr.write("PostgreSQL pool shutdown failed.\n");
      process.exitCode = 1;
    }
    if (error) {
      process.stderr.write("HTTP server shutdown failed.\n");
      process.exitCode = 1;
      return;
    }
    if (process.exitCode === undefined) process.exitCode = 0;
  });
}
process.on("SIGTERM", () => shutdown("SIGTERM"));
process.on("SIGINT", () => shutdown("SIGINT"));
