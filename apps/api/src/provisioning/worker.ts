import { randomUUID } from "node:crypto";
import { MongoClient } from "mongodb";
import type { Pool } from "pg";
import { decryptSecretString, type EncryptedConnectionSecret, type EncryptionKeyring } from "../connections/crypto.js";
import { loadConnectionCredential } from "../connections/credential-service.js";
import { createSharedDatabaseIdentity, provisionSharedDatabaseUser, removeSharedDatabaseUser } from "./shared-mongodb.js";
import { createSafeMongoLookup } from "./network-guard.js";

type ClaimedJob = { id: string; project_id: string; resource_id: string; operation: "provision" | "delete"; lock_token: string; attempt_count: number; max_attempts: number };
type ResourceRow = EncryptedConnectionSecret & {
  id: string; project_id: string; connection_id: string; database_name: string; username: string;
  created_by: string | null; created_by_is_platform_admin: boolean | null; encryptionContextVersion: 1 | 2;
};
export type ProvisioningWorkerOptions = {
  pollIntervalMs?: number;
  leaseSeconds?: number;
  tls?: boolean;
  allowPrivateNetworks?: boolean;
  allowLoopback?: boolean;
};

async function claimJob(pool: Pool, leaseSeconds: number): Promise<ClaimedJob | undefined> {
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    const result = await client.query<ClaimedJob>(
      `WITH candidate AS (
         SELECT id FROM provisioning_jobs
          WHERE operation IN ('provision', 'delete')
            AND ((status = 'queued' AND available_at <= now())
              OR (status = 'running' AND lease_expires_at < now()))
          ORDER BY available_at, created_at
          FOR UPDATE SKIP LOCKED
          LIMIT 1
       )
       UPDATE provisioning_jobs j
          SET status = 'running', attempt_count = j.attempt_count + 1,
              locked_at = now(), lease_expires_at = now() + ($1::int * interval '1 second'),
              lock_token = $2, updated_at = now()
         FROM candidate c
        WHERE j.id = c.id
       RETURNING j.id, j.project_id, j.resource_id, j.operation, j.lock_token, j.attempt_count, j.max_attempts`,
      [leaseSeconds, randomUUID()],
    );
    await client.query("COMMIT");
    return result.rows[0];
  } catch (error) {
    await client.query("ROLLBACK");
    throw error;
  } finally { client.release(); }
}

async function completeJob(pool: Pool, job: ClaimedJob, actorId: string): Promise<void> {
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    const updated = await client.query(
      `UPDATE provisioning_jobs
          SET status='succeeded', lock_token=NULL, locked_at=NULL, lease_expires_at=NULL,
              last_error_code=NULL, updated_at=now()
        WHERE id=$1 AND status='running' AND lock_token=$2`,
      [job.id, job.lock_token],
    );
    if (updated.rowCount !== 1) throw new Error("PROVISIONING_LEASE_LOST");
    if (job.operation === "delete") {
      await client.query(
        `UPDATE database_resources
            SET status='deleted', last_error_code=NULL,
                credential_ciphertext=$3, credential_nonce=$4, credential_auth_tag=$5,
                wrapped_dek=$6, wrap_nonce=$7, wrap_auth_tag=$8, updated_at=now()
          WHERE id=$1 AND project_id=$2`,
        [job.resource_id, job.project_id, Buffer.alloc(0), Buffer.alloc(12), Buffer.alloc(16),
         Buffer.alloc(0), Buffer.alloc(12), Buffer.alloc(16)],
      );
    } else {
      await client.query(
        "UPDATE database_resources SET status='ready', last_error_code=NULL, updated_at=now() WHERE id=$1 AND project_id=$2",
        [job.resource_id, job.project_id],
      );
    }
    const action = job.operation === "delete" ? "database.delete.succeeded" : "database.provision.succeeded";
    await client.query(
      `INSERT INTO audit_events (actor_user_id, project_id, action, target_type, target_id, metadata)
       VALUES ($1,$2,$4,'database',$3,'{}'::jsonb)`,
      [actorId, job.project_id, job.resource_id, action],
    );
    await client.query("COMMIT");
  } catch (error) {
    await client.query("ROLLBACK");
    throw error;
  } finally { client.release(); }
}

async function failJob(pool: Pool, job: ClaimedJob, actorId: string | null): Promise<void> {
  const terminal = job.attempt_count >= job.max_attempts;
  const delayMs = Math.min(30_000 * (2 ** Math.max(0, job.attempt_count - 1)), 900_000);
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    const updated = await client.query(
      `UPDATE provisioning_jobs
          SET status=$3, available_at=CASE WHEN $3='queued' THEN now()+($4::int * interval '1 millisecond') ELSE available_at END,
              lock_token=NULL, locked_at=NULL, lease_expires_at=NULL,
              last_error_code='PROVISIONING_FAILED', updated_at=now()
        WHERE id=$1 AND status='running' AND lock_token=$2`,
      [job.id, job.lock_token, terminal ? "failed" : "queued", delayMs],
    );
    if (updated.rowCount === 1) {
      await client.query(
        `UPDATE database_resources
            SET status=CASE WHEN $2 THEN 'failed' WHEN $3='delete' THEN 'deleting' ELSE 'provisioning' END,
                last_error_code='PROVISIONING_FAILED', updated_at=now()
          WHERE id=$1 AND status <> 'deleted'`,
        [job.resource_id, terminal, job.operation],
      );
      if (actorId) {
        await client.query(
          `INSERT INTO audit_events (actor_user_id, project_id, action, target_type, target_id, metadata)
           VALUES ($1,$2,$5,'database',$3,jsonb_build_object('terminal',$4::boolean,'errorCode','PROVISIONING_FAILED'))`,
          [actorId, job.project_id, job.resource_id, terminal, job.operation === "delete" ? "database.delete.failed" : "database.provision.failed"],
        );
      }
    }
    await client.query("COMMIT");
  } catch (error) {
    await client.query("ROLLBACK");
    throw error;
  } finally { client.release(); }
}

async function loadResource(pool: Pool, job: ClaimedJob): Promise<ResourceRow> {
  const result = await pool.query<ResourceRow>(
    `SELECT r.id, r.project_id, r.connection_id, r.database_name, r.username, r.created_by,
            u.is_platform_admin AS created_by_is_platform_admin,
            r.credential_ciphertext AS ciphertext, r.credential_nonce AS nonce,
            r.credential_auth_tag AS "authTag", r.wrapped_dek AS "wrappedDek",
            r.wrap_nonce AS "wrapNonce", r.wrap_auth_tag AS "wrapAuthTag",
            r.key_version AS "keyVersion", r.encryption_context_version AS "encryptionContextVersion"
       FROM database_resources r
       LEFT JOIN users u ON u.id = r.created_by
      WHERE r.id=$1 AND r.project_id=$2 AND r.status=$3`,
    [job.resource_id, job.project_id, job.operation === "delete" ? "deleting" : "provisioning"],
  );
  const row = result.rows[0];
  if (!row || !row.created_by) throw new Error("PROVISIONING_RESOURCE_UNAVAILABLE");
  return row;
}

async function processJob(pool: Pool, keyring: EncryptionKeyring, job: ClaimedJob, options: ProvisioningWorkerOptions): Promise<void> {
  let actorId: string | null = null;
  let adminClient: MongoClient | undefined;
  try {
    const resource = await loadResource(pool, job);
    const createdBy = resource.created_by;
    if (!createdBy) throw new Error("PROVISIONING_RESOURCE_UNAVAILABLE");
    actorId = createdBy;
    const password = decryptSecretString(resource, keyring, { projectId: resource.project_id, connectionId: resource.id });
    const adminUri = await loadConnectionCredential(pool, keyring, {
      caller: { userId: createdBy, isPlatformAdmin: resource.created_by_is_platform_admin === true },
      projectId: resource.project_id,
      connectionId: resource.connection_id,
    });
    const identity = createSharedDatabaseIdentity(resource.project_id, resource.id, password);
    if (identity.databaseName !== resource.database_name || identity.username !== resource.username) {
      throw new Error("PROVISIONING_IDENTITY_MISMATCH");
    }
    adminClient = new MongoClient(adminUri, {
      tls: options.tls ?? true,
      lookup: createSafeMongoLookup({
        ...(options.allowPrivateNetworks !== undefined ? { allowPrivateNetworks: options.allowPrivateNetworks } : {}),
        ...(options.allowLoopback !== undefined ? { allowLoopback: options.allowLoopback } : {}),
      }),
      serverSelectionTimeoutMS: 10_000,
      connectTimeoutMS: 10_000,
      socketTimeoutMS: 30_000,
      maxPoolSize: 2,
      minPoolSize: 0,
    });
    await adminClient.connect();
    if (job.operation === "provision") {
      await provisionSharedDatabaseUser(adminClient, identity);
    } else {
      await removeSharedDatabaseUser(adminClient, identity);
      await adminClient.db(resource.database_name).dropDatabase();
    }
    await completeJob(pool, job, createdBy);
  } catch {
    await failJob(pool, job, actorId);
  } finally {
    await adminClient?.close().catch(() => undefined);
  }
}

/** Claims and processes at most one job. Useful for controlled worker processes and integration tests. */
export async function processNextProvisioningJob(
  pool: Pool,
  keyring: EncryptionKeyring,
  options: ProvisioningWorkerOptions = {},
): Promise<boolean> {
  const job = await claimJob(pool, options.leaseSeconds ?? 120);
  if (!job) return false;
  await processJob(pool, keyring, job, options);
  return true;
}

/** A PostgreSQL outbox worker. Multiple processes can run safely using SKIP LOCKED leases. */
export async function runProvisioningWorker(
  pool: Pool,
  keyring: EncryptionKeyring,
  options: ProvisioningWorkerOptions = {},
  signal?: AbortSignal,
): Promise<void> {
  const pollIntervalMs = options.pollIntervalMs ?? 1_000;
  const leaseSeconds = options.leaseSeconds ?? 120;
  if (!Number.isInteger(pollIntervalMs) || pollIntervalMs < 100 || pollIntervalMs > 60_000) throw new Error("Invalid provisioning worker poll interval.");
  if (!Number.isInteger(leaseSeconds) || leaseSeconds < 30 || leaseSeconds > 900) throw new Error("Invalid provisioning worker lease.");
  while (!signal?.aborted) {
    try {
      const processed = await processNextProvisioningJob(pool, keyring, options);
      if (processed) continue;
    } catch {
      process.stderr.write("Provisioning worker could not claim or process a job.\n");
    }
    await new Promise<void>((resolve) => setTimeout(resolve, pollIntervalMs));
  }
}
