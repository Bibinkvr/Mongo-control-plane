import { randomUUID } from "node:crypto";
import type { Pool } from "pg";
import type { EncryptionKeyring } from "../connections/crypto.js";
import { deleteEncryptedBackup } from "./encrypted-storage.js";
import { loadBackupDatabaseCredential } from "./credential-service.js";
import { DatabaseToolsError, runMongodumpToEncryptedStorage } from "./database-tools.js";

type ClaimedBackupJob = {
  id: string;
  project_id: string;
  backup_id: string;
  lock_token: string;
  attempt_count: number;
  max_attempts: number;
};

export type BackupWorkerOptions = {
  executablePath: string;
  storageRoot: string;
  egressIsolationConfirmed: boolean;
  pollIntervalMs?: number;
  leaseSeconds?: number;
  maxBytes?: number;
  timeoutMs?: number;
};

const DEFAULT_MAX_BYTES = 20 * 1024 * 1024 * 1024;
const DEFAULT_TIMEOUT_MS = 6 * 60 * 60 * 1000;

async function claimBackupJob(pool: Pool, leaseSeconds: number): Promise<ClaimedBackupJob | undefined> {
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    const claimed = await client.query<ClaimedBackupJob>(
      `WITH candidate AS (
         SELECT j.id
           FROM backup_jobs j
           JOIN backup_records b ON b.id=j.backup_id AND b.project_id=j.project_id
          WHERE j.operation='backup'
            AND (
              (j.status='queued' AND j.available_at <= now() AND b.status='queued')
              OR (j.status='running' AND j.lease_expires_at < now() AND b.status='running')
            )
          ORDER BY j.available_at, j.created_at
          FOR UPDATE OF j SKIP LOCKED
          LIMIT 1
       )
       UPDATE backup_jobs j
          SET status='running', attempt_count=j.attempt_count+1,
              locked_at=now(), lease_expires_at=now()+($1::int * interval '1 second'),
              lock_token=$2, updated_at=now()
         FROM candidate c
        WHERE j.id=c.id
       RETURNING j.id, j.project_id, j.backup_id, j.lock_token, j.attempt_count, j.max_attempts`,
      [leaseSeconds, randomUUID()],
    );
    const job = claimed.rows[0];
    if (!job) {
      await client.query("COMMIT");
      return undefined;
    }
    const updated = await client.query(
      `UPDATE backup_records
          SET status='running', started_at=COALESCE(started_at,now()),
              last_error_code=NULL, updated_at=now()
        WHERE id=$1 AND project_id=$2 AND status IN ('queued','running')`,
      [job.backup_id, job.project_id],
    );
    if (updated.rowCount !== 1) throw new Error("BACKUP_RECORD_STATE_CHANGED");
    await client.query("COMMIT");
    return job;
  } catch (error) {
    await client.query("ROLLBACK");
    throw error;
  } finally {
    client.release();
  }
}

async function renewBackupLease(pool: Pool, job: ClaimedBackupJob, leaseSeconds: number): Promise<boolean> {
  const result = await pool.query(
    `UPDATE backup_jobs
        SET lease_expires_at=now()+($3::int * interval '1 second'), locked_at=now(), updated_at=now()
      WHERE id=$1 AND status='running' AND lock_token=$2`,
    [job.id, job.lock_token, leaseSeconds],
  );
  return result.rowCount === 1;
}

async function completeBackupJob(
  pool: Pool,
  job: ClaimedBackupJob,
  actorId: string | null,
  metadata: Awaited<ReturnType<typeof runMongodumpToEncryptedStorage>>,
): Promise<void> {
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    const completed = await client.query(
      `UPDATE backup_jobs
          SET status='succeeded', lock_token=NULL, locked_at=NULL, lease_expires_at=NULL,
              last_error_code=NULL, updated_at=now()
        WHERE id=$1 AND project_id=$2 AND backup_id=$3
          AND status='running' AND lock_token=$4`,
      [job.id, job.project_id, job.backup_id, job.lock_token],
    );
    if (completed.rowCount !== 1) throw new Error("BACKUP_LEASE_LOST");

    const record = await client.query(
      `UPDATE backup_records
          SET status='ready', storage_key=$3, nonce=$4, auth_tag=$5, wrapped_dek=$6,
              wrap_nonce=$7, wrap_auth_tag=$8, key_version=$9, plaintext_bytes=$10,
              sha256=$11, last_error_code=NULL, completed_at=now(), updated_at=now()
        WHERE id=$1 AND project_id=$2 AND status='running'`,
      [job.backup_id, job.project_id, metadata.storageKey, metadata.nonce, metadata.authTag,
       metadata.wrappedDek, metadata.wrapNonce, metadata.wrapAuthTag, metadata.keyVersion,
       metadata.plaintextBytes, metadata.sha256],
    );
    if (record.rowCount !== 1) throw new Error("BACKUP_RECORD_STATE_CHANGED");

    await client.query(
      `INSERT INTO audit_events (actor_user_id, project_id, action, target_type, target_id, metadata)
       VALUES ($1,$2,'backup.completed','backup',$3,jsonb_build_object('bytes',$4::bigint,'sha256',$5::text))`,
      [actorId, job.project_id, job.backup_id, metadata.plaintextBytes, metadata.sha256],
    );
    await client.query("COMMIT");
  } catch (error) {
    await client.query("ROLLBACK");
    throw error;
  } finally {
    client.release();
  }
}

async function failBackupJob(
  pool: Pool,
  job: ClaimedBackupJob,
  actorId: string | null,
  errorCode: string,
): Promise<void> {
  const terminal = job.attempt_count >= job.max_attempts;
  const delayMs = Math.min(30_000 * (2 ** Math.max(0, job.attempt_count - 1)), 900_000);
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    const updated = await client.query(
      `UPDATE backup_jobs
          SET status=$3,
              available_at=CASE WHEN $3='queued' THEN now()+($4::int * interval '1 millisecond') ELSE available_at END,
              lock_token=NULL, locked_at=NULL, lease_expires_at=NULL,
              last_error_code=$5, updated_at=now()
        WHERE id=$1 AND status='running' AND lock_token=$2`,
      [job.id, job.lock_token, terminal ? "failed" : "queued", delayMs, errorCode],
    );
    if (updated.rowCount === 1) {
      await client.query(
        `UPDATE backup_records
            SET status=$3, last_error_code=$4, updated_at=now()
          WHERE id=$1 AND project_id=$2 AND status='running'`,
        [job.backup_id, job.project_id, terminal ? "failed" : "queued", errorCode],
      );
      await client.query(
        `INSERT INTO audit_events (actor_user_id, project_id, action, target_type, target_id, metadata)
         VALUES ($1,$2,$5,'backup',$3,jsonb_build_object('terminal',$4::boolean,'errorCode',$6::text))`,
        [actorId, job.project_id, job.backup_id, terminal, terminal ? "backup.failed" : "backup.retry", errorCode],
      );
    }
    await client.query("COMMIT");
  } catch (error) {
    await client.query("ROLLBACK");
    throw error;
  } finally {
    client.release();
  }
}

async function isBackupMetadataCommitted(
  pool: Pool,
  backupId: string,
  storageKey: string,
): Promise<boolean> {
  try {
    const result = await pool.query<{ status: string; storage_key: string | null }>(
      "SELECT status, storage_key FROM backup_records WHERE id=$1",
      [backupId],
    );
    return result.rows[0]?.status === "ready" && result.rows[0]?.storage_key === storageKey;
  } catch {
    // If commit outcome cannot be established, preserve the object. An orphan
    // can be reconciled later; deleting a committed object would corrupt a ready backup.
    return true;
  }
}

function safeErrorCode(error: unknown): string {
  if (error instanceof DatabaseToolsError) return error.code;
  if (error instanceof Error && error.message === "BACKUP_LEASE_LOST") return "BACKUP_LEASE_LOST";
  return "BACKUP_FAILED";
}

async function processBackupJob(
  pool: Pool,
  keyring: EncryptionKeyring,
  job: ClaimedBackupJob,
  options: BackupWorkerOptions,
): Promise<void> {
  const leaseSeconds = options.leaseSeconds ?? 300;
  const controller = new AbortController();
  let leaseLost = false;
  let actorId: string | null = null;
  let metadata: Awaited<ReturnType<typeof runMongodumpToEncryptedStorage>> | undefined;
  const heartbeat = setInterval(() => {
    void renewBackupLease(pool, job, leaseSeconds)
      .then((renewed) => {
        if (!renewed) {
          leaseLost = true;
          controller.abort();
        }
      })
      .catch(() => {
        leaseLost = true;
        controller.abort();
      });
  }, Math.max(10_000, Math.floor(leaseSeconds * 1_000 / 3)));
  heartbeat.unref();

  try {
    const credential = await loadBackupDatabaseCredential(pool, keyring, {
      projectId: job.project_id,
      backupId: job.backup_id,
      jobId: job.id,
      lockToken: job.lock_token,
    });
    actorId = credential.actorId;
    metadata = await runMongodumpToEncryptedStorage({
      executablePath: options.executablePath,
      uri: credential.uri,
      databaseName: credential.databaseName,
      storageRoot: options.storageRoot,
      projectId: job.project_id,
      backupId: job.backup_id,
      keyring,
      maxBytes: options.maxBytes ?? DEFAULT_MAX_BYTES,
      timeoutMs: options.timeoutMs ?? DEFAULT_TIMEOUT_MS,
      signal: controller.signal,
    });
    if (leaseLost || controller.signal.aborted) throw new Error("BACKUP_LEASE_LOST");
    await completeBackupJob(pool, job, actorId, metadata);
    metadata = undefined;
  } catch (error) {
    if (metadata) {
      const committed = await isBackupMetadataCommitted(pool, job.backup_id, metadata.storageKey);
      if (!committed) {
        await deleteEncryptedBackup(options.storageRoot, job.project_id, job.backup_id).catch(() => undefined);
      }
    }
    await failBackupJob(pool, job, actorId, safeErrorCode(error)).catch(() => undefined);
  } finally {
    clearInterval(heartbeat);
  }
}

/** Claims and processes one backup job; the database lease prevents concurrent execution. */
export async function processNextBackupJob(
  pool: Pool,
  keyring: EncryptionKeyring,
  options: BackupWorkerOptions,
): Promise<boolean> {
  const leaseSeconds = options.leaseSeconds ?? 300;
  const job = await claimBackupJob(pool, leaseSeconds);
  if (!job) return false;
  await processBackupJob(pool, keyring, job, options);
  return true;
}

/**
 * Runs the backup outbox worker. The egress flag is an operator attestation,
 * not a firewall implementation: deploy this process in a separately
 * restricted network namespace/container before setting it to true.
 */
export async function runBackupWorker(
  pool: Pool,
  keyring: EncryptionKeyring,
  options: BackupWorkerOptions,
  signal?: AbortSignal,
): Promise<void> {
  if (options.egressIsolationConfirmed !== true) {
    throw new Error("Backup worker is disabled until its network egress is externally isolated.");
  }
  if (!options.executablePath || !options.storageRoot) {
    throw new Error("Backup worker executable path and storage root are required.");
  }
  const pollIntervalMs = options.pollIntervalMs ?? 1_000;
  const leaseSeconds = options.leaseSeconds ?? 300;
  if (!Number.isInteger(pollIntervalMs) || pollIntervalMs < 100 || pollIntervalMs > 60_000) {
    throw new Error("Invalid backup worker poll interval.");
  }
  if (!Number.isInteger(leaseSeconds) || leaseSeconds < 30 || leaseSeconds > 900) {
    throw new Error("Invalid backup worker lease.");
  }
  while (!signal?.aborted) {
    try {
      const processed = await processNextBackupJob(pool, keyring, options);
      if (processed) continue;
    } catch {
      process.stderr.write("Backup worker could not claim or process a job.\n");
    }
    await new Promise<void>((resolve) => setTimeout(resolve, pollIntervalMs));
  }
}
