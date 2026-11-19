import { randomUUID } from "node:crypto";
import type { Pool, PoolClient } from "pg";
import { hasProjectPermission } from "../auth/permissions.js";

export type BackupCaller = { userId: string; isPlatformAdmin: boolean };

export class BackupRequestError extends Error {
  constructor(
    public readonly code: "PROJECT_NOT_FOUND" | "FORBIDDEN" | "CONNECTION_NOT_FOUND" | "CONNECTION_DISABLED" | "BACKUP_NOT_FOUND" | "BACKUP_OPERATION_ACTIVE",
    message: string,
  ) {
    super(message);
    this.name = "BackupRequestError";
  }
}

async function lockProjectAccess(
  client: PoolClient,
  caller: BackupCaller,
  projectId: string,
): Promise<string> {
  const access = await client.query<{ role: string }>(
    `SELECT CASE WHEN u.is_platform_admin THEN 'platform_admin' ELSE pm.role END AS role
       FROM projects p
       JOIN users u ON u.id = $2
       LEFT JOIN project_memberships pm ON pm.project_id = p.id AND pm.user_id = u.id
      WHERE p.id = $1 AND (u.is_platform_admin OR pm.user_id IS NOT NULL)
      FOR UPDATE OF p`,
    [projectId, caller.userId],
  );
  const role = access.rows[0]?.role;
  if (!role) throw new BackupRequestError("PROJECT_NOT_FOUND", "The project was not found.");
  return role;
}

export async function requestBackup(
  pool: Pool,
  input: {
    caller: BackupCaller;
    projectId: string;
    connectionId: string;
    name: string;
  },
): Promise<{ id: string; name: string; status: "queued"; jobId: string; createdAt: Date }> {
  const backupId = randomUUID();
  const jobId = randomUUID();
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    const role = await lockProjectAccess(client, input.caller, input.projectId);
    if (!hasProjectPermission(role, "backup:manage")) {
      throw new BackupRequestError("FORBIDDEN", "Backup management permission is required.");
    }

    const connection = await client.query<{ status: string }>(
      "SELECT status FROM connection_targets WHERE id=$1 AND project_id=$2 FOR SHARE",
      [input.connectionId, input.projectId],
    );
    const target = connection.rows[0];
    if (!target) throw new BackupRequestError("CONNECTION_NOT_FOUND", "The connection was not found.");
    if (target.status !== "configured") {
      throw new BackupRequestError("CONNECTION_DISABLED", "The connection is disabled.");
    }

    const inserted = await client.query<{ created_at: Date }>(
      `INSERT INTO backup_records (id, project_id, connection_id, name, status, created_by)
       VALUES ($1,$2,$3,$4,'queued',$5)
       RETURNING created_at`,
      [backupId, input.projectId, input.connectionId, input.name, input.caller.userId],
    );
    await client.query(
      `INSERT INTO backup_jobs (id, project_id, backup_id, operation, status, created_by)
       VALUES ($1,$2,$3,'backup','queued',$4)`,
      [jobId, input.projectId, backupId, input.caller.userId],
    );
    await client.query(
      `INSERT INTO audit_events (actor_user_id, project_id, action, target_type, target_id, metadata)
       VALUES ($1,$2,'backup.request','backup',$3,jsonb_build_object('connectionId',$4::text,'name',$5::text))`,
      [input.caller.userId, input.projectId, backupId, input.connectionId, input.name],
    );
    await client.query("COMMIT");
    return { id: backupId, name: input.name, status: "queued", jobId, createdAt: inserted.rows[0]!.created_at };
  } catch (error) {
    await client.query("ROLLBACK");
    if (typeof error === "object" && error !== null && "code" in error && error.code === "23505") {
      throw new BackupRequestError("BACKUP_OPERATION_ACTIVE", "An operation is already active for this backup.");
    }
    throw error;
  } finally {
    client.release();
  }
}

export async function listProjectBackups(
  pool: Pool,
  caller: BackupCaller,
  projectId: string,
  limit = 50,
): Promise<Array<{
  id: string;
  connectionId: string;
  name: string;
  format: string;
  status: string;
  plaintextBytes: string | null;
  sha256: string | null;
  lastErrorCode: string | null;
  retentionProtected: boolean;
  createdAt: Date;
  startedAt: Date | null;
  completedAt: Date | null;
}>> {
  if (!Number.isInteger(limit) || limit < 1 || limit > 100) {
    throw new Error("Backup list limit must be between 1 and 100.");
  }
  const access = await pool.query<{ role: string }>(
    `SELECT CASE WHEN u.is_platform_admin THEN 'platform_admin' ELSE pm.role END AS role
       FROM projects p
       JOIN users u ON u.id = $2
       LEFT JOIN project_memberships pm ON pm.project_id = p.id AND pm.user_id = u.id
      WHERE p.id = $1 AND (u.is_platform_admin OR pm.user_id IS NOT NULL)
      LIMIT 1`,
    [projectId, caller.userId],
  );
  const role = access.rows[0]?.role;
  if (!role) throw new BackupRequestError("PROJECT_NOT_FOUND", "The project was not found.");
  if (!hasProjectPermission(role, "backup:read")) {
    throw new BackupRequestError("FORBIDDEN", "Backup read permission is required.");
  }

  const result = await pool.query(
    `SELECT id, connection_id AS "connectionId", name, format, status,
            plaintext_bytes::text AS "plaintextBytes", sha256,
            last_error_code AS "lastErrorCode", retention_protected AS "retentionProtected",
            created_at AS "createdAt", started_at AS "startedAt", completed_at AS "completedAt"
       FROM backup_records
      WHERE project_id=$1 AND status <> 'deleted'
      ORDER BY created_at DESC
      LIMIT $2`,
    [projectId, limit],
  );
  return result.rows;
}

export async function getProjectBackup(
  pool: Pool,
  caller: BackupCaller,
  projectId: string,
  backupId: string,
): Promise<{
  id: string;
  connectionId: string;
  name: string;
  format: string;
  status: string;
  plaintextBytes: string | null;
  sha256: string | null;
  lastErrorCode: string | null;
  retentionProtected: boolean;
  createdAt: Date;
  startedAt: Date | null;
  completedAt: Date | null;
} | null> {
  const access = await pool.query<{ role: string }>(
    `SELECT CASE WHEN u.is_platform_admin THEN 'platform_admin' ELSE pm.role END AS role
       FROM projects p
       JOIN users u ON u.id = $2
       LEFT JOIN project_memberships pm ON pm.project_id = p.id AND pm.user_id = u.id
      WHERE p.id = $1 AND (u.is_platform_admin OR pm.user_id IS NOT NULL)
      LIMIT 1`,
    [projectId, caller.userId],
  );
  const role = access.rows[0]?.role;
  if (!role) throw new BackupRequestError("PROJECT_NOT_FOUND", "The project was not found.");
  if (!hasProjectPermission(role, "backup:read")) {
    throw new BackupRequestError("FORBIDDEN", "Backup read permission is required.");
  }

  const result = await pool.query(
    `SELECT id, connection_id AS "connectionId", name, format, status,
            plaintext_bytes::text AS "plaintextBytes", sha256,
            last_error_code AS "lastErrorCode", retention_protected AS "retentionProtected",
            created_at AS "createdAt", started_at AS "startedAt", completed_at AS "completedAt"
       FROM backup_records
      WHERE project_id=$1 AND id=$2 AND status <> 'deleted'`,
    [projectId, backupId],
  );
  return result.rows[0] ?? null;
}
