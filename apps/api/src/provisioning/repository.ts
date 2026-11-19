import { randomUUID } from "node:crypto";
import type { Pool } from "pg";
import { hasProjectPermission } from "../auth/permissions.js";
import { encryptSecretString, type EncryptionKeyring } from "../connections/crypto.js";
import { createSharedDatabaseBackupIdentity, createSharedDatabaseIdentity, generateSharedDatabasePassword } from "./shared-mongodb.js";

export type ProvisioningCaller = { userId: string; isPlatformAdmin: boolean };
export type CreateDatabaseRequest = {
  caller: ProvisioningCaller;
  projectId: string;
  connectionId: string;
  name: string;
};
export class ProvisioningRequestError extends Error {
  constructor(public readonly code: "PROJECT_NOT_FOUND" | "FORBIDDEN" | "CONNECTION_NOT_FOUND" | "CONNECTION_DISABLED" | "INVALID_CONNECTION_KIND" | "RESOURCE_NAME_TAKEN" | "DATABASE_NOT_FOUND" | "DATABASE_NOT_READY" | "CONFIRMATION_MISMATCH" | "DATABASE_OPERATION_ACTIVE", message: string) {
    super(message);
    this.name = "ProvisioningRequestError";
  }
}

export async function createDatabaseProvisioningRequest(
  pool: Pool,
  keyring: EncryptionKeyring,
  input: CreateDatabaseRequest,
): Promise<{ id: string; name: string; databaseName: string; username: string; status: "provisioning"; jobId: string }> {
  const resourceId = randomUUID();
  const jobId = randomUUID();
  const password = generateSharedDatabasePassword();
  const identity = createSharedDatabaseIdentity(input.projectId, resourceId, password);
  const encrypted = encryptSecretString(password, keyring, { projectId: input.projectId, connectionId: resourceId });
  const backupPassword = generateSharedDatabasePassword();
  const backupIdentity = createSharedDatabaseBackupIdentity(input.projectId, resourceId, backupPassword);
  const encryptedBackupPassword = encryptSecretString(backupPassword, keyring, { projectId: input.projectId, connectionId: resourceId });
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    const access = await client.query<{ role: string }>(
      `SELECT CASE WHEN u.is_platform_admin THEN 'platform_admin' ELSE pm.role END AS role
         FROM projects p
         JOIN users u ON u.id = $2
         LEFT JOIN project_memberships pm ON pm.project_id = p.id AND pm.user_id = u.id
        WHERE p.id = $1 AND (u.is_platform_admin OR pm.user_id IS NOT NULL)
        FOR UPDATE OF p`,
      [input.projectId, input.caller.userId],
    );
    const role = access.rows[0]?.role;
    if (!role) throw new ProvisioningRequestError("PROJECT_NOT_FOUND", "The project was not found.");
    if (!hasProjectPermission(role, "database:admin")) {
      throw new ProvisioningRequestError("FORBIDDEN", "Database administration permission is required.");
    }

    const connection = await client.query<{ kind: string; status: string }>(
      "SELECT kind, status FROM connection_targets WHERE id = $1 AND project_id = $2 FOR SHARE",
      [input.connectionId, input.projectId],
    );
    const target = connection.rows[0];
    if (!target) throw new ProvisioningRequestError("CONNECTION_NOT_FOUND", "The connection was not found.");
    if (target.status !== "configured") throw new ProvisioningRequestError("CONNECTION_DISABLED", "The connection is disabled.");
    if (target.kind !== "shared") throw new ProvisioningRequestError("INVALID_CONNECTION_KIND", "Only shared MongoDB connections can provision managed databases.");

    await client.query(
      `INSERT INTO database_resources
        (id, project_id, connection_id, name, database_name, username,
         credential_ciphertext, credential_nonce, credential_auth_tag, wrapped_dek,
         wrap_nonce, wrap_auth_tag, key_version, encryption_context_version,
         backup_username, backup_credential_ciphertext, backup_credential_nonce,
         backup_credential_auth_tag, backup_wrapped_dek, backup_wrap_nonce,
         backup_wrap_auth_tag, backup_key_version, created_by)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,2,$14,$15,$16,$17,$18,$19,$20,$21,$22)`,
      [resourceId, input.projectId, input.connectionId, input.name, identity.databaseName, identity.username,
       encrypted.ciphertext, encrypted.nonce, encrypted.authTag, encrypted.wrappedDek,
       encrypted.wrapNonce, encrypted.wrapAuthTag, encrypted.keyVersion,
       backupIdentity.username, encryptedBackupPassword.ciphertext, encryptedBackupPassword.nonce,
       encryptedBackupPassword.authTag, encryptedBackupPassword.wrappedDek, encryptedBackupPassword.wrapNonce,
       encryptedBackupPassword.wrapAuthTag, encryptedBackupPassword.keyVersion, input.caller.userId],
    );
    await client.query(
      "INSERT INTO provisioning_jobs (id, project_id, resource_id, operation, status) VALUES ($1,$2,$3,'provision','queued')",
      [jobId, input.projectId, resourceId],
    );
    await client.query(
      `INSERT INTO audit_events (actor_user_id, project_id, action, target_type, target_id, metadata)
       VALUES ($1,$2,'database.provision.request','database',$3,jsonb_build_object('connectionId',$4::text,'databaseName',$5::text))`,
      [input.caller.userId, input.projectId, resourceId, input.connectionId, identity.databaseName],
    );
    await client.query("COMMIT");
    return { id: resourceId, name: input.name, databaseName: identity.databaseName, username: identity.username, status: "provisioning", jobId };
  } catch (error) {
    await client.query("ROLLBACK");
    if (typeof error === "object" && error !== null && "code" in error && error.code === "23505") {
      throw new ProvisioningRequestError("RESOURCE_NAME_TAKEN", "A database resource with this name already exists in the project.");
    }
    throw error;
  } finally {
    client.release();
  }
}

export async function listProjectDatabases(
  pool: Pool,
  caller: ProvisioningCaller,
  projectId: string,
): Promise<Array<{ id: string; name: string; databaseName: string; username: string; status: string; lastErrorCode: string | null; createdAt: Date; updatedAt: Date }>> {
  const access = await pool.query<{ role: string }>(
    `SELECT CASE WHEN u.is_platform_admin THEN 'platform_admin' ELSE pm.role END AS role
       FROM projects p JOIN users u ON u.id = $2
       LEFT JOIN project_memberships pm ON pm.project_id = p.id AND pm.user_id = u.id
      WHERE p.id = $1 AND (u.is_platform_admin OR pm.user_id IS NOT NULL) LIMIT 1`,
    [projectId, caller.userId],
  );
  const role = access.rows[0]?.role;
  if (!role) throw new ProvisioningRequestError("PROJECT_NOT_FOUND", "The project was not found.");
  if (!hasProjectPermission(role, "database:read")) throw new ProvisioningRequestError("FORBIDDEN", "Database read permission is required.");
  const result = await pool.query(
    `SELECT id, name, database_name AS "databaseName", username, status,
            last_error_code AS "lastErrorCode", created_at AS "createdAt", updated_at AS "updatedAt"
       FROM database_resources WHERE project_id = $1 AND status <> 'deleted' ORDER BY created_at DESC`,
    [projectId],
  );
  return result.rows;
}

export async function requestDatabaseDeletion(
  pool: Pool,
  input: { caller: ProvisioningCaller; projectId: string; databaseId: string; confirmDatabaseName: string },
): Promise<{ id: string; databaseName: string; status: "deleting"; jobId: string }> {
  const jobId = randomUUID();
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    const access = await client.query<{ role: string }>(
      `SELECT CASE WHEN u.is_platform_admin THEN 'platform_admin' ELSE pm.role END AS role
         FROM projects p
         JOIN users u ON u.id = $2
         LEFT JOIN project_memberships pm ON pm.project_id = p.id AND pm.user_id = u.id
        WHERE p.id = $1 AND (u.is_platform_admin OR pm.user_id IS NOT NULL)
        FOR UPDATE OF p`,
      [input.projectId, input.caller.userId],
    );
    const role = access.rows[0]?.role;
    if (!role) throw new ProvisioningRequestError("PROJECT_NOT_FOUND", "The project was not found.");
    if (!hasProjectPermission(role, "database:admin")) {
      throw new ProvisioningRequestError("FORBIDDEN", "Database administration permission is required.");
    }
    const selected = await client.query<{ database_name: string; status: string }>(
      "SELECT database_name, status FROM database_resources WHERE id=$1 AND project_id=$2 FOR UPDATE",
      [input.databaseId, input.projectId],
    );
    const resource = selected.rows[0];
    if (!resource || resource.status === "deleted") {
      throw new ProvisioningRequestError("DATABASE_NOT_FOUND", "The database resource was not found.");
    }
    if (resource.database_name !== input.confirmDatabaseName) {
      throw new ProvisioningRequestError("CONFIRMATION_MISMATCH", "The confirmation name does not match this database.");
    }
    if (resource.status !== "ready" && resource.status !== "failed") {
      throw new ProvisioningRequestError("DATABASE_NOT_READY", "The database must be ready or failed before deletion can be queued.");
    }
    await client.query(
      "UPDATE database_resources SET status='deleting', last_error_code=NULL, updated_at=now() WHERE id=$1",
      [input.databaseId],
    );
    await client.query(
      "INSERT INTO provisioning_jobs (id, project_id, resource_id, operation, status) VALUES ($1,$2,$3,'delete','queued')",
      [jobId, input.projectId, input.databaseId],
    );
    await client.query(
      `INSERT INTO audit_events (actor_user_id, project_id, action, target_type, target_id, metadata)
       VALUES ($1,$2,'database.delete.request','database',$3,jsonb_build_object('databaseName',$4::text))`,
      [input.caller.userId, input.projectId, input.databaseId, resource.database_name],
    );
    await client.query("COMMIT");
    return { id: input.databaseId, databaseName: resource.database_name, status: "deleting", jobId };
  } catch (error) {
    await client.query("ROLLBACK");
    if (typeof error === "object" && error !== null && "code" in error && error.code === "23505") {
      throw new ProvisioningRequestError("DATABASE_OPERATION_ACTIVE", "A database operation is already active.");
    }
    throw error;
  } finally {
    client.release();
  }
}
