import { MongoClient, type Db, type Document } from "mongodb";
import type { Pool } from "pg";
import { hasProjectPermission, type ProjectPermission } from "../auth/permissions.js";
import { loadConnectionCredentialInTransaction, type CredentialCaller } from "../connections/credential-service.js";
import { decryptSecretString, type EncryptedConnectionSecret, type EncryptionKeyring } from "../connections/crypto.js";
import { buildDatabaseConnectionUri } from "../provisioning/credentials.js";
import { createSafeMongoLookup, type MongoNetworkPolicy } from "../provisioning/network-guard.js";

export type WorkspacePolicy = MongoNetworkPolicy & { tls?: boolean };
export class DatabaseWorkspaceError extends Error {
  constructor(
    public readonly code: "PROJECT_NOT_FOUND" | "DATABASE_NOT_FOUND" | "DATABASE_NOT_READY" | "FORBIDDEN",
    message: string,
  ) {
    super(message);
    this.name = "DatabaseWorkspaceError";
  }
}

type WorkspaceResource = EncryptedConnectionSecret & {
  id: string;
  project_id: string;
  connection_id: string;
  database_name: string;
  username: string;
  status: string;
};

export type WorkspaceRequest = {
  caller: CredentialCaller;
  projectId: string;
  databaseId: string;
  permission: Extract<ProjectPermission, "database:read" | "database:write" | "database:admin">;
  auditAction?: string;
  auditMetadata?: Record<string, unknown>;
};

/**
 * Runs one bounded operation as the generated database-scoped application user.
 * PostgreSQL row locks are held for the operation so deletion/key rotation cannot
 * race an active workspace request. No administrator URI or app password leaves
 * this server-side function.
 */
export async function withManagedDatabase<T>(
  pool: Pool,
  keyring: EncryptionKeyring,
  policy: WorkspacePolicy,
  request: WorkspaceRequest,
  operation: (database: Db) => Promise<T>,
): Promise<T> {
  const pg = await pool.connect();
  let mongo: MongoClient | undefined;
  try {
    await pg.query("BEGIN");
    const access = await pg.query<{ role: string }>(
      `SELECT CASE WHEN u.is_platform_admin THEN 'platform_admin' ELSE pm.role END AS role
         FROM projects p
         JOIN users u ON u.id = $2
         LEFT JOIN project_memberships pm ON pm.project_id = p.id AND pm.user_id = u.id
        WHERE p.id = $1 AND u.status='active'
          AND (u.is_platform_admin OR pm.user_id IS NOT NULL)
        FOR SHARE OF p`,
      [request.projectId, request.caller.userId],
    );
    const role = access.rows[0]?.role;
    if (!role) throw new DatabaseWorkspaceError("PROJECT_NOT_FOUND", "The project was not found.");
    if (!hasProjectPermission(role, request.permission)) {
      throw new DatabaseWorkspaceError("FORBIDDEN", "You do not have permission to perform this database operation.");
    }

    const selected = await pg.query<WorkspaceResource>(
      `SELECT id, project_id, connection_id, database_name, username, status,
              credential_ciphertext AS ciphertext, credential_nonce AS nonce,
              credential_auth_tag AS "authTag", wrapped_dek AS "wrappedDek",
              wrap_nonce AS "wrapNonce", wrap_auth_tag AS "wrapAuthTag",
              key_version AS "keyVersion", encryption_context_version AS "encryptionContextVersion"
         FROM database_resources
        WHERE id=$1 AND project_id=$2
        FOR SHARE`,
      [request.databaseId, request.projectId],
    );
    const resource = selected.rows[0];
    if (!resource || resource.status === "deleted") {
      throw new DatabaseWorkspaceError("DATABASE_NOT_FOUND", "The database resource was not found.");
    }
    if (resource.status !== "ready") {
      throw new DatabaseWorkspaceError("DATABASE_NOT_READY", "The database is not ready for workspace operations.");
    }
    if (!resource.connection_id) {
      throw new DatabaseWorkspaceError("DATABASE_NOT_READY", "The database connection is unavailable.");
    }

    const password = decryptSecretString(resource, keyring, {
      projectId: request.projectId,
      connectionId: resource.id,
    });
    const administratorUri = await loadConnectionCredentialInTransaction(pg, keyring, {
      caller: request.caller,
      projectId: request.projectId,
      connectionId: resource.connection_id,
    });
    const applicationUri = buildDatabaseConnectionUri(
      administratorUri,
      resource.username,
      password,
      resource.database_name,
      policy.tls ?? true,
    );

    mongo = new MongoClient(applicationUri, {
      tls: policy.tls ?? true,
      lookup: createSafeMongoLookup({
        ...(policy.allowPrivateNetworks !== undefined ? { allowPrivateNetworks: policy.allowPrivateNetworks } : {}),
        ...(policy.allowLoopback !== undefined ? { allowLoopback: policy.allowLoopback } : {}),
      }),
      serverSelectionTimeoutMS: 10_000,
      connectTimeoutMS: 10_000,
      socketTimeoutMS: 30_000,
      maxPoolSize: 2,
      minPoolSize: 0,
      maxConnecting: 1,
      writeConcern: { w: "majority" },
      appName: "MongoControlPlaneWorkspace",
    });
    await mongo.connect();
    const result = await operation(mongo.db(resource.database_name));

    if (request.auditAction) {
      await pg.query(
        `INSERT INTO audit_events (actor_user_id, project_id, action, target_type, target_id, metadata)
         VALUES ($1,$2,$3,'database',$4,$5::jsonb)`,
        [
          request.caller.userId,
          request.projectId,
          request.auditAction,
          request.databaseId,
          JSON.stringify(request.auditMetadata ?? {}),
        ],
      );
    }
    await pg.query("COMMIT");
    return result;
  } catch (error) {
    await pg.query("ROLLBACK");
    throw error;
  } finally {
    await mongo?.close().catch(() => undefined);
    pg.release();
  }
}

export function isSafeCollectionName(name: string): boolean {
  return name.length >= 1
    && name.length <= 120
    && /^[A-Za-z0-9_][A-Za-z0-9_.-]*$/.test(name)
    && !name.startsWith("system.")
    && !name.includes("$");
}

export function isSafeDocument(value: unknown, depth = 0): value is Document {
  if (depth > 20 || typeof value !== "object" || value === null || Array.isArray(value)) return false;
  const visit = (item: unknown, level: number): boolean => {
    if (level > 20) return false;
    if (Array.isArray(item)) return item.every((entry) => visit(entry, level + 1));
    if (typeof item !== "object" || item === null) return true;
    for (const [key, child] of Object.entries(item)) {
      if (!key || key.startsWith("$") || key.includes(".") || ["__proto__", "prototype", "constructor"].includes(key)) return false;
      if (!visit(child, level + 1)) return false;
    }
    return true;
  };
  return visit(value, depth);
}
