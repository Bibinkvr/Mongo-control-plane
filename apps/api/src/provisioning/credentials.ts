import type { Pool } from "pg";
import { hasProjectPermission } from "../auth/permissions.js";
import { loadConnectionCredentialInTransaction, type CredentialCaller } from "../connections/credential-service.js";
import {
  decryptSecretString,
  type EncryptedConnectionSecret,
  type EncryptionKeyring,
} from "../connections/crypto.js";

export class DatabaseCredentialError extends Error {
  constructor(
    public readonly code: "PROJECT_NOT_FOUND" | "DATABASE_NOT_FOUND" | "FORBIDDEN" | "DATABASE_NOT_READY",
    message: string,
  ) {
    super(message);
    this.name = "DatabaseCredentialError";
  }
}

type CredentialRow = EncryptedConnectionSecret & {
  id: string;
  project_id: string;
  connection_id: string;
  database_name: string;
  username: string;
  status: string;
  encryptionContextVersion: 2;
};

/** Rebuilds a user URI while preserving the original MongoDB host list and options. */
export function buildDatabaseConnectionUri(
  adminUri: string,
  username: string,
  password: string,
  databaseName: string,
): string {
  const match = /^(mongodb(?:\+srv)?:\/\/)(?:[^@/]*@)?([^/?#]+)(?:\/[^?#]*)?(?:\?([^#]*))?$/i.exec(adminUri);
  if (!match) throw new Error("The configured MongoDB URI cannot be safely transformed.");
  const scheme = match[1]!;
  const hosts = match[2]!;
  const params = new URLSearchParams(match[3] ?? "");
  params.set("authSource", databaseName);
  params.set("authMechanism", "SCRAM-SHA-256");
  params.set("tls", "true");
  return `${scheme}${encodeURIComponent(username)}:${encodeURIComponent(password)}@${hosts}/${encodeURIComponent(databaseName)}?${params.toString()}`;
}

/**
 * Explicit secret-reveal operation for database clients such as Compass.
 * Requires database:use and connection:use; never call from list/detail APIs.
 */
export async function revealDatabaseConnectionUri(
  pool: Pool,
  keyring: EncryptionKeyring,
  input: { caller: CredentialCaller; projectId: string; databaseId: string },
): Promise<string> {
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    const access = await client.query<{ role: string }>(
      `SELECT CASE WHEN u.is_platform_admin THEN 'platform_admin' ELSE pm.role END AS role
         FROM projects p
         JOIN users u ON u.id = $2
         LEFT JOIN project_memberships pm ON pm.project_id = p.id AND pm.user_id = u.id
        WHERE p.id = $1 AND (u.is_platform_admin OR pm.user_id IS NOT NULL)
        FOR SHARE OF p`,
      [input.projectId, input.caller.userId],
    );
    const role = access.rows[0]?.role;
    if (!role) throw new DatabaseCredentialError("PROJECT_NOT_FOUND", "The project was not found.");
    if (!hasProjectPermission(role, "database:use")) {
      throw new DatabaseCredentialError("FORBIDDEN", "Permission to use this database is required.");
    }

    const result = await client.query<CredentialRow>(
      `SELECT id, project_id, connection_id, database_name, username, status,
              credential_ciphertext AS ciphertext, credential_nonce AS nonce,
              credential_auth_tag AS "authTag", wrapped_dek AS "wrappedDek",
              wrap_nonce AS "wrapNonce", wrap_auth_tag AS "wrapAuthTag",
              key_version AS "keyVersion", encryption_context_version AS "encryptionContextVersion"
         FROM database_resources
        WHERE id=$1 AND project_id=$2
        FOR SHARE`,
      [input.databaseId, input.projectId],
    );
    const row = result.rows[0];
    if (!row) throw new DatabaseCredentialError("DATABASE_NOT_FOUND", "The database resource was not found.");
    if (row.status !== "ready") throw new DatabaseCredentialError("DATABASE_NOT_READY", "The database is not ready for connections.");

    const password = decryptSecretString(row, keyring, { projectId: input.projectId, connectionId: row.id });
    const adminUri = await loadConnectionCredentialInTransaction(client, keyring, {
      caller: input.caller,
      projectId: input.projectId,
      connectionId: row.connection_id,
    });
    const uri = buildDatabaseConnectionUri(adminUri, row.username, password, row.database_name);
    await client.query(
      `INSERT INTO audit_events (actor_user_id, project_id, action, target_type, target_id, metadata)
       VALUES ($1,$2,'database.credential.reveal','database',$3,jsonb_build_object('connectionId',$4::text))`,
      [input.caller.userId, input.projectId, row.id, row.connection_id],
    );
    await client.query("COMMIT");
    return uri;
  } catch (error) {
    await client.query("ROLLBACK");
    throw error;
  } finally {
    client.release();
  }
}
