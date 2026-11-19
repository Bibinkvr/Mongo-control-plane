import type { Pool } from "pg";
import { hasProjectPermission } from "../auth/permissions.js";
import {
  decryptConnectionUri,
  type EncryptedConnectionSecret,
  type EncryptionKeyring,
} from "./crypto.js";

export type CredentialCaller = { userId: string; isPlatformAdmin: boolean };
export type ConnectionCredentialRequest = {
  caller: CredentialCaller;
  projectId: string;
  connectionId: string;
};
export class ConnectionCredentialError extends Error {
  constructor(
    public readonly code: "PROJECT_NOT_FOUND" | "CONNECTION_NOT_FOUND" | "FORBIDDEN" | "CONNECTION_DISABLED",
    message: string,
  ) { super(message); this.name = "ConnectionCredentialError"; }
}
type CredentialRow = EncryptedConnectionSecret & {
  id: string;
  project_id: string;
  status: "configured" | "disabled";
  encryptionContextVersion: 1 | 2;
};

/**
 * Server-only credential access. Do not call from route handlers that serialize
 * the result, log the URI, or return it to a browser. The caller must already
 * have authenticated the user; this service re-checks project membership and
 * the dedicated connection:use permission before decrypting.
 */
export async function loadConnectionCredential(
  pool: Pool,
  keyring: EncryptionKeyring,
  request: ConnectionCredentialRequest,
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
      [request.projectId, request.caller.userId],
    );
    const role = access.rows[0]?.role;
    if (!role) throw new ConnectionCredentialError("PROJECT_NOT_FOUND", "The project was not found.");
    if (!hasProjectPermission(role, "connection:use")) {
      throw new ConnectionCredentialError("FORBIDDEN", "Permission to use this connection is required.");
    }

    const result = await client.query<CredentialRow>(
      `SELECT id, project_id, status,
              secret_ciphertext AS ciphertext, secret_nonce AS nonce,
              secret_auth_tag AS "authTag", wrapped_dek AS "wrappedDek",
              wrap_nonce AS "wrapNonce", wrap_auth_tag AS "wrapAuthTag",
              key_version AS "keyVersion",
              encryption_context_version AS "encryptionContextVersion"
         FROM connection_targets
        WHERE id = $1 AND project_id = $2
        FOR SHARE`,
      [request.connectionId, request.projectId],
    );
    const row = result.rows[0];
    if (!row) throw new ConnectionCredentialError("CONNECTION_NOT_FOUND", "The connection was not found.");
    if (row.status !== "configured") throw new ConnectionCredentialError("CONNECTION_DISABLED", "The connection is disabled.");

    const uri = decryptConnectionUri(row, keyring, {
      projectId: request.projectId,
      connectionId: request.connectionId,
    });
    await client.query(
      `INSERT INTO audit_events (actor_user_id, project_id, action, target_type, target_id, metadata)
       VALUES ($1, $2, 'connection.credential.use', 'connection', $3, '{}'::jsonb)`,
      [request.caller.userId, request.projectId, request.connectionId],
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
