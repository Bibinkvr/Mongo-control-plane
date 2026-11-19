import type { Pool } from "pg";
import { buildDatabaseConnectionUri } from "../provisioning/credentials.js";
import {
  decryptConnectionUri,
  decryptSecretString,
  type EncryptedConnectionSecret,
  type EncryptionKeyring,
} from "../connections/crypto.js";

type BackupCredentialRow = {
  project_id: string;
  backup_id: string;
  database_id: string;
  database_name: string;
  username: string;
  database_encryption_context_version: 2;
  database_secret: EncryptedConnectionSecret;
  connection_id: string;
  connection_secret: EncryptedConnectionSecret;
  created_by: string | null;
};

export class BackupCredentialError extends Error {
  constructor(
    public readonly code: "BACKUP_JOB_NOT_OWNED" | "BACKUP_TARGET_UNAVAILABLE",
    message: string,
  ) {
    super(message);
    this.name = "BackupCredentialError";
  }
}

/**
 * Internal worker-only credential access. A valid running backup lease is
 * required. The resulting URI is scoped to one managed database user and
 * must never be logged, serialized to an API response, or persisted plaintext.
 */
export async function loadBackupDatabaseCredential(
  pool: Pool,
  keyring: EncryptionKeyring,
  input: { projectId: string; backupId: string; jobId: string; lockToken: string },
): Promise<{ uri: string; databaseName: string; actorId: string | null }> {
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    const result = await client.query<BackupCredentialRow>(
      `SELECT b.project_id, b.id AS backup_id, b.created_by,
              d.id AS database_id, d.database_name, d.username,
              d.encryption_context_version AS database_encryption_context_version,
              jsonb_build_object(
                'ciphertext', encode(d.credential_ciphertext, 'base64'),
                'nonce', encode(d.credential_nonce, 'base64'),
                'authTag', encode(d.credential_auth_tag, 'base64'),
                'wrappedDek', encode(d.wrapped_dek, 'base64'),
                'wrapNonce', encode(d.wrap_nonce, 'base64'),
                'wrapAuthTag', encode(d.wrap_auth_tag, 'base64'),
                'keyVersion', d.key_version,
                'encryptionContextVersion', d.encryption_context_version
              ) AS database_secret,
              c.id AS connection_id,
              jsonb_build_object(
                'ciphertext', encode(c.secret_ciphertext, 'base64'),
                'nonce', encode(c.secret_nonce, 'base64'),
                'authTag', encode(c.secret_auth_tag, 'base64'),
                'wrappedDek', encode(c.wrapped_dek, 'base64'),
                'wrapNonce', encode(c.wrap_nonce, 'base64'),
                'wrapAuthTag', encode(c.wrap_auth_tag, 'base64'),
                'keyVersion', c.key_version,
                'encryptionContextVersion', c.encryption_context_version
              ) AS connection_secret
         FROM backup_jobs j
         JOIN backup_records b ON b.id=j.backup_id AND b.project_id=j.project_id
         JOIN database_resources d ON d.id=b.database_id
                                   AND d.project_id=b.project_id
                                   AND d.connection_id=b.connection_id
         JOIN connection_targets c ON c.id=d.connection_id AND c.project_id=d.project_id
        WHERE j.id=$1 AND j.backup_id=$2 AND j.project_id=$3
          AND j.operation='backup' AND j.status='running' AND j.lock_token=$4
          AND b.status='running' AND d.status='ready' AND c.status='configured'
        FOR SHARE OF j,b,d,c`,
      [input.jobId, input.backupId, input.projectId, input.lockToken],
    );
    const row = result.rows[0];
    if (!row) throw new BackupCredentialError("BACKUP_JOB_NOT_OWNED", "The running backup job no longer owns its target.");
    const decode = (value: unknown): Buffer => {
      if (typeof value !== "string") throw new Error("Encrypted backup credential metadata is invalid.");
      return Buffer.from(value, "base64");
    };
    const databaseSecret = row.database_secret as unknown as Record<string, unknown>;
    const connectionSecret = row.connection_secret as unknown as Record<string, unknown>;
    const databaseEncrypted: EncryptedConnectionSecret = {
      ciphertext: decode(databaseSecret["ciphertext"]),
      nonce: decode(databaseSecret["nonce"]),
      authTag: decode(databaseSecret["authTag"]),
      wrappedDek: decode(databaseSecret["wrappedDek"]),
      wrapNonce: decode(databaseSecret["wrapNonce"]),
      wrapAuthTag: decode(databaseSecret["wrapAuthTag"]),
      keyVersion: Number(databaseSecret["keyVersion"]),
      encryptionContextVersion: Number(databaseSecret["encryptionContextVersion"]) as 1 | 2,
    };
    const connectionEncrypted: EncryptedConnectionSecret = {
      ciphertext: decode(connectionSecret["ciphertext"]),
      nonce: decode(connectionSecret["nonce"]),
      authTag: decode(connectionSecret["authTag"]),
      wrappedDek: decode(connectionSecret["wrappedDek"]),
      wrapNonce: decode(connectionSecret["wrapNonce"]),
      wrapAuthTag: decode(connectionSecret["wrapAuthTag"]),
      keyVersion: Number(connectionSecret["keyVersion"]),
      encryptionContextVersion: Number(connectionSecret["encryptionContextVersion"]) as 1 | 2,
    };
    if (databaseEncrypted.encryptionContextVersion !== 2) {
      throw new Error("Managed database credential encryption context is unsupported.");
    }
    const password = decryptSecretString(databaseEncrypted, keyring, {
      projectId: row.project_id,
      connectionId: row.database_id,
    });
    const adminUri = decryptConnectionUri(connectionEncrypted, keyring, {
      projectId: row.project_id,
      connectionId: row.connection_id,
    });
    const uri = buildDatabaseConnectionUri(adminUri, row.username, password, row.database_name, true);
    await client.query(
      `INSERT INTO audit_events (actor_user_id, project_id, action, target_type, target_id, metadata)
       VALUES ($1,$2,'backup.credential.use','backup',$3,jsonb_build_object('databaseId',$4::text))`,
      [row.created_by, row.project_id, row.backup_id, row.database_id],
    );
    await client.query("COMMIT");
    return { uri, databaseName: row.database_name, actorId: row.created_by };
  } catch (error) {
    await client.query("ROLLBACK");
    throw error;
  } finally {
    client.release();
  }
}
