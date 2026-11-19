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
  database_ciphertext: Buffer;
  database_nonce: Buffer;
  database_auth_tag: Buffer;
  database_wrapped_dek: Buffer;
  database_wrap_nonce: Buffer;
  database_wrap_auth_tag: Buffer;
  database_key_version: number;
  database_encryption_context_version: 2;
  connection_id: string;
  connection_ciphertext: Buffer;
  connection_nonce: Buffer;
  connection_auth_tag: Buffer;
  connection_wrapped_dek: Buffer;
  connection_wrap_nonce: Buffer;
  connection_wrap_auth_tag: Buffer;
  connection_key_version: number;
  connection_encryption_context_version: 1 | 2;
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
              d.credential_ciphertext AS database_ciphertext,
              d.credential_nonce AS database_nonce,
              d.credential_auth_tag AS database_auth_tag,
              d.wrapped_dek AS database_wrapped_dek,
              d.wrap_nonce AS database_wrap_nonce,
              d.wrap_auth_tag AS database_wrap_auth_tag,
              d.key_version AS database_key_version,
              d.encryption_context_version AS database_encryption_context_version,
              c.id AS connection_id,
              c.secret_ciphertext AS connection_ciphertext,
              c.secret_nonce AS connection_nonce,
              c.secret_auth_tag AS connection_auth_tag,
              c.wrapped_dek AS connection_wrapped_dek,
              c.wrap_nonce AS connection_wrap_nonce,
              c.wrap_auth_tag AS connection_wrap_auth_tag,
              c.key_version AS connection_key_version,
              c.encryption_context_version AS connection_encryption_context_versionfrom "pg";
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
  database_ciphertext: Buffer;
  database_nonce: Buffer;
  database_auth_tag: Buffer;
  database_wrapped_dek: Buffer;
  database_wrap_nonce: Buffer;
  database_wrap_auth_tag: Buffer;
  database_key_version: number;
  database_encryption_context_version: 2;
  connection_id: string;
  connection_ciphertext: Buffer;
  connection_nonce: Buffer;
  connection_auth_tag: Buffer;
  connection_wrapped_dek: Buffer;
  connection_wrap_nonce: Buffer;
  connection_wrap_auth_tag: Buffer;
  connection_key_version: number;
  connection_encryption_context_version: 1 | 2;
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
    const databaseEncrypted: EncryptedConnectionSecret = {
      ciphertext: row.database_ciphertext,
      nonce: row.database_nonce,
      authTag: row.database_auth_tag,
      wrappedDek: row.database_wrapped_dek,
      wrapNonce: row.database_wrap_nonce,
      wrapAuthTag: row.database_wrap_auth_tag,
      keyVersion: row.database_key_version,
      encryptionContextVersion: row.database_encryption_context_version,
    };
    const connectionEncrypted: EncryptedConnectionSecret = {
      ciphertext: row.connection_ciphertext,
      nonce: row.connection_nonce,
      authTag: row.connection_auth_tag,
      wrappedDek: row.connection_wrapped_dek,
      wrapNonce: row.connection_wrap_nonce,
      wrapAuthTag: row.connection_wrap_auth_tag,
      keyVersion: row.connection_key_version,
      encryptionContextVersion: row.connection_encryption_context_version,
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
