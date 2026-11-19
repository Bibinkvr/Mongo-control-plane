-- Durable backup inventory and job queue. Backup payloads remain outside PostgreSQL.
BEGIN;

CREATE TABLE backup_records (
  id uuid PRIMARY KEY,
  project_id uuid NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  connection_id uuid NOT NULL REFERENCES connection_targets(id) ON DELETE RESTRICT,
  name text NOT NULL,
  format text NOT NULL DEFAULT 'mongodump_archive_gzip'
    CHECK (format IN ('mongodump_archive_gzip')),
  status text NOT NULL DEFAULT 'queued'
    CHECK (status IN ('queued', 'running', 'ready', 'failed', 'deleting', 'deleted')),
  storage_key text UNIQUE,
  nonce bytea,
  auth_tag bytea,
  wrapped_dek bytea,
  wrap_nonce bytea,
  wrap_auth_tag bytea,
  key_version integer CHECK (key_version IS NULL OR key_version > 0),
  plaintext_bytes bigint CHECK (plaintext_bytes IS NULL OR plaintext_bytes > 0),
  sha256 char(64) CHECK (sha256 IS NULL OR sha256 ~ '^[a-f0-9]{64}$'),
  last_error_code text,
  retention_protected boolean NOT NULL DEFAULT false,
  created_by uuid REFERENCES users(id) ON DELETE SET NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  started_at timestamptz,
  completed_at timestamptz,
  updated_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT backup_records_name_not_blank CHECK (length(btrim(name)) > 0),
  CONSTRAINT backup_records_envelope_complete CHECK (
    (storage_key IS NULL AND nonce IS NULL AND auth_tag IS NULL AND wrapped_dek IS NULL
      AND wrap_nonce IS NULL AND wrap_auth_tag IS NULL AND key_version IS NULL
      AND plaintext_bytes IS NULL AND sha256 IS NULL)
    OR
    (storage_key IS NOT NULL AND nonce IS NOT NULL AND octet_length(nonce) = 12
      AND auth_tag IS NOT NULL AND octet_length(auth_tag) = 16
      AND wrapped_dek IS NOT NULL AND octet_length(wrapped_dek) = 32
      AND wrap_nonce IS NOT NULL AND octet_length(wrap_nonce) = 12
      AND wrap_auth_tag IS NOT NULL AND octet_length(wrap_auth_tag) = 16
      AND key_version IS NOT NULL AND plaintext_bytes IS NOT NULL AND sha256 IS NOT NULL)
  ),
  CONSTRAINT backup_records_ready_has_payload CHECK (status <> 'ready' OR storage_key IS NOT NULL),
  CONSTRAINT backup_records_timestamps CHECK (
    completed_at IS NULL OR (started_at IS NOT NULL AND completed_at >= started_at)
  )
);

CREATE INDEX backup_records_project_created_idx
  ON backup_records(project_id, created_at DESC);
CREATE INDEX backup_records_connection_created_idx
  ON backup_records(connection_id, created_at DESC);
CREATE INDEX backup_records_retention_idx
  ON backup_records(project_id, status, retention_protected, completed_at);

CREATE TABLE backup_jobs (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  project_id uuid NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  backup_id uuid NOT NULL REFERENCES backup_records(id) ON DELETE RESTRICT,
  operation text NOT NULL CHECK (operation IN ('backup', 'restore', 'delete')),
  target_database_id uuid REFERENCES database_resources(id) ON DELETE RESTRICT,
  status text NOT NULL DEFAULT 'queued'
    CHECK (status IN ('queued', 'running', 'succeeded', 'failed', 'cancelled')),
  attempt_count integer NOT NULL DEFAULT 0 CHECK (attempt_count >= 0),
  max_attempts integer NOT NULL DEFAULT 3 CHECK (max_attempts BETWEEN 1 AND 10),
  available_at timestamptz NOT NULL DEFAULT now(),
  locked_at timestamptz,
  lease_expires_at timestamptz,
  lock_token uuid,
  last_error_code text,
  created_by uuid REFERENCES users(id) ON DELETE SET NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT backup_jobs_lease_consistency CHECK (
    (status = 'running' AND lock_token IS NOT NULL AND lease_expires_at IS NOT NULL)
    OR (status <> 'running' AND lock_token IS NULL AND lease_expires_at IS NULL)
  ),
  CONSTRAINT backup_jobs_restore_target CHECK (
    (operation = 'restore' AND target_database_id IS NOT NULL)
    OR (operation <> 'restore' AND target_database_id IS NULL)
  )
);

CREATE INDEX backup_jobs_claim_idx
  ON backup_jobs(status, available_at, lease_expires_at, created_at);
CREATE UNIQUE INDEX backup_jobs_one_active_operation_uq
  ON backup_jobs(backup_id, operation)
  WHERE status IN ('queued', 'running');

COMMIT;
