-- Durable database resources and PostgreSQL-backed provisioning outbox.
BEGIN;

CREATE TABLE database_resources (
  id uuid PRIMARY KEY,
  project_id uuid NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  connection_id uuid NOT NULL REFERENCES connection_targets(id) ON DELETE RESTRICT,
  name text NOT NULL,
  database_name text NOT NULL,
  username text NOT NULL,
  credential_ciphertext bytea NOT NULL,
  credential_nonce bytea NOT NULL CHECK (octet_length(credential_nonce) = 12),
  credential_auth_tag bytea NOT NULL CHECK (octet_length(credential_auth_tag) = 16),
  wrapped_dek bytea NOT NULL,
  wrap_nonce bytea NOT NULL CHECK (octet_length(wrap_nonce) = 12),
  wrap_auth_tag bytea NOT NULL CHECK (octet_length(wrap_auth_tag) = 16),
  key_version integer NOT NULL CHECK (key_version > 0),
  encryption_context_version smallint NOT NULL CHECK (encryption_context_version = 2),
  status text NOT NULL DEFAULT 'provisioning'
    CHECK (status IN ('provisioning', 'ready', 'failed', 'deleting', 'deleted')),
  last_error_code text,
  created_by uuid REFERENCES users(id) ON DELETE SET NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT database_resources_name_not_blank CHECK (length(btrim(name)) > 0),
  CONSTRAINT database_resources_project_name_uq UNIQUE (project_id, name),
  CONSTRAINT database_resources_connection_db_uq UNIQUE (connection_id, database_name),
  CONSTRAINT database_resources_connection_user_uq UNIQUE (connection_id, username)
);

CREATE INDEX database_resources_project_created_idx
  ON database_resources(project_id, created_at DESC);

CREATE TABLE provisioning_jobs (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  project_id uuid NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  resource_id uuid NOT NULL REFERENCES database_resources(id) ON DELETE RESTRICT,
  operation text NOT NULL CHECK (operation IN ('provision', 'delete')),
  status text NOT NULL DEFAULT 'queued'
    CHECK (status IN ('queued', 'running', 'succeeded', 'failed', 'cancelled')),
  attempt_count integer NOT NULL DEFAULT 0 CHECK (attempt_count >= 0),
  max_attempts integer NOT NULL DEFAULT 5 CHECK (max_attempts BETWEEN 1 AND 20),
  available_at timestamptz NOT NULL DEFAULT now(),
  locked_at timestamptz,
  lease_expires_at timestamptz,
  lock_token uuid,
  last_error_code text,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT provisioning_jobs_lease_consistency CHECK (
    (status = 'running' AND lock_token IS NOT NULL AND lease_expires_at IS NOT NULL)
    OR (status <> 'running' AND lock_token IS NULL AND lease_expires_at IS NULL)
  )
);

CREATE INDEX provisioning_jobs_claim_idx
  ON provisioning_jobs(status, available_at, lease_expires_at, created_at);

CREATE UNIQUE INDEX provisioning_jobs_one_active_operation_uq
  ON provisioning_jobs(resource_id, operation)
  WHERE status IN ('queued', 'running');

COMMIT;
