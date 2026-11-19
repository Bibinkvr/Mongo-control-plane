-- Encrypted MongoDB connection target registry. Never store plaintext URIs here.
BEGIN;

CREATE TABLE connection_targets (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  project_id uuid NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  name text NOT NULL,
  kind text NOT NULL CHECK (kind IN ('shared', 'dedicated', 'atlas')),
  host_label text NOT NULL,
  status text NOT NULL DEFAULT 'configured' CHECK (status IN ('configured', 'disabled')),
  secret_ciphertext bytea NOT NULL,
  secret_nonce bytea NOT NULL CHECK (octet_length(secret_nonce) = 12),
  secret_auth_tag bytea NOT NULL CHECK (octet_length(secret_auth_tag) = 16),
  wrapped_dek bytea NOT NULL,
  wrap_nonce bytea NOT NULL CHECK (octet_length(wrap_nonce) = 12),
  wrap_auth_tag bytea NOT NULL CHECK (octet_length(wrap_auth_tag) = 16),
  key_version integer NOT NULL CHECK (key_version > 0),
  created_by uuid REFERENCES users(id) ON DELETE SET NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT connection_targets_name_not_blank CHECK (length(btrim(name)) > 0),
  CONSTRAINT connection_targets_host_not_blank CHECK (length(btrim(host_label)) > 0),
  CONSTRAINT connection_targets_project_name_uq UNIQUE (project_id, name)
);

CREATE INDEX connection_targets_project_created_idx
  ON connection_targets(project_id, created_at DESC);

COMMIT;
