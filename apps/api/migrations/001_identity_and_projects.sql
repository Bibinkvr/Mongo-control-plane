-- Mongo Control Plane: identity and project-control schema.
-- PostgreSQL is the control-plane store only. Customer MongoDB documents never
-- belong in these tables.
BEGIN;

CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE users (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  email text NOT NULL,
  email_normalized text GENERATED ALWAYS AS (lower(btrim(email))) STORED,
  password_hash text NOT NULL,
  display_name text NOT NULL,
  status text NOT NULL DEFAULT 'active'
    CHECK (status IN ('active', 'disabled', 'pending')),
  is_platform_admin boolean NOT NULL DEFAULT false,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT users_email_not_blank CHECK (length(btrim(email)) > 3),
  CONSTRAINT users_display_name_not_blank CHECK (length(btrim(display_name)) > 0),
  CONSTRAINT users_password_hash_not_blank CHECK (length(password_hash) > 20)
);

CREATE UNIQUE INDEX users_email_normalized_uq ON users(email_normalized);

CREATE TABLE sessions (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  token_hash bytea NOT NULL UNIQUE,
  created_at timestamptz NOT NULL DEFAULT now(),
  expires_at timestamptz NOT NULL,
  last_seen_at timestamptz NOT NULL DEFAULT now(),
  revoked_at timestamptz,
  ip_address inet,
  user_agent text,
  CONSTRAINT sessions_expiry_after_creation CHECK (expires_at > created_at),
  CONSTRAINT sessions_user_agent_size CHECK (user_agent IS NULL OR length(user_agent) <= 1024)
);

CREATE INDEX sessions_user_active_idx
  ON sessions(user_id, expires_at)
  WHERE revoked_at IS NULL;

CREATE TABLE projects (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  name text NOT NULL,
  slug text NOT NULL,
  created_by uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT projects_name_not_blank CHECK (length(btrim(name)) > 0),
  CONSTRAINT projects_slug_format CHECK (slug ~ '^[a-z0-9]+(?:-[a-z0-9]+)*$'),
  CONSTRAINT projects_slug_uq UNIQUE (slug)
);

CREATE TABLE project_memberships (
  project_id uuid NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  role text NOT NULL CHECK (role IN ('project_admin', 'developer', 'read_only')),
  created_at timestamptz NOT NULL DEFAULT now(),
  created_by uuid REFERENCES users(id) ON DELETE SET NULL,
  PRIMARY KEY (project_id, user_id)
);

CREATE INDEX project_memberships_user_idx ON project_memberships(user_id, project_id);

CREATE TABLE audit_events (
  id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  actor_user_id uuid REFERENCES users(id) ON DELETE SET NULL,
  project_id uuid REFERENCES projects(id) ON DELETE SET NULL,
  action text NOT NULL,
  target_type text NOT NULL,
  target_id text,
  metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
  request_id text,
  occurred_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT audit_action_not_blank CHECK (length(btrim(action)) > 0),
  CONSTRAINT audit_target_type_not_blank CHECK (length(btrim(target_type)) > 0),
  CONSTRAINT audit_metadata_object CHECK (jsonb_typeof(metadata) = 'object')
);

CREATE INDEX audit_events_project_time_idx ON audit_events(project_id, occurred_at DESC);
CREATE INDEX audit_events_actor_time_idx ON audit_events(actor_user_id, occurred_at DESC);

-- Audit events are append-only at the database layer. The application DB role
-- should not own these tables or have permission to disable triggers.
CREATE FUNCTION reject_audit_event_mutation() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  RAISE EXCEPTION 'audit_events is append-only';
END;
$$;

CREATE TRIGGER audit_events_no_update
  BEFORE UPDATE OR DELETE ON audit_events
  FOR EACH ROW EXECUTE FUNCTION reject_audit_event_mutation();

CREATE TRIGGER audit_events_no_truncate
  BEFORE TRUNCATE ON audit_events
  FOR EACH STATEMENT EXECUTE FUNCTION reject_audit_event_mutation();

COMMIT;
