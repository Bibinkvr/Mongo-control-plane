-- Track whether the read-only backup principal has actually been provisioned in MongoDB.
BEGIN;

ALTER TABLE database_resources
  ADD COLUMN backup_user_ready_at timestamptz;

COMMIT;
