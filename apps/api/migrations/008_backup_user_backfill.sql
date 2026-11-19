-- Backfill dedicated backup users for databases created before migration 007.
BEGIN;

ALTER TABLE provisioning_jobs
  DROP CONSTRAINT IF EXISTS provisioning_jobs_operation_check;

ALTER TABLE provisioning_jobs
  ADD CONSTRAINT provisioning_jobs_operation_check
  CHECK (operation IN ('provision', 'delete', 'backup_user'));

INSERT INTO provisioning_jobs (id, project_id, resource_id, operation, status)
SELECT gen_random_uuid(), d.project_id, d.id, 'backup_user', 'queued'
  FROM database_resources d
 WHERE d.status='ready' AND d.backup_username IS NULL
ON CONFLICT DO NOTHING;

COMMIT;
