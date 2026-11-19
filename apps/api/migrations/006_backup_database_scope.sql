-- Bind backup records to one managed database, never an entire connection.
BEGIN;

ALTER TABLE database_resources
  ADD CONSTRAINT database_resources_id_project_connection_uq
  UNIQUE (id, project_id, connection_id);

ALTER TABLE backup_records
  ADD COLUMN database_id uuid;

-- Jobs queued by the earlier connection-scoped API cannot be safely executed.
-- Preserve the records for audit, but fail them rather than risking a cross-tenant dump.
UPDATE backup_jobs
   SET status='failed', last_error_code='BACKUP_TARGET_REQUIRES_DATABASE',
       lock_token=NULL, locked_at=NULL, lease_expires_at=NULL, updated_at=now()
 WHERE status IN ('queued','running')
   AND backup_id IN (
     SELECT id FROM backup_records WHERE database_id IS NULL
   );

UPDATE backup_records
   SET status='failed', last_error_code='BACKUP_TARGET_REQUIRES_DATABASE',
       updated_at=now()
 WHERE status IN ('queued','running') AND database_id IS NULL;

ALTER TABLE backup_records
  ADD CONSTRAINT backup_records_database_owner_fk
  FOREIGN KEY (database_id, project_id, connection_id)
  REFERENCES database_resources (id, project_id, connection_id)
  ON DELETE RESTRICT;

ALTER TABLE backup_records
  ADD CONSTRAINT backup_records_active_requires_database
  CHECK (status NOT IN ('queued','running') OR database_id IS NOT NULL);

CREATE INDEX backup_records_database_created_idx
  ON backup_records(database_id, created_at DESC);

COMMIT;
