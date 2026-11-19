-- Permit reuse of a display name after a resource has been fully deleted.
-- Keep tombstones while allowing their source connection to be removed.
ALTER TABLE database_resources ALTER COLUMN connection_id DROP NOT NULL;
ALTER TABLE database_resources DROP CONSTRAINT database_resources_connection_id_fkey;
ALTER TABLE database_resources
  ADD CONSTRAINT database_resources_connection_id_fkey
  FOREIGN KEY (connection_id) REFERENCES connection_targets(id) ON DELETE SET NULL;

ALTER TABLE database_resources
  DROP CONSTRAINT database_resources_project_name_uq;

CREATE UNIQUE INDEX database_resources_project_name_active_uq
  ON database_resources(project_id, name)
  WHERE status <> 'deleted';
