-- Permit reuse of a display name after a resource has been fully deleted.
ALTER TABLE database_resources
  DROP CONSTRAINT database_resources_project_name_uq;

CREATE UNIQUE INDEX database_resources_project_name_active_uq
  ON database_resources(project_id, name)
  WHERE status <> 'deleted';
