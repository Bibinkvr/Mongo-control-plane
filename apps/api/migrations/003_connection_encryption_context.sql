-- Version the AAD format. Existing records remain legacy-compatible (version 1);
-- new records use project/connection-bound AAD (version 2).
BEGIN;
ALTER TABLE connection_targets ADD COLUMN encryption_context_version smallint NOT NULL DEFAULT 1
  CHECK (encryption_context_version IN (1, 2));
COMMIT;
