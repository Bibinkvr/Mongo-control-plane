-- Dedicated read-only credentials for backup workers.
BEGIN;

ALTER TABLE database_resources
  ADD COLUMN backup_username text,
  ADD COLUMN backup_credential_ciphertext bytea,
  ADD COLUMN backup_credential_nonce bytea,
  ADD COLUMN backup_credential_auth_tag bytea,
  ADD COLUMN backup_wrapped_dek bytea,
  ADD COLUMN backup_wrap_nonce bytea,
  ADD COLUMN backup_wrap_auth_tag bytea,
  ADD COLUMN backup_key_version integer;

ALTER TABLE database_resources
  ADD CONSTRAINT database_resources_backup_credential_complete CHECK (
    (backup_username IS NULL AND backup_credential_ciphertext IS NULL
      AND backup_credential_nonce IS NULL AND backup_credential_auth_tag IS NULL
      AND backup_wrapped_dek IS NULL AND backup_wrap_nonce IS NULL
      AND backup_wrap_auth_tag IS NULL AND backup_key_version IS NULL)
    OR
    (backup_username IS NOT NULL AND backup_credential_ciphertext IS NOT NULL
      AND backup_credential_nonce IS NOT NULL AND octet_length(backup_credential_nonce)=12
      AND backup_credential_auth_tag IS NOT NULL AND octet_length(backup_credential_auth_tag)=16
      AND backup_wrapped_dek IS NOT NULL AND octet_length(backup_wrapped_dek)=32
      AND backup_wrap_nonce IS NOT NULL AND octet_length(backup_wrap_nonce)=12
      AND backup_wrap_auth_tag IS NOT NULL AND octet_length(backup_wrap_auth_tag)=16
      AND backup_key_version IS NOT NULL AND backup_key_version > 0)
  );

CREATE UNIQUE INDEX database_resources_connection_backup_user_uq
  ON database_resources(connection_id, backup_username)
  WHERE backup_username IS NOT NULL;

COMMIT;
