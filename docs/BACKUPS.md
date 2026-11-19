# Backup architecture and security

## Current implementation status

The API exposes authenticated backup request and inventory endpoints, backed by PostgreSQL metadata and a durable job queue. Requests are queued transactionally and audited. A leased background worker and fixed-argument `mongodump` adapter are implemented. The worker is disabled by default and must not be enabled until a separate network namespace/container has a verified outbound allowlist. CI exercises the adapter and worker with a fake executable; it does not yet prove compatibility with a real MongoDB Database Tools installation or customer MongoDB topology. Restore endpoints, retention policies, scheduling, object storage, and a backup UI remain unimplemented. This is not yet a production backup service.

## Backup request API\n\n- `POST /api/projects/:projectId/backups` queues a backup request for one ready managed database (`databaseId`), not an entire connection. It returns HTTP 202 with a backup ID and job ID. It does not run a dump in the API process.\n- `GET /api/projects/:projectId/backups` lists backup metadata (maximum 100 rows per request).\n- `GET /api/projects/:projectId/backups/:backupId` returns one project-scoped backup record.\n- `backup:manage` is required to queue a backup; `backup:read` is required to list or inspect. Project membership is checked server-side. The caller cannot provide a storage path, MongoDB URI, executable, or shell arguments.\n- Backup record and job creation plus the audit event are committed in one PostgreSQL transaction. A composite foreign key binds the backup's project, connection, and managed database IDs, preventing mismatched target references. Legacy connection-scoped queued records are failed during migration 006 rather than executed with unsafe scope. The queue uses a separate `backup_jobs` table with lease fields for a future worker.\n- API responses intentionally omit storage keys and encryption envelope metadata.\n\n## Storage envelope

Each backup object is identified by a project UUID and backup UUID. The storage path is derived from those identifiers; clients never provide filesystem paths.

- A random 256-bit data-encryption key (DEK) is generated for each backup.
- The archive is encrypted with AES-256-GCM.
- Authenticated additional data binds the archive to its project and backup IDs.
- The DEK is wrapped with the configured versioned key-encryption key (KEK), using separate authenticated data that includes the key version.
- PostgreSQL metadata must store the nonce, authentication tag, wrapped DEK, wrapping nonce/tag, key version, plaintext byte count, and SHA-256 digest.
- The file contains a versioned magic header, nonce, and ciphertext. The GCM authentication tag is stored in metadata.
- The object is written to a private temporary file and published with a no-overwrite hard link. Files are mode `0600`; storage directories are mode `0700`.
- Restore preparation decrypts the complete object into a private temporary file, verifies the GCM tag, byte count, and SHA-256 digest, and only then returns the plaintext path. A restore process must never consume unauthenticated plaintext.
- DEKs are zeroed from application buffers in `finally` blocks where practical.

The local filesystem adapter is single-node storage. A multi-node deployment needs a private object-storage adapter with conditional object creation, encrypted transport, access controls, lifecycle policies, and a documented durability model. Do not put the backup root under a public web root or a user-writable directory.

## Implemented dump adapter and worker

The worker claims backup jobs using PostgreSQL `SKIP LOCKED`, renewable leases, bounded retries, and audit events. It loads a credential only while it owns the job lease, uses the managed database's scoped user, and supplies a server-generated `--nsInclude` filter for that database. The adapter runs a configured absolute `mongodump` executable with `shell: false`, streams archive output directly into encrypted storage, enforces a byte limit and deadline, ignores stderr to avoid credential leakage, and deletes the object if the tool exits unsuccessfully.\n\nThe adapter uses the official MongoDB Database Tools:

- `mongodump --archive --gzip` writes one compressed archive to stdout.
- `mongorestore --archive --gzip` restores from an archive stream or file.
- Use the Database Tools `--config` option for the sensitive connection URI. MongoDB documents this option in Database Tools 100.3.0 and later. The config file must be created in a private temporary directory with mode `0600`, then removed after the process exits.
- Invoke the binary with Node.js `spawn`, a fixed executable path configured by the operator, a fixed allowlisted argument list, and `shell: false`. Never concatenate a command string or accept tool arguments from an API request.
- Do not put a credential-bearing URI or password in process arguments. MongoDB warns that URI/password values may be visible through process-list tools and documents `--config` as the safer option.
- Capture bounded stderr, redact connection information, enforce wall-clock and output-size limits, kill the child on cancellation, and treat non-zero exit codes as failure.

Official references:

- [mongodump](https://www.mongodb.com/docs/database-tools/mongodump/)
- [mongorestore](https://www.mongodb.com/docs/database-tools/mongorestore/)
- [MongoDB Database Tools](https://www.mongodb.com/docs/database-tools/)

## Mandatory network isolation gate

The Node.js MongoDB driver can use the application's DNS-pinned lookup callback. The external Database Tools binaries do not use that callback. Therefore, a backup worker must not run `mongodump` against customer-controlled connection strings until its network namespace/container has an enforced egress policy that allows only approved database destinations and blocks loopback, link-local, cloud metadata, multicast, and reserved ranges. DNS validation alone is not enough if the actual process can resolve a different address.

The worker retrieves a managed database credential only through a lease-bound internal service, and must not log the URI. **Current limitation:** the managed database credential is the application's existing database-scoped user, which currently has `readWrite` privileges. Before production use, provision a separate `read`-only backup user and make the worker require that credential; do not fall back to the application's write-capable credential. No public API route may accept a URI, host, binary path, command, or arbitrary restore options.

## Consistency and restore semantics

A logical `mongodump` is not automatically a point-in-time backup for every deployment topology. The adapter must declare its consistency level and support matrix. Replica-set oplog behavior, sharded-cluster restrictions, server version compatibility, and database-tool version compatibility must be tested and documented before offering point-in-time restore claims.

Restore is a destructive operation. The eventual API must require a project-level backup permission, explicit target database confirmation, a verified backup state, and an audited job. The first implementation must not use `--drop` by default. Restore into a new isolated target and verify it before any cutover where the deployment model permits it.

## Remaining release gates

- Backup metadata schema and API authorization.
- Durable scheduling and retry-safe backup/restore jobs.
- Isolated worker with enforceable egress firewall policy (the environment flag is only an operator attestation).\n- Separate read-only backup database user and encrypted credential lifecycle.\n- Real `mongodump` integration tests against the supported MongoDB versions and topologies.
- Database Tools installation/version check and compatibility matrix.
- Encrypted local and object-storage adapters.
- Restore verification and failure compensation.
- Retention and deletion that never remove the last verified backup.
- Backup/restore integration tests against real MongoDB.
- Operational restore drills, retention monitoring, and key-rotation runbook.
