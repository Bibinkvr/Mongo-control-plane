# Roadmap

Status labels: **Planned**, **In progress**, **Implemented**, **Verified**. A feature is not production-ready merely because its UI exists.

## Phase 0 — Repository foundation
- [x] Repository identity and MIT licence
- [x] Architecture and trust-boundary specification
- [x] Security requirements and threat checklist
- [x] Initial npm workspace and strict TypeScript configuration
- [x] API process bootstrap, environment validation, and health endpoints
- [x] API unit tests and GitHub Actions CI workflow definition
- [ ] Generate and commit npm lockfile
- [x] Execute GitHub Actions CI successfully (typecheck, build, and tests)
- [x] Local development Compose stack (PostgreSQL, MongoDB, Redis; loopback-only ports)
- [ ] Structured, secret-redacting application logging

## Phase 1 — Identity and project control
- [x] Password login, logout, hashed opaque sessions, and one-time admin bootstrap (CI verified; login/bootstrap PostgreSQL integration pending)
- [ ] Production rate limiting, CSRF/origin policy, session cleanup, and security review
- [x] Initial PostgreSQL schema for users, sessions, projects, memberships, and audit events
- [x] Checksum-verified, advisory-lock-protected migration runner
- [x] Central project permission catalog and role matrix (CI verified)
- [x] Authenticated project list, creation, and detail endpoints with membership-scoped SQL (unit-tested; project-create API PostgreSQL test pending)
- [x] Project membership listing, add, role change, removal, and final-admin protection (PostgreSQL CI verified)
- [ ] Project environments
- [x] Server-side tenant isolation through membership-scoped project queries
- [x] Append-only audit-event table with mutation guard trigger
- [x] PostgreSQL integration and cross-project authorization tests (CI verified)
- [x] Auth route and session-helper test coverage (CI verified)

## Phase 2 — Connection and secret management
- [x] Encrypted connection target registry API (metadata-only responses; project permission checks; audit events)
- [x] AES-256-GCM envelope encryption with per-secret DEKs and versioned KEKs
- [x] DEK re-wrapping key rotation without decrypting MongoDB URI plaintext
- [x] Rename and enable/disable connection targets with audit events
- [x] PostgreSQL integration coverage for encrypted storage, key rotation, CRUD, credential authorization, and tenant permissions (CI verified)
- [x] Internal server-side credential loader with project membership checks, `connection:use` permission, disabled-target rejection, and audit events (CI verified)
- [x] Context-bound AES-GCM AAD for new secrets, with versioned compatibility for existing records
- [x] Provisioning-worker TLS enforcement and DNS-pinned egress validation (loopback, link-local, metadata, multicast, reserved ranges blocked; private networks require operator opt-in)
- [ ] User-triggered connection testing and external egress-firewall deployment verification
- [x] Bounded process-local MongoDB client pools with credential-change retirement and graceful shutdown (CI verified)
- [ ] Production KMS/secret-manager adapter and operational key-rotation runbook

## Phase 3 — Shared MongoDB provisioning
- [x] Shared MongoDB user provisioning with project/resource ownership markers and safe retry reconciliation
- [x] Database-scoped `readWrite` role and SCRAM-SHA-256 enforcement
- [x] Ownership-checked user removal and database deletion
- [x] PostgreSQL-backed provisioning outbox with `SKIP LOCKED`, expiring leases, bounded retries, and idempotent worker operations
- [x] Encrypted application credentials persisted before external provisioning; credentials wiped after successful deletion
- [x] Database create/list, explicit connection-URI reveal, and credential key-rotation endpoints
- [x] Confirmed asynchronous deletion with tombstones and safe connection cleanup
- [x] Real MongoDB 8 integration coverage for scoped access, retries, key rotation, deletion, and credential erasure (CI verified)
- [ ] Provider interface and capability model
- [ ] Per-project quotas, provisioning rate limits, and operational alerting

## Phase 4 — MongoDB workspace
- [x] Server-side collection list/create/confirmed-drop API
- [x] Document insert/update/delete API with ObjectId addressing, recursive field validation, 1 MB document cap, and bounded page reads
- [x] Index list/create/drop API with protected `_id_` index and field-name validation
- [x] Project RBAC enforced inside the server-side MongoDB operation boundary; only project admins can reveal the application URI
- [x] TLS, DNS-pinned egress, PostgreSQL row locks, request timeouts, and audit events for workspace operations
- [ ] Web workspace UI and BSON-aware editor
- [ ] Safe query builder with allowlisted filters, sorting, projection, and cursor pagination
- [ ] Aggregation pipeline editor with stage/operator allowlists and resource limits
- [ ] Schema sampling/inspection
- [ ] Import/export with limits, validation, and streaming

## Phase 5 — Backups and observability
- [ ] Backup scheduling and retention
- [x] Encrypted streaming file-storage primitive with per-backup DEKs, context-bound AES-GCM, atomic publication, and authenticated restore staging (CI verified)
- [x] Backup metadata schema, transactional request queue, inventory API, project RBAC, and audit events (CI verified)
- [x] Backup targets bound to a ready managed database with composite tenant/connection/database foreign-key enforcement (CI verified)
- [x] Leased backup worker and fixed-argument MongoDB Database Tools adapter (CI fake-executable tests; production egress isolation and real-tool verification remain gates)\n- [ ] Enforced backup-worker network egress allowlist\n- [ ] Dedicated read-only backup credentials
- [ ] Restore jobs, integrity verification, and retention-safe deletion
- [ ] Object storage adapter and multi-node durability
- [ ] Health, metrics, logs, and alert hooks

## Phase 6 — Dedicated deployments and Atlas
- [ ] Restricted remote agent
- [ ] Dedicated Docker deployment adapter
- [ ] Resource limits, storage lifecycle, upgrades
- [ ] Atlas administrative integration
- [ ] Replica-set and sharding diagnostics

## Release gates

A stable release requires automated tests, security review, documented supported versions, migration/rollback guidance, backup-and-restore evidence, and an operational deployment guide.
