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
- [x] Internal server-side credential loader with project membership checks, `connection:use` permission, disabled-target rejection, and audit events (CI verification pending)
- [x] Context-bound AES-GCM AAD for new secrets, with versioned compatibility for existing records
- [x] Provisioning-worker TLS enforcement and DNS-pinned egress validation (loopback, link-local, metadata, multicast, reserved ranges blocked; private networks require operator opt-in)
- [ ] User-triggered connection testing and external egress-firewall deployment verification
- [ ] Per-project connection pooling
- [ ] Production KMS/secret-manager adapter and operational key-rotation runbook

## Phase 3 — Shared MongoDB provisioning
- [x] Shared MongoDB user provisioning with project/resource ownership markers and safe retry reconciliation
- [x] Database-scoped `readWrite` role and SCRAM-SHA-256 enforcement
- [x] Ownership-checked user removal and database deletion
- [x] PostgreSQL-backed provisioning outbox with `SKIP LOCKED`, expiring leases, bounded retries, and idempotent worker operations
- [x] Encrypted application credentials persisted before external provisioning; credentials wiped after successful deletion
- [x] Database create/list, explicit connection-URI reveal, and credential key-rotation endpoints
- [x] Confirmed asynchronous deletion with tombstones and safe connection cleanup
- [x] Real MongoDB 8 integration coverage for scoped access, retries, key rotation, deletion, and credential erasure (CI verification pending)
- [ ] Provider interface and capability model
- [ ] Per-project quotas, provisioning rate limits, and operational alerting

## Phase 4 — MongoDB workspace
- [ ] Database and collection explorer
- [ ] BSON-aware document CRUD
- [ ] Query filters, sorting, projection, pagination
- [ ] Aggregation pipeline editor
- [ ] Index and schema management
- [ ] Import/export with limits and validation

## Phase 5 — Backups and observability
- [ ] Backup scheduling and retention
- [ ] Encrypted backup storage
- [ ] Restore and integrity verification
- [ ] Health, metrics, logs, and alert hooks

## Phase 6 — Dedicated deployments and Atlas
- [ ] Restricted remote agent
- [ ] Dedicated Docker deployment adapter
- [ ] Resource limits, storage lifecycle, upgrades
- [ ] Atlas administrative integration
- [ ] Replica-set and sharding diagnostics

## Release gates

A stable release requires automated tests, security review, documented supported versions, migration/rollback guidance, backup-and-restore evidence, and an operational deployment guide.
