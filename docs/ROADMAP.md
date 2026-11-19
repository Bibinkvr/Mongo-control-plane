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
- [x] Password login, logout, hashed opaque sessions, and one-time admin bootstrap (CI verified; PostgreSQL integration pending)
- [ ] Production rate limiting, CSRF/origin policy, session cleanup, and security review
- [x] Initial PostgreSQL schema for users, sessions, projects, memberships, and audit events
- [x] Checksum-verified, advisory-lock-protected migration runner
- [ ] Full permission catalog and fine-grained permission enforcement
- [x] Authenticated project list, creation, and detail endpoints with membership-scoped SQL (real-DB verification pending)
- [x] Project membership listing, add, role change, removal, and final-admin protection (PostgreSQL CI verified)
- [ ] Project environments
- [x] Server-side tenant isolation through membership-scoped project queries
- [x] Append-only audit-event table with mutation guard trigger
- [x] PostgreSQL integration and cross-project authorization tests (CI verified)
- [x] Auth route and session-helper test coverage (CI verified)

## Phase 2 — Connection and secret management
- [ ] Connection target registry
- [ ] Envelope encryption and key rotation
- [ ] Secret reveal and rotation workflow
- [ ] Safe connection testing and SSRF protections
- [ ] Per-project connection pooling

## Phase 3 — Shared MongoDB provisioning
- [ ] Provider interface and capability model
- [ ] Database namespace creation
- [ ] Least-privilege database user creation
- [ ] Idempotent jobs and cleanup compensation
- [ ] Real MongoDB integration tests

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
