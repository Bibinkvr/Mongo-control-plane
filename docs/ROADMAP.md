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
- [ ] Execute CI successfully and resolve any failures
- [ ] Local development Compose stack
- [ ] Structured, secret-redacting application logging

## Phase 1 — Identity and project control
- [ ] Authentication and secure session lifecycle
- [x] Initial PostgreSQL schema for users, sessions, projects, memberships, and audit events\n- [ ] Users, roles, permissions
- [ ] Projects and environments
- [ ] Server-side tenant isolation
- [x] Append-only audit-event table with mutation guard trigger
- [ ] Integration and authorization tests

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
