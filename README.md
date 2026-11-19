# Mongo Control Plane

A self-hosted control plane for managing MongoDB projects, deployments, credentials, data, backups, and operational health.

> **Development status:** early development. The TypeScript API now includes authentication/projects, encrypted connection management, shared MongoDB provisioning/deletion, and a permission-checked workspace API. The web portal, advanced query tools, backups, dedicated deployments, Atlas integration, and several production security/operations gates remain incomplete. Do not connect production databases until a stable release and security review are published.

## Goals

- Manage multiple MongoDB deployments and project environments from one portal.
- Provision project-scoped databases and least-privilege database users on supported deployments.
- Connect existing MongoDB deployments, including MongoDB Atlas.
- Provide a BSON-aware workspace for documents, queries, indexes, and aggregation.
- Automate backups and verified restore workflows.
- Enforce project isolation, auditable administration, and secure secret handling.

## Architecture principles

1. The control plane is separate from customer MongoDB data.
2. PostgreSQL stores platform metadata; MongoDB stores application data.
3. Administrator and application credentials are encrypted at rest; an explicit, audited URI reveal is available only to project admins.
4. All authorization is enforced by the API, not only by the UI.
5. Provisioning and backup operations run as asynchronous, observable jobs.
6. Remote agents expose a narrow, authenticated operation protocol; they do not execute arbitrary user-supplied shell commands.
7. Destructive operations require explicit authorization, confirmation, and audit records.

## Current stack

- API and worker: Node.js 24, TypeScript, Express 5
- Control-plane database: PostgreSQL using node-postgres and versioned SQL migrations
- MongoDB access: official MongoDB Node.js driver 7.x
- Encryption: AES-256-GCM envelope encryption with versioned keys
- Local dependencies: PostgreSQL 18, MongoDB 8.0, Redis 8 via Docker Compose
- Tests: Vitest, PostgreSQL integration tests, and MongoDB 8 integration tests
- Web portal: planned; not yet implemented
- Jobs: PostgreSQL-backed outbox/worker; Redis/BullMQ not yet wired

See [Architecture](docs/ARCHITECTURE.md), [Security](docs/SECURITY.md), [Development](docs/DEVELOPMENT.md), and [Roadmap](docs/ROADMAP.md).

## Implemented API modules

- Authentication, sessions, project membership, RBAC, and append-only audit events.
- Encrypted connection registry, server-side credential access, and key rotation.
- Shared MongoDB database/user provisioning, retryable worker jobs, confirmed deletion, and credential erasure.
- Workspace API for collections, document CRUD, and index management with role checks, bounded requests, TLS, and DNS-pinned egress.

The API is not yet a complete MongoDB Compass replacement. There is no web UI, advanced query builder, aggregation editor, schema inspector, import/export, backups, dedicated deployment manager, or Atlas administration yet. Production use is blocked on the release gates in [Roadmap](docs/ROADMAP.md).

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Security vulnerabilities must be reported privately as described in [SECURITY.md](SECURITY.md).

## License

The project-owned source code is licensed under the MIT License. Third-party software and MongoDB server distributions retain their own licences; see [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).


### MongoDB workspace

The shared-database module provisions isolated database-scoped application users, encrypts credentials, supports audited key rotation and confirmed asynchronous deletion, and exposes a permission-checked workspace API for collections, documents, and indexes. The workspace does not expose administrator credentials or accept arbitrary MongoDB commands.
