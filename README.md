# Mongo Control Plane

A self-hosted control plane for managing MongoDB projects, deployments, credentials, data, backups, and operational health.

> **Development status:** early development. This repository currently contains specifications and initial project documentation, not a production-ready application. Do not connect production databases until a stable release and its security review are published.

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
3. Database credentials are encrypted at rest and never returned after initial creation unless explicitly rotated.
4. All authorization is enforced by the API, not only by the UI.
5. Provisioning and backup operations run as asynchronous, observable jobs.
6. Remote agents expose a narrow, authenticated operation protocol; they do not execute arbitrary user-supplied shell commands.
7. Destructive operations require explicit authorization, confirmation, and audit records.

## Planned stack

- Web: Next.js, React, TypeScript
- API and workers: Node.js, TypeScript, Express
- Control-plane database: PostgreSQL and Prisma
- MongoDB access: official MongoDB Node.js driver
- Jobs: Redis and BullMQ
- Testing: Vitest, integration tests against real MongoDB instances, and Playwright
- Deployment: Docker Compose initially; production deployment guidance to follow

Exact dependency versions and supported runtime versions will be pinned and documented during implementation. See [Architecture](docs/ARCHITECTURE.md), [Security](docs/SECURITY.md), and [Roadmap](docs/ROADMAP.md).

## Development status

The repository currently contains project specifications and architecture decisions. Runtime modules are not yet implemented. Do not use this repository to manage production databases until a release explicitly marked stable is published and deployment/security documentation is complete.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Security vulnerabilities must be reported privately as described in [SECURITY.md](SECURITY.md).

## License

The project-owned source code is licensed under the MIT License. Third-party software and MongoDB server distributions retain their own licences; see [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).


### MongoDB workspace

The shared-database module provisions isolated database-scoped application users, encrypts credentials, supports audited key rotation and confirmed asynchronous deletion, and exposes a permission-checked workspace API for collections, documents, and indexes. The workspace does not expose administrator credentials or accept arbitrary MongoDB commands.
