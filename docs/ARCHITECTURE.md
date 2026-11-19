# Architecture

## Product boundary

Mongo Control Plane is a self-hosted management application. It is not a MongoDB server implementation and does not replace MongoDB Atlas or MongoDB Community Server.

## Logical components

- **Web application:** presentation layer; no direct database credentials or privileged MongoDB access.
- **API:** authentication, authorization, validation, project isolation, connection brokering, and audit-event creation.
- **Control-plane PostgreSQL:** platform users, projects, environments, connection metadata, encrypted secret references, jobs, policies, and audit metadata.
- **Secret service:** envelope encryption for credentials; encryption keys are supplied outside the database through deployment secrets or a KMS integration.
- **Worker:** asynchronous provisioning, backup, restore, and maintenance jobs.
- **MongoDB connection manager:** bounded, pooled connections to configured MongoDB targets; strict timeouts and operation limits.
- **Provisioning adapters:** explicit provider interfaces for shared MongoDB deployments, dedicated deployments, and Atlas.
- **Remote agent (later phase):** outbound-authenticated agent with a narrow allowlisted API for operations on a managed host.

## Trust boundaries

1. Browser to API: TLS, secure session cookies, CSRF protection, input validation, and rate limits.
2. API to PostgreSQL: least-privilege database role and parameterized queries.
3. API/worker to MongoDB: per-project database credentials; no routine use of deployment administrator credentials.
4. Control plane to remote agent: mutually authenticated transport, short-lived scoped credentials, replay protection, and operation allowlists.
5. Backup storage: private bucket/container, encryption, access controls, retention policies, integrity checks, and restore verification.

## Multi-tenancy

Every project-owned record is scoped by project ID. API queries derive accessible project IDs from the authenticated principal and enforce scope server-side. Client-supplied project IDs are identifiers, not authorization.

Shared-server provisioning creates a database namespace and a dedicated MongoDB user with the minimum required roles for that database. This is logical isolation, not a guarantee of dedicated CPU, memory, storage, or failure domains.

Dedicated provisioning creates a separately managed MongoDB deployment and persistent storage. It must not expose Docker socket access to the public API.

## Data flow

1. An administrator creates a project and environment.
2. An authorized user selects a configured provider and target.
3. The API validates the request and records a provisioning job.
4. A worker performs idempotent provider operations and records state transitions.
5. Credentials are generated, stored using envelope encryption, and shown only through a controlled one-time reveal or rotation flow.
6. The API performs a bounded connectivity test and records the outcome.
7. The UI displays status and a connection URI assembled from the secret only for an authorized reveal operation.

## Reliability

- Provisioning and backup jobs must be idempotent and retry-safe.
- Job state transitions must be persisted.
- Retries use bounded exponential backoff with jitter.
- Long-running operations have deadlines and cancellation semantics.
- Connection pools, query execution time, result sizes, and concurrency are bounded.
- Health endpoints distinguish liveness from readiness.
- Database migrations are versioned and reversible where practical.

## Initial implementation order

Start with contracts, configuration validation, authentication, authorization, and project isolation before adding MongoDB mutations or remote provisioning.
