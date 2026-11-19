# Development

## Prerequisites

- Node.js 24.x (24.11 or later recommended)
- npm 10 or later
- Git

Node.js 24 is the supported runtime baseline for the current API and MongoDB Node.js driver 7.x dependency. Re-evaluate this baseline when the supported dependency matrix changes.

## Install

From the repository root:

```bash
npm install
```

This creates the npm lockfile for the current dependency graph. Commit the generated `package-lock.json` before treating the dependency graph as reproducible or deploying production builds.

## API

```bash
npm run dev:api
npm run typecheck
npm run build
npm test
```

The API listens on `127.0.0.1:5000` by default. Override `HOST` and `PORT` through environment variables when needed.

## Current endpoints

- `GET /health/live`: process liveness.
- `GET /health/ready`: checks PostgreSQL when configured; Redis and per-target MongoDB readiness are not included.
- `POST /api/auth/login`, `POST /api/auth/logout`, `GET /api/auth/me`: session authentication.
- `GET /api/projects`, `POST /api/projects`, `GET /api/projects/:projectId`: project management.
- `GET|POST /api/projects/:projectId/connections`, `PATCH|DELETE /api/projects/:projectId/connections/:connectionId`, and `POST .../rotate-key`: encrypted connection registry.
- `GET|POST /api/projects/:projectId/databases`: list and enqueue shared database provisioning.
- `POST /api/projects/:projectId/databases/:databaseId/credentials`: explicit Compass-compatible URI reveal for project admins only.
- `POST /api/projects/:projectId/databases/:databaseId/rotate-key`: re-wrap the application credential DEK.
- `DELETE /api/projects/:projectId/databases/:databaseId`: enqueue confirmed asynchronous deletion.
- Collection, document, and index routes are listed in the MongoDB workspace section below.

## Current limitations

- The web portal/UI has not been implemented. The current workspace is an API.
- The workspace supports collection list/create/drop, document insert/update/delete, bounded document paging, and index list/create/drop. Query filters, custom sorting/projection, aggregation, schema sampling, and import/export are not yet exposed.
- The workspace reuses process-local MongoDB client pools keyed by database resource and a one-way credential fingerprint. Pools are capped at 100 clients per API process, use bounded pool/queue/timeouts, and close after 60 seconds idle. This is a per-process cap, not a distributed per-project quota.
- Dedicated MongoDB deployments, Atlas administration, backup scheduling/jobs, restore workflows, retention, metrics, and alerts are not implemented. Backup request/inventory endpoints and durable PostgreSQL job records now exist, and encrypted file storage is tested. The leased backup worker and `mongodump` adapter are implemented but remain disabled until network egress is externally isolated. Restore, retention, scheduling, and a dedicated read-only backup credential are not implemented; see `docs/BACKUPS.md`.
- Production rate limiting, CSRF/origin policy, structured secret-redacting logs, lockfile reproducibility, KMS integration, quotas, and operational key-rotation runbooks remain release gates.
- The API readiness endpoint checks PostgreSQL only; it is not a production readiness guarantee.

Never put production credentials or customer data in local test fixtures.

## PostgreSQL control-plane schema

The initial identity/project schema is in `apps/api/migrations/001_identity_and_projects.sql`.

Apply schema changes with the versioned migration runner:

```bash
npm run migrate --workspace @mongo-control-plane/api
```

The runner records SHA-256 checksums and serializes concurrent migrations with a PostgreSQL advisory transaction lock. Create a new numbered migration instead of editing an already-applied migration.

Use a dedicated application role that does not own the schema or migration objects. Run schema migrations with a separate deployment role. The application role should receive only the DML permissions required by the API; it must not own `audit_events`, disable triggers, or alter schema objects.

The schema stores account identity, hashed session-token material, project membership, encrypted connection/database credential envelopes, provisioning jobs, and append-only audit events. It does not store customer MongoDB documents or plaintext MongoDB credentials. The API uses node-postgres pools and the versioned migration runner. Readiness currently verifies PostgreSQL only; MongoDB connectivity is evaluated per configured operation.

## Authentication bootstrap and local API

The API supports password login, logout, and current-session identity at:

- `POST /api/auth/login`
- `POST /api/auth/logout`
- `GET /api/auth/me`

Passwords are hashed with Node.js scrypt. Session cookies are HttpOnly, SameSite=Lax, and Secure when `NODE_ENV=production`. Only SHA-256 digests of opaque session tokens are stored in PostgreSQL. Sessions expire after seven days and are revoked on logout. Login/session changes are written to the audit table in the same SQL statement as the session mutation.

There is no public registration endpoint. Create the first platform administrator once, using a private shell with environment variables supplied by your secret manager:

```bash
DATABASE_URL='postgresql://...' \
BOOTSTRAP_ADMIN_EMAIL='admin@example.com' \
BOOTSTRAP_ADMIN_PASSWORD='use-a-unique-password-of-at-least-12-characters' \
BOOTSTRAP_ADMIN_DISPLAY_NAME='Platform Administrator' \
npm run bootstrap:admin --workspace @mongo-control-plane/api
```

The bootstrap command takes a PostgreSQL advisory transaction lock and refuses to create another platform administrator if one already exists. Do not put bootstrap credentials in source control, CI variables, shell history, or a persistent service environment. Remove them immediately after successful bootstrap.

Production deployment still requires a distributed login rate limiter, CSRF/origin controls appropriate to the deployment topology, session cleanup/retention, integration tests against a real PostgreSQL instance, and a documented key/credential rotation procedure. The current auth implementation is a development milestone, not a production security certification.

## Project API

Authenticated project endpoints:

- `GET /api/projects` — list projects the current user belongs to; platform administrators can list all projects.
- `POST /api/projects` — create a project and automatically grant the creator the `project_admin` role.
- `GET /api/projects/:projectId` — retrieve a project only when the caller is a member or platform administrator.

Project access is derived from the server-side session and membership tables. A project ID supplied by a client is never treated as proof of access. Project creation, creator membership, and the audit event are committed as one PostgreSQL statement.

The current route tests use a controlled database stub. Run the PostgreSQL integration suite once the Compose/test database stack is available; the stub tests do not prove database isolation under real PostgreSQL execution.

## Connection registry and encryption

The API supports project-scoped connection metadata and encrypted secret registration:

- `GET /api/projects/:projectId/connections` — list safe connection metadata only.
- `POST /api/projects/:projectId/connections` — register a MongoDB URI; the URI is encrypted before persistence.
- `PATCH /api/projects/:projectId/connections/:connectionId` — rename a connection and/or set its status to `configured` or `disabled`.
- `POST /api/projects/:projectId/connections/:connectionId/rotate-key` — re-wrap the per-secret data key using the current keyring version.
- `DELETE /api/projects/:projectId/connections/:connectionId` — remove a registered connection.

Connection creation, updates, key rotation, and deletion require `connection:manage`; listing requires `connection:read`. Trusted server-side credential retrieval requires `connection:use` (project administrators, developers, and read-only members); this permission is internal to the API and does not reveal the URI. Mutations and their audit events are committed in one PostgreSQL transaction. PostgreSQL integration tests exercise encrypted persistence, metadata-only responses, project isolation, read-only denial, key rotation, updates, and deletion. All routes are project-membership scoped. Connection metadata responses never expose URI ciphertext or key material. The explicit, audited `POST .../credentials` endpoint returns the application URI only to project admins with `database:use`; developers and read-only members use the server-side workspace API and never receive the URI. `loadConnectionCredential` in `apps/api/src/connections/credential-service.ts` is an internal server-only service: it checks membership and `connection:use`, refuses disabled targets, decrypts only after authorization, and writes a credential-use audit event. Callers must not log or serialize its returned URI.

Configure `CONNECTION_ENCRYPTION_KEYS` as a JSON object mapping positive integer versions to canonical base64-encoded 32-byte keys, and `CONNECTION_ENCRYPTION_CURRENT_VERSION` to a version present in that object. Generate a local development key with:

```bash
openssl rand -base64 32
```

Keep old key versions available until every stored secret has been re-wrapped. Migration `003_connection_encryption_context.sql` adds an AAD-format version: pre-existing rows retain legacy AAD (version 1), while new rows use project- and connection-bound AAD (version 2). Key rotation preserves each row's AAD version; legacy secrets must be explicitly re-encrypted before they gain context binding. The rotate-key endpoint only re-wraps the data-encryption key; it does not return secret material. Store production keys in a secret manager and restrict access to the API process. Do not commit real key material.

The URI parser checks scheme, host syntax, and TLS options. Provisioning and workspace operations resolve and validate every socket destination, pin vetted DNS results, block loopback/link-local/metadata/multicast/reserved ranges, require explicit operator opt-in for private networks, and apply connection/query timeouts. Host/container egress firewall rules are still required; these controls do not replace network policy. A user-triggered connection-test endpoint is not implemented.

## Local dependency stack

The repository includes a development-only Compose stack for PostgreSQL, MongoDB, and Redis. All published ports bind to loopback; do not expose this Compose file directly to the public internet.

1. Copy `.env.example` to `.env` and replace all three passwords with unique random values.
2. Start the services:

   ```bash
   docker compose up -d
   docker compose ps
   ```

3. Export the control-plane connection string into your shell (URL-encode any special characters in the database password), then run migrations:

   ```bash
   export DATABASE_URL='postgresql://mcp_dev:YOUR_PASSWORD@127.0.0.1:54329/mcp_control_plane'
   npm install
   npm run migrate --workspace @mongo-control-plane/api
   ```

4. Bootstrap the first administrator using the one-time command above.
5. Start the API:

   ```bash
   npm run dev:api
   ```

The migration runner applies numbered SQL files in order, records SHA-256 checksums, serializes concurrent runners with a PostgreSQL advisory transaction lock, and refuses to run an already-applied migration whose contents have changed. Create a new migration instead of editing an applied one.

The API can enqueue shared database provisioning and deletion requests. Run the separate worker with `npm run worker --workspace @mongo-control-plane/api`; the worker requires the same PostgreSQL URL and encryption keyring as the API. It connects to configured MongoDB targets with TLS and DNS-pinned egress validation. Redis remains reserved for future workloads.

Shared database endpoints (all responses use `Cache-Control: no-store`):

- `GET /api/projects/:projectId/databases` — list non-deleted database resources (`database:read`).
- `POST /api/projects/:projectId/databases` — enqueue provisioning with JSON `{ "connectionId": "...", "name": "..." }` (`database:admin`).
- `POST /api/projects/:projectId/databases/:databaseId/credentials` — explicitly reveal a Compass-compatible URI (`database:use`, project-admin only, plus `connection:use`); every reveal is audited.
- `POST /api/projects/:projectId/databases/:databaseId/rotate-key` — re-wrap the encrypted credential DEK without changing the ciphertext (`database:admin`).
- `DELETE /api/projects/:projectId/databases/:databaseId` — enqueue deletion with JSON `{ "confirmDatabaseName": "exact-generated-database-name" }` (`database:admin`). The worker removes the owned user, drops the database, and wipes the encrypted credential envelope. The API returns `202`; poll the list endpoint for the final state.

Only connections with kind `shared` can be used by this provisioning adapter. The configured connection URI must have valid TLS settings. The worker blocks loopback and link-local/metadata addresses; RFC1918/ULA targets require `MONGODB_ALLOW_PRIVATE_NETWORKS=true`. `MONGODB_ALLOW_LOOPBACK=true` is for isolated local development only and is rejected in production. Do not use the example credentials or this development stack as production deployment configuration.

Project membership administration is also available:

- `GET /api/projects/:projectId/members` — list members, roles, and join dates.
- `POST /api/projects/:projectId/members` — add an existing active account with `project_admin`, `developer`, or `read_only`.
- `PATCH /api/projects/:projectId/members/:userId` — change a member's role.
- `DELETE /api/projects/:projectId/members/:userId` — remove a member.

Only a project administrator or platform administrator can change membership. Mutations lock the project row in a transaction, re-check the caller's role, and prevent removing or downgrading the final project administrator. Membership changes and their audit events are committed together. Project and authentication responses set `Cache-Control: no-store`.

Fine-grained permission catalogs and real-world authorization testing for all project operations remain future work; these roles are currently coarse project-level roles.

## Project permission matrix

The permission catalog is centralized in `apps/api/src/auth/permissions.ts`:

| Permission | Project admin | Developer | Read-only |
|---|---:|---:|---:|
| Project read | Yes | Yes | Yes |
| Member list | Yes | Yes | Yes |
| Member management | Yes | No | No |
| Connection metadata read | Yes | Yes | Yes |
| Use connection credential (server-only) | Yes | Yes | Yes |
| Connection management | Yes | No | No |
| Database read | Yes | Yes | Yes |
| Database write | Yes | Yes | No |
| Database administration | Yes | No | No |\n| Use database credentials | Yes | No | No |
| Backup read | Yes | Yes | Yes |
| Backup management | Yes | No | No |
| Audit read | Yes | No | No |

Platform administrators bypass project-level permission checks. New protected modules should call `hasProjectPermission` on a membership role obtained from the database; never accept a role or permission list from the request body.


### MongoDB workspace API

The workspace uses the generated database-scoped application account. It does not expose administrator credentials or accept arbitrary MongoDB commands, filters, aggregation pipelines, or shell input.

- `GET /api/projects/:projectId/databases/:databaseId/collections` — list collections (`database:read`).
- `POST /api/projects/:projectId/databases/:databaseId/collections` — create a collection with JSON `{ "name": "customers" }` (`database:admin`).
- `DELETE /api/projects/:projectId/databases/:databaseId/collections/:collectionName` — drop a collection with JSON `{ "confirmCollectionName": "customers" }` (`database:admin`).
- `GET /api/projects/:projectId/databases/:databaseId/collections/:collectionName/documents?limit=25&skip=0` — bounded document page (`database:read`, maximum 100 documents and 10,000 skip).
- `POST /api/projects/:projectId/databases/:databaseId/collections/:collectionName/documents` — insert a JSON document (`database:write`, no caller-supplied `_id`, maximum 1 MB).
- `PATCH /api/projects/:projectId/databases/:databaseId/collections/:collectionName/documents/:documentId` — update fields with JSON `{ "set": { "status": "active" } }` (`database:write`).
- `DELETE /api/projects/:projectId/databases/:databaseId/collections/:collectionName/documents/:documentId` — delete one ObjectId document (`database:write`).
- `GET /api/projects/:projectId/databases/:databaseId/collections/:collectionName/indexes` — list indexes (`database:read`).
- `POST /api/projects/:projectId/databases/:databaseId/collections/:collectionName/indexes` — create a bounded index, JSON `{ "keys": { "email": 1 }, "unique": true }` (`database:admin`).
- `DELETE /api/projects/:projectId/databases/:databaseId/collections/:collectionName/indexes/:indexName` — drop a non-`_id_` index (`database:admin`).

The workspace uses TLS, bounded MongoDB timeouts, DNS-pinned egress checks and PostgreSQL row locks while an operation runs. The locks prevent database deletion, credential rotation, or connection removal from racing active workspace operations. Project admins may reveal the application URI; developers and read-only members use the permission-checked workspace API without receiving the URI. The API reuses a bounded MongoDB client pool per database resource and credential version. Credential changes use a distinct pool; old pools drain active operations and are closed when idle. Pools are closed during graceful API shutdown.
