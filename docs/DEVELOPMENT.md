# Development

## Prerequisites

- Node.js 24.x (24.11 or later recommended)
- npm 10 or later
- Git

Node.js 24 is selected because the MongoDB Node.js driver 7.x compatibility table explicitly lists Node 24, and the Prisma 7 system requirements support Node 24. Re-evaluate this baseline when the supported dependency matrix changes.

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
- `GET /health/ready`: verifies PostgreSQL when the API pool is configured; Redis and MongoDB readiness are not yet included.
- `GET /api/projects/:projectId/databases`: list database resources (requires `database:read`).
- `POST /api/projects/:projectId/databases`: enqueue shared MongoDB database/user provisioning (requires `database:admin`); credentials are never returned in the response.

## Current limitations

- Shared database provisioning is implemented as a PostgreSQL-backed outbox with encrypted application credentials and a separate worker. It is not yet a complete MongoDB workspace or dedicated-deployment manager.
- Connection metadata endpoints never return plaintext URIs or encryption material.
- The current encryption keyring is environment-injected; production KMS integration and an operational rotation runbook remain outstanding.
- Connection-route PostgreSQL integration tests are implemented and run in CI when `TEST_DATABASE_URL` is configured; verify the latest workflow before treating them as passed.
- The provisioning worker enforces TLS, validates every socket DNS result, and pins vetted addresses to block DNS rebinding and metadata/loopback access. RFC1918/ULA destinations require `MONGODB_ALLOW_PRIVATE_NETWORKS=true`; link-local and metadata destinations remain blocked. Loopback access is disabled by default and `MONGODB_ALLOW_LOOPBACK=true` is rejected in production; enable it only for isolated local development.
- The current health endpoints are not a production readiness guarantee.

Never put production credentials or customer data in local test fixtures.

## PostgreSQL control-plane schema

The initial identity/project schema is in `apps/api/migrations/001_identity_and_projects.sql`.

Apply it to a dedicated PostgreSQL database using a migration runner or, for local development only:

```bash
psql "$DATABASE_URL" -v ON_ERROR_STOP=1 -f apps/api/migrations/001_identity_and_projects.sql
```

Use a dedicated application role that does not own the schema or migration objects. Run schema migrations with a separate deployment role. The application role should receive only the DML permissions required by the API; it must not own `audit_events`, disable triggers, or alter schema objects.

The schema stores account identity, hashed session-token material, project membership, and append-only audit events. It does not store customer MongoDB documents or MongoDB credentials. Do not use the SQL file as an automatic production migration mechanism; a versioned migration runner and migration-state table are still required before production deployment.

The API's PostgreSQL pool helper uses the node-postgres driver. Pool lifecycle wiring, dependency-aware readiness, migration execution, and integration tests are the next implementation steps.

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

Connection creation, updates, key rotation, and deletion require `connection:manage`; listing requires `connection:read`. Trusted server-side credential retrieval requires `connection:use` (project administrators and developers; not read-only members). Mutations and their audit events are committed in one PostgreSQL transaction. PostgreSQL integration tests exercise encrypted persistence, metadata-only responses, project isolation, read-only denial, key rotation, updates, and deletion. All routes are project-membership scoped. The browser never receives a plaintext URI, ciphertext, nonce, authentication tag, wrapped key, or master key. `loadConnectionCredential` in `apps/api/src/connections/credential-service.ts` is an internal server-only service: it checks membership and `connection:use`, refuses disabled targets, decrypts only after authorization, and writes a credential-use audit event. Callers must not log or serialize its returned URI.

Configure `CONNECTION_ENCRYPTION_KEYS` as a JSON object mapping positive integer versions to canonical base64-encoded 32-byte keys, and `CONNECTION_ENCRYPTION_CURRENT_VERSION` to a version present in that object. Generate a local development key with:

```bash
openssl rand -base64 32
```

Keep old key versions available until every stored secret has been re-wrapped. Migration `003_connection_encryption_context.sql` adds an AAD-format version: pre-existing rows retain legacy AAD (version 1), while new rows use project- and connection-bound AAD (version 2). Key rotation preserves each row's AAD version; legacy secrets must be explicitly re-encrypted before they gain context binding. The rotate-key endpoint only re-wraps the data-encryption key; it does not return secret material. Store production keys in a secret manager and restrict access to the API process. Do not commit real key material.

The URI parser checks the MongoDB scheme and basic host syntax only. It does not make a target safe to connect to. No endpoint currently opens a network connection to a supplied host; implement DNS resolution/pinning, forbidden-address checks, egress policy, timeouts, and resource limits before adding connection testing.

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
- `POST /api/projects/:projectId/databases/:databaseId/credentials` — explicitly reveal a Compass-compatible URI (`database:use` and `connection:use`); every reveal is audited.
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
| Use connection credential (server-only) | Yes | Yes | No |
| Connection management | Yes | No | No |
| Database read | Yes | Yes | Yes |
| Database write | Yes | Yes | No |
| Database administration | Yes | No | No |\n| Use database credentials | Yes | Yes | No |
| Backup read | Yes | Yes | Yes |
| Backup management | Yes | No | No |
| Audit read | Yes | No | No |

Platform administrators bypass project-level permission checks. New protected modules should call `hasProjectPermission` on a membership role obtained from the database; never accept a role or permission list from the request body.
