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
- `GET /health/ready`: process readiness only. It does not yet verify PostgreSQL, Redis, or MongoDB dependencies.

## Current limitations

- No authentication or authorization is implemented yet.
- No PostgreSQL or Redis connection is implemented yet.
- No MongoDB connection or provisioning is implemented yet.
- No secrets are stored or managed yet.
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
