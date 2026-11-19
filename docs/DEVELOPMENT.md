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
