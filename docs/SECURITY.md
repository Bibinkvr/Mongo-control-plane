# Security model

This document describes required controls. A control is not considered implemented until code and tests demonstrate it.

## Mandatory controls

- Use secure, HttpOnly, SameSite cookies for browser sessions; protect state-changing requests against CSRF.
- Hash passwords with a modern password-hashing algorithm and appropriate parameters.
- Enforce RBAC and project-level authorization on every API operation.
- Encrypt database credentials using envelope encryption. Bind authenticated encryption to the owning project and connection IDs. Keep the master key outside PostgreSQL and outside source control.
- Decrypt credentials only inside trusted server-side services after checking a dedicated permission; never serialize credentials into HTTP responses or log them.
- Preserve legacy encryption-format compatibility until existing secrets have been re-encrypted with context-bound AAD.
- Redact passwords, URI credentials, access tokens, and sensitive payloads from logs, traces, and errors.
- Restrict outbound connections to configured database targets. The provisioning worker resolves and validates every socket destination, pins vetted DNS results for each connection, and blocks loopback, link-local, metadata, multicast, and reserved ranges. RFC1918/ULA destinations require the explicit operator setting `MONGODB_ALLOW_PRIVATE_NETWORKS=true`. Loopback is disabled by default and the API rejects `MONGODB_ALLOW_LOOPBACK=true` in production. Deployments must also apply host/container egress firewall rules; application checks do not replace network policy.
- Apply strict connection, query, execution-time, response-size, and concurrency limits.
- Never accept arbitrary shell commands, Docker arguments, filesystem paths, or provider URLs from untrusted clients.
- Use least-privilege MongoDB users. Keep deployment-administrator credentials separate from application credentials. Application users receive only database-scoped `readWrite` and SCRAM-SHA-256; credential reveal requires `database:use`, is audited, and returns `Cache-Control: no-store` responses. Confirm database names before asynchronous deletion; erase credential ciphertext only after MongoDB user/database deletion succeeds.
- Require explicit confirmation and appropriate permission for destructive operations.
- Write append-only audit events for authentication, authorization failures, secret reveal/rotation, provisioning, data mutations, backup, restore, and administrative actions.
- Secure backups with encryption, access controls, retention, integrity verification, and restore tests.

## Threats to test

- Cross-project IDOR and tenant data leakage.
- SSRF through user-controlled MongoDB connection strings or hostnames.
- DNS rebinding and redirects to forbidden network ranges.
- Credential disclosure through logs, exceptions, API responses, and browser storage.
- NoSQL injection and unsafe operator handling.
- Session fixation, CSRF, brute force, and privilege escalation.
- Replay or impersonation of remote-agent requests.
- Path traversal and unsafe archive extraction during restore.
- Resource exhaustion from unbounded queries, exports, backups, or connection creation.

## Operational requirements

- TLS for all network boundaries outside a trusted local development environment.
- Regular dependency and container image scanning.
- Supported MongoDB server/driver compatibility matrix.
- Documented key rotation and disaster recovery.
- Security contact and coordinated vulnerability disclosure process.

## Reporting

Do not publish exploitable vulnerability details in public issues. Use the repository owner's GitHub security reporting feature if enabled, or contact the maintainer privately through their verified GitHub profile.
