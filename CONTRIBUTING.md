# Contributing

Thanks for considering a contribution.

## Before opening a pull request

1. Open or locate an issue describing the problem or proposed change.
2. Keep changes focused and include tests for changed behavior.
3. Never commit credentials, connection strings, production data, private keys, or real customer documents.
4. Do not weaken authorization, tenant isolation, encryption, audit logging, or safe defaults to make tests pass.
5. Update documentation and migration notes when behavior or configuration changes.

The executable workspace and exact commands will be added during the foundation implementation phase. Until then, treat architecture and security documents as design specifications, not evidence of implemented controls.

## Pull request checklist

- [ ] The change has a clear purpose and compatibility impact is documented.
- [ ] Tests cover success, validation failure, authorization failure, and relevant edge cases.
- [ ] No secrets or sensitive sample data are included.
- [ ] Documentation is updated.
- [ ] Security implications have been considered.
