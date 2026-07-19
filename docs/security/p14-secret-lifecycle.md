# P14 Secret Lifecycle

P14 records secret lifecycle posture without exporting secret material.

Tracked credential classes:

- API keys
- Keycloak client secrets
- MinIO credentials
- NATS credentials
- database credentials
- signing identities

Secrets must not enter:

- Git history
- logs
- acceptance artifacts
- compliance package plaintext
- frontend state
- exception traces

Delivery packages are scanned for forbidden sensitive markers and use placeholders only.
