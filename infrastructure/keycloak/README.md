# Development OIDC provider

The `identity` Compose profile provides a fixed-version Keycloak instance for
local OIDC integration and acceptance testing. It is disabled by default and
is not the production identity architecture. Production must use the
organization's managed OIDC provider and secret manager.

The imported `vulnlab-development` realm enables Authorization Code Flow with
PKCE (`S256`) for the web console and a bearer-only control-plane audience. It
defines the eight P1 role names, a managed UUID `tenant_id` profile attribute
that only administrators can edit, five-minute access tokens, refresh-token
rotation, brute-force protection, and identity/admin events. It intentionally
contains no users, client secrets, or business passwords.

Set a unique `PLATFORM_KEYCLOAK_ADMIN_PASSWORD` in `.env.platform`, then start:

```powershell
./infrastructure/scripts/start.ps1 -Identity
```

```sh
infrastructure/scripts/start.sh infrastructure/docker-compose/.env.platform --identity
```

The administration console and realm endpoints bind to
`http://127.0.0.1:8081` by default. The container entry point rejects generated
placeholders and passwords shorter than 24 characters. Realm state is held in
the `keycloak-data` development volume; the platform backup contract excludes
that disposable identity fixture.

Provision the same issuer/subject/tenant binding in PostgreSQL with the protected
`tools/p1/bootstrap_tenant.py` command before the first login. Do not use a
Keycloak realm role as the application authorization source; the control plane
always resolves current database assignments so revocation affects the next
request.

The end-to-end acceptance script creates and deletes a temporary user, drives a
real browser through Code + PKCE, exchanges the code, and verifies the access
token with the realm JWKS:

```powershell
$env:P1_KEYCLOAK_URL = 'http://127.0.0.1:8081'
$env:P1_KEYCLOAK_ADMIN_USER = '<development-admin>'
$env:P1_KEYCLOAK_ADMIN_PASSWORD = '<development-password>'
node tools/p1/validate_keycloak_oidc.mjs
```
