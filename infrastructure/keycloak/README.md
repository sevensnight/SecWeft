# Development OIDC provider

The `identity` Compose profile provides a fixed-version Keycloak instance for
local OIDC integration and acceptance testing. It is disabled by default and
is not the production identity architecture. Production must use the
organization's managed OIDC provider and secret manager.

The imported `vulnlab-development` realm enables Authorization Code Flow with
PKCE (`S256`) for the web console and defines development role names aligned
with the RBAC model. It intentionally contains no users and no passwords.
Create development users through the Keycloak administration console after
startup.

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
