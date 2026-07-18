# PostgreSQL Repository Adapters

P9-H introduces an explicit `ControlPlaneRepository` protocol for the compatibility control-plane business services. Services use the protocol surface (`initialize`, `connect`, `transaction`, `fetch_one`, `fetch_all`, `execute`) and deployment chooses the adapter.

## Modes

| Mode | Adapter | Purpose | Production allowed |
|---|---|---|---|
| SQLite deterministic development mode | `SQLiteControlPlaneRepository` | Fast local baseline and compatibility regression | No |
| PostgreSQL production mode | `PostgresControlPlaneRepository` | Production/integration persistence | Yes |

`VULNLAB_REPOSITORY_BACKEND=postgres` requires `DATABASE_URL`. `VULNLAB_ENV=production` rejects SQLite and fails startup instead of falling back.

## Repository scope

The protocol covers:

- Tenant / User / RBAC
- Model Provider / Quota / Cost
- Task / Stage / Agent / Skill
- Knowledge / Context
- Policy / Approval
- Asset / Scope
- Validation Plan
- Validation Execution
- Execution Event
- Evidence Metadata
- Review
- Audit
- Report metadata paths that use existing task/evidence/audit tables

P9-H does not add validation templates, pages, or P10 behavior.

## PostgreSQL compatibility strategy

The adapter initializes an isolated PostgreSQL schema, default `compat`, using the existing compatibility control-plane table contract. Runtime SQL is translated at the repository boundary:

- SQLite `?` placeholders become PostgreSQL `%s`.
- `INSERT OR IGNORE` becomes `ON CONFLICT DO NOTHING`.
- SQLite autoincrement event/audit IDs become PostgreSQL `BIGSERIAL`.
- Connections set UTC timezone and an explicit `search_path`.

Migration `0009_p9h_repository_hardening` records the repository adapter contract in PostgreSQL and creates the adapter metadata anchor.
