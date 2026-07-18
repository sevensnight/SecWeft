# P9-R runtime acceptance matrix

This matrix separates deterministic local baseline coverage from real infrastructure runtime coverage.

## Deterministic baseline

| Check | Command | Current status |
|---|---|---|
| P9 business loop and negative tests | `solve_p9_baseline.py --full` | passed |
| P9/P9-R targeted regression | `pytest tests/test_p9_validation_executions.py tests/test_p9r_validation_queue.py tests/contract/test_postgres_migrations.py -q` | 18 passed |
| Static lint | `ruff check .` | passed |
| Static types | `mypy apps/control-plane/src` | passed |
| Compose runtime config parse | `docker compose --profile runtime config --quiet` | passed |

## Real runtime acceptance

| Requirement | Runner/check | Current status |
|---|---|---|
| PostgreSQL migrations 0001-0008 | temporary `postgres:17.4-alpine` in `solve_p9_runtime.py` | passed |
| PostgreSQL P9-R outbox schema | insert execution/queue row, lease CAS, publish metadata, duplicate message rejection | passed |
| Full FastAPI compatibility control-plane PostgreSQL repository | replace existing SQLite `Database` adapter for API business flow | not implemented |
| NATS JetStream stream publish | `solve_p9_runtime.py` outbox dispatch | passed |
| Durable worker consumption | `solve_p9_runtime.py` worker consume | passed |
| Duplicate message idempotency | duplicate JetStream publish | passed |
| Docker sandbox creates fixed HTTP template container | `DockerSandboxBackend` in `solve_p9_runtime.py` | passed |
| Docker sandbox cleanup | timeout probe container inventory check | passed |
| MinIO upload/download SHA-256 | `MinioEvidenceStore` in `solve_p9_runtime.py` | passed |
| Worker crash redelivery | restart worker after delivery before completion | not executed |
| Service restart recovery | restart dispatcher/worker/API | not executed |
| Internet egress blocked by runtime behavior | sandbox outbound connection test on internal Docker network | passed |
| Authorized lab network allowed | sandbox reaches allowed target container on internal Docker network | passed |
| Timeout termination | fixed long-running runtime probe | passed |
| Memory limit kill | fixed memory-pressure runtime probe | passed |
| Cancel execution | cancel API while queued/running | baseline API covered; runtime race not executed |
| Approval revoked blocks execution | worker re-check path | deterministic covered; runtime JetStream path pending |
| Cross-tenant evidence isolation | API/evidence lookup and tenant-scoped MinIO object key | deterministic/API covered; object key checked at runtime |
| Trace chain complete | API/outbox/NATS/worker/sandbox/evidence fields | fields present; distributed OTEL backend trace export pending |

## Current environment note

Windows Docker Desktop returned `valid: true` for the current host-side runtime runner with a pinned MinIO image tag and temporary PostgreSQL/NATS/MinIO/lab-network containers.

Linux CI or a Linux host should be used as the authority for network isolation, resource kill, and container cleanup tests.
