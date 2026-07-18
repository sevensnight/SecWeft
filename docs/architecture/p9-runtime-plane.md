# P9-R controlled execution runtime plane

P9-R closes the gap between the P9 deterministic business loop and the real controlled execution runtime. It keeps the existing P0-P9 architecture and adds infrastructure adapters behind explicit interfaces. Business code depends on interfaces, not concrete clients.

## Runtime interfaces

| Interface | Development/test implementation | Runtime implementation | Production fallback rule |
|---|---|---|---|
| `ValidationQueue` | `SQLiteValidationQueue` | `NatsJetStreamValidationQueue` | production must use NATS |
| `SandboxBackend` | `InProcessSandboxBackend` | `DockerSandboxBackend` | production must use Docker |
| `EvidenceStore` | `FilesystemEvidenceStore` | `MinioEvidenceStore` | production must use MinIO |

SQLite, in-process sandboxing, and filesystem evidence are deterministic local adapters only. They are rejected when `VULNLAB_ENV=production`.

## End-to-end runtime flow

```text
POST /api/v1/validation-plans/{plan_id}/executions
-> validation_executions row created
-> validation_queue_messages outbox row created in the same DB transaction
-> outbox dispatcher publishes to NATS JetStream
-> durable worker consumes at-least-once delivery
-> worker acquires DB-backed execution lease
-> worker re-checks tenant, approval, scope, authorization, policy, and template version
-> DockerSandboxBackend runs the registered template entrypoint
-> EvidenceStore writes full JSON artifact and verifies SHA-256
-> validation_execution_evidence stores metadata
-> worker marks SUCCEEDED / FAILED / exception state
-> frontend/API/audit read execution, events, policy decision, sandbox state, and evidence
```

The API never treats NATS publish as the only durable step. The database outbox is the source of truth until `published_at` and `publish_attempt` are updated.

## Transactional outbox and JetStream

`validation_queue_messages` stores:

- `schema_version`
- `message_id`
- `execution_id`
- `tenant_id` inside payload
- `subject`
- `publish_attempt`
- `published_at`
- `last_publish_error`
- `status`
- `attempt`
- `available_at`
- DB lock owner/token/expiry

NATS headers propagate:

- `schema_version`
- `message_id`
- `execution_id`
- `tenant_id`
- `trace_id`
- `request_id`
- `queue_message_id`
- `transport=nats-jetstream`

Worker consumption is idempotent. Duplicate messages after terminal execution completion are acknowledged and do not create duplicate evidence.

## Execution lease

The worker uses DB compare-and-swap fields on `validation_executions`:

- `lease_owner`
- `lease_token`
- `lease_expires_at`
- `worker_attempt`

Only statuses in `APPROVED`/`QUEUED` and expired leases can transition to `QUEUED` under a new worker. Terminal statuses clear the lease.

## Evidence object keys

Logical object keys include tenant, project, execution, and evidence identifiers:

```text
tenant={tenant_id}/project={project_id}/execution={execution_id}/{evidence_id}.json
```

`MinioEvidenceStore` uploads the JSON artifact, downloads it, recalculates SHA-256, and only then persists metadata. The filesystem adapter preserves the same logical object key in metadata but uses a short local blob path to avoid Windows path-length failures.

## Runtime profile

`docker-compose.yml` now has a `runtime` profile for:

- `nats`
- `minio`
- `validation-outbox-dispatcher`
- `validation-worker`

The local authoritative host-side runtime runner is `solve_p9_runtime.py`. It starts temporary NATS, MinIO, PostgreSQL, and an internal Docker lab network when endpoints are not provided, then exercises the host Docker engine through `DockerSandboxBackend`.

## Acceptance split

Deterministic local baseline:

```powershell
.\.venv\Scripts\python.exe solve_p9_baseline.py --full
.\.venv\Scripts\python.exe -m pytest -q -rs
```

Real infrastructure runtime acceptance:

```powershell
.\.venv\Scripts\python.exe solve_p9_runtime.py
```

Current Windows Docker Desktop execution returned `valid: true` for:

- PostgreSQL migrations 0001-0008 and P9-R outbox/lease schema behavior.
- NATS JetStream outbox publish and durable worker consume.
- Docker sandbox execution against an authorized internal lab-network target.
- MinIO evidence upload/download SHA-256 verification.
- Duplicate JetStream message idempotency.
- Internet egress blocked from the internal sandbox network.
- Timeout cleanup and memory-limit kill probes.

Boundary: the current FastAPI compatibility control plane still uses the existing SQLite `Database` adapter for API-level business persistence. The runtime PostgreSQL check proves the P9-R migration/outbox/lease schema and behavior, not a complete replacement of the compatibility control-plane repository with PostgreSQL.

Linux CI or a Linux host should still be used as the authority for final network-isolation and cgroup behavior before production release.
