# P9-R runtime runbook

## Local deterministic check

Use this before and after runtime work:

```powershell
cd C:\Users\SevensNight\Documents\Codex\2026-07-10\new-chat\project-ascii
.\.venv\Scripts\python.exe solve_p9_baseline.py --full
.\.venv\Scripts\python.exe -m pytest -q -rs
.\.venv\Scripts\python.exe -m mypy apps/control-plane/src
pnpm typecheck
pnpm test
pnpm build
```

## Host-side runtime check

The runtime runner starts temporary NATS, MinIO, PostgreSQL, and an internal Docker lab network unless endpoints are provided:

```powershell
.\.venv\Scripts\python.exe solve_p9_runtime.py
```

Use existing services:

```powershell
.\.venv\Scripts\python.exe solve_p9_runtime.py `
  --nats-url nats://127.0.0.1:4222 `
  --minio-endpoint 127.0.0.1:9000 `
  --minio-access-key minioadmin `
  --minio-secret-key minioadmin-secret `
  --minio-bucket validation-evidence `
  --postgres-dsn postgresql://p9r:password@127.0.0.1:5432/p9r
```

The command is successful only when the JSON output contains:

```json
{
  "valid": true
}
```

## Runtime Compose profile

Prepare secrets:

```powershell
$env:VULNLAB_ADMIN_KEY = "replace-with-long-admin-key"
$env:VULNLAB_MASTER_KEY = & .\.venv\Scripts\python.exe -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
$env:VULNLAB_VALIDATION_QUEUE_BACKEND = "nats"
$env:VULNLAB_EVIDENCE_STORE_BACKEND = "minio"
$env:VULNLAB_MINIO_ACCESS_KEY = "minioadmin"
$env:VULNLAB_MINIO_SECRET_KEY = "minioadmin-secret"
$env:VULNLAB_MINIO_IMAGE = "minio/minio:RELEASE.2025-04-22T22-12-26Z"
```

Validate config:

```powershell
docker compose --profile runtime config --quiet
```

Start runtime services:

```powershell
docker compose --profile runtime up --build
```

## Expected services

- API: FastAPI control plane
- NATS: JetStream stream for validation execution messages
- MinIO: evidence artifact storage
- validation-outbox-dispatcher: publishes DB outbox rows to JetStream
- validation-worker: consumes durable messages and executes registered templates

## Troubleshooting

| Symptom | Likely cause | Action |
|---|---|---|
| `No such image: minio/minio:RELEASE.2025-04-22T22-12-26Z` | image not pulled | run `docker pull minio/minio:RELEASE.2025-04-22T22-12-26Z` or use an existing MinIO endpoint |
| runtime runner startup fails on MinIO | Docker Hub/network issue | use `--minio-endpoint` with a reachable MinIO |
| worker returns `SANDBOX_FAILED` | Docker unavailable or sandbox network invalid | check Docker Desktop/Linux Docker daemon and `VULNLAB_VALIDATION_SANDBOX_NETWORK` |
| worker returns `SCOPE_INVALID` | target host/port not approved | check scope target, approved ports, and plan step |
| duplicate evidence appears | idempotency regression | inspect `validation_executions.status`, queue message id, and worker lease fields |

## Cleanup

Temporary runner containers are named:

```text
vulnlab-p9r-nats-*
vulnlab-p9r-minio-*
vulnlab-p9r-postgres-*
vulnlab-p9r-target-*
```

Manual cleanup:

```powershell
docker ps --format "{{.Names}}" | Where-Object { $_ -like "vulnlab-p9r-*" } | ForEach-Object { docker rm -f $_ }
```

Compose cleanup:

```powershell
docker compose --profile runtime down
```
