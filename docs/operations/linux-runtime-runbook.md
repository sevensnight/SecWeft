# Linux Runtime Runbook

Use this runbook for P9-H authoritative acceptance.

## Prerequisites

- Ubuntu/Linux host or GitHub Actions `ubuntu-24.04`
- Docker engine available to the runner
- Python 3.12 dependencies installed from `requirements-dev.lock`
- Node 22 and pnpm 10 for the full SQLite baseline invoked by hardening

## Command

```bash
python solve_p9_hardening.py
```

The runner starts temporary PostgreSQL, NATS JetStream, MinIO, Docker sandbox, and local lab resources through existing P9-R runtime code. It fails if any check fails or skips.

## Modes

- SQLite deterministic development mode: `solve_p9_baseline.py --full`
- PostgreSQL production persistence mode: `tests/integration/test_p9h_postgres_repository.py`
- Windows development runtime: useful for fast Docker Desktop validation
- Linux authoritative runtime: `p9h-linux-runtime` CI job

## Cleanup

After interrupted runs, remove temporary containers:

```bash
docker ps -a --format '{{.Names}}' | grep -E 'vulnlab-p9h|vulnlab-p9r' | xargs -r docker rm -f
```
