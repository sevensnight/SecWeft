# P12-R Runtime Acceptance Report

Version: `2.12.1-p12r`

Scope: resilience runtime acceptance for P12 high availability, scale, disaster recovery, evidence consistency, and chaos gates.

This report distinguishes deterministic readiness from authoritative Linux runtime acceptance. A readiness pass does not imply runtime acceptance.

## Required runtime result shape

After a real runtime pass, each runtime entry point must return:

- `valid=true`
- `runtime=true`
- `runtime_not_claimed=false`
- `summary.failed=0`
- `summary.skipped=0`

Precondition failures are recorded as failed checks, not skips.

## Local environment observed during P12-R hardening

Observed at: `2026-07-19T01:33:44+08:00`

| Field | Observed value |
| --- | --- |
| Host OS | Microsoft Windows NT 10.0.26200.0 |
| Docker client | 28.4.0, context `desktop-linux`, windows/amd64 |
| Docker server | Docker Desktop 4.46.0, engine 28.4.0, Linux backend |
| Docker kernel | `6.6.87.2-microsoft-standard-WSL2` |
| Docker cgroup | v2, pids/cpu/memory limits available |
| kubectl client | v1.32.2, windows/amd64 |
| kubectl cluster | not connected; `current-context is not set` |
| Helm | v4.2.3 |
| kind | not installed / not on PATH |
| k3d | not installed / not on PATH |
| Git remote | none configured in local checkout |
| GitHub Actions inspection | not possible from this checkout; no remote and no `gh` CLI available |

This is a Windows development host with Docker Desktop's Linux backend. It is not the authoritative Linux kind/k3d runtime environment required for network isolation, pod scheduling, and chaos acceptance.

## Required Linux authoritative runtime environment

The authoritative runtime environment must provide:

- Ubuntu/Linux runner
- Docker daemon
- kind or k3d cluster
- active `kubectl` context pointing at the isolated test cluster
- Helm
- PostgreSQL
- Redis
- NATS JetStream
- MinIO
- API gateway
- Prometheus/OpenTelemetry
- local authorized training lab
- runtime values file and Kubernetes Secret material for the Helm release

Required markers:

- `ENVIRONMENT=test`
- `P12_RUNTIME_ACCEPTANCE=true`
- `P12R_RUNTIME_ENV=isolated`
- `P12R_RUNTIME_NAMESPACE=vulnlab`
- `P12R_TEST_CLUSTER_MARKER=isolated-runtime`
- active Kubernetes context prefixed with `kind-` or `k3d-`
- Kubernetes nodes labeled `vulnlab.openai.local/p12-runtime=isolated`
- non-production database and MinIO endpoints
- `CHAOS_ENABLED=true` for chaos only
- `VULNLAB_P12_CHAOS_ACK=isolated-chaos` for chaos only

## GitHub Actions isolated runtime workflow

The authoritative workflow is manual-only:

```text
workflow_dispatch:
  p12r_runtime=true
  confirm_isolated_runtime=RUN_P12_ISOLATED_RUNTIME
```

The job uses Ubuntu 24.04, Docker, kind, kubectl, Helm, Python 3.11, Node.js, and pnpm. It creates an isolated kind cluster, builds project images, loads them into kind, writes private runtime Helm values outside the artifact directory, runs P12 scale/DR/chaos runtime entry points, reruns P9-P12 deterministic baselines, collects Kubernetes diagnostics, uploads sanitized artifacts, and destroys kind in an `always()` cleanup step.

Required sanitized artifacts:

- `scale-runtime-result.json`
- `dr-backup-result.json`
- `dr-restore-result.json`
- `chaos-runtime-result.json`
- `environment-fingerprint.json`
- `rpo-rto-result.json`
- `evidence-consistency-result.json`
- `helm-status.txt`
- `kubectl-events.txt`
- `pod-logs/`
- `p9-p12-baseline-results/`

Private Helm values remain under `work/p12r/private/` and are not uploaded.

Status semantics:

- `READINESS_COMPLETE`: deterministic readiness exists.
- `RUNTIME_BLOCKED`: destructive isolated runtime confirmation or guard is missing.
- `RUNTIME_RUNNING`: isolated runtime job has started.
- `RUNTIME_FAILED`: a real runtime step failed.
- `RUNTIME_ACCEPTED`: all runtime reports have `valid=true`, `runtime=true`, and `runtime_not_claimed=false`.

Only the isolated Linux workflow may produce `RUNTIME_ACCEPTED`.

## Runtime commands

| Command | Current local result | Runtime claimed |
| --- | --- | --- |
| `python solve_p12_scale.py --runtime --namespace vulnlab --release p12 --values work/p12r/missing-runtime-values.yaml` | Executed locally; failed closed with `valid=false`, `runtime=true`, `runtime_not_claimed=true`, `failed=1`, `skipped=0`. First blockers: `ENVIRONMENT=test`, `P12R_RUNTIME_ENV=isolated`, and `P12R_TEST_CLUSTER_MARKER=isolated-runtime` missing. | No |
| `python solve_p12_disaster_recovery.py backup --runtime` | Executed locally; failed closed with `valid=false`, `runtime=true`, `runtime_not_claimed=true`, `failed=1`, `skipped=0`. First blockers: `ENVIRONMENT=test`, `P12R_RUNTIME_ENV=isolated`, and `P12R_TEST_CLUSTER_MARKER=isolated-runtime` missing. | No |
| `python solve_p12_disaster_recovery.py restore --runtime` | Executed locally without `--backup-id` only to verify fail-closed preconditions; failed with `valid=false`, `runtime=true`, `runtime_not_claimed=true`, `failed=1`, `skipped=0`. First blockers: isolated runtime markers missing. | No |
| `python solve_p12_chaos.py --runtime --all` | Executed locally; failed closed with `valid=false`, `runtime=true`, `runtime_not_claimed=true`, `failed=9`, `skipped=0`. First blockers: isolated runtime markers, `CHAOS_ENABLED=true`, and `VULNLAB_P12_CHAOS_ACK=isolated-chaos` missing. | No |

Local JSON reports were written under `work/p12r/` during the run. They are intentionally untracked build artifacts.

## Required validation coverage

Runtime acceptance must cover:

- Helm install with at least 3 control-plane pods and 3 worker pods
- multi-instance load balancing
- Idempotency-Key consistency
- optimistic locking
- worker lease CAS
- exactly-once effective execution
- no duplicate evidence
- control-plane termination recovery
- worker termination recovery
- rolling updates
- PDB, HPA, topology spread, and graceful shutdown
- two-tenant fairness and overload classification
- PostgreSQL and MinIO backup
- PostgreSQL and MinIO restore
- evidence object existence and SHA-256 verification
- orphan object detection
- unfinished execution recovery
- RPO/RTO measured as test-environment observations
- isolated chaos targets: control plane, idle worker, running worker, NATS, PostgreSQL, MinIO, sandbox timeout, duplicate message, and poison message

## Evidence consistency status taxonomy

P12-R runtime consistency checks must create or detect:

- `MISSING_OBJECT`
- `ORPHAN_OBJECT`
- `HASH_MISMATCH`
- `METADATA_MISMATCH`
- `TENANT_PREFIX_MISMATCH`

Default mode is read/report only. Repair must be explicit, auditable, idempotent, and dry-run capable.

## Current acceptance status

Authoritative Linux runtime acceptance is not claimed in this local checkout because the required kind/k3d Kubernetes environment and runtime values are unavailable.

The P12-R script and documentation work hardens the gate so that missing runtime infrastructure fails explicitly instead of passing as static readiness.
