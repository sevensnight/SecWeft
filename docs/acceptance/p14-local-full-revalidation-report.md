# P14 Local Isolated Runtime and Full Revalidation Report

This report records the local-only closure path for version `2.14.0-p14`.

Status boundary:

- `LOCAL_VERIFIED` means the local isolated runtime or deterministic command matrix produced matching local evidence.
- `REMOTE_NOT_EXECUTED` means GitHub Actions authoritative isolated runtime was not triggered or inspected.
- `PRODUCTION_BLOCKED` means production readiness remains false because this run is not GitHub authoritative evidence.

The local path must never change these production-facing flags:

```json
{
  "github_runtime_not_claimed": true,
  "runtime_not_claimed": true,
  "production_ready": false
}
```

## Evidence sources

| Evidence source | Meaning | Production promotion |
| --- | --- | --- |
| `GITHUB_ISOLATED_RUNTIME` | Workflow-dispatched, ubuntu-24.04, kind-isolated runtime evidence bound to the current commit. | Required for production readiness. |
| `LOCAL_ISOLATED_LINUX_RUNTIME` | Local kind/k3d isolated runtime evidence produced by `solve_p14_local_authoritative.py`. | Accepted only for local engineering confidence. |
| `WINDOWS_DEVELOPMENT_RUNTIME` | Windows Docker Desktop development evidence. | Informational only. |
| `DETERMINISTIC_BASELINE` | SQLite/in-process deterministic baseline evidence. | Informational only. |

## Local authoritative entrypoint

```bash
python solve_p14_local_authoritative.py preflight --json
python solve_p14_local_authoritative.py run --json
python solve_p14_local_authoritative.py verify --json
python solve_p14_local_authoritative.py clean --json
```

The `run` phase writes artifacts under:

```text
artifacts/acceptance/<run_id>/
├─ STARTED.json
├─ COMPLETED.json
├─ artifact-manifest.json
├─ logs/
└─ runtime/
```

Required runtime files include:

```text
environment-fingerprint.json
scale-runtime-result.json
dr-backup-result.json
dr-restore-result.json
chaos-runtime-result.json
evidence-consistency-result.json
rpo-rto-result.json
p9-baseline-result.json
p10-baseline-result.json
p11-baseline-result.json
p12-baseline-result.json
p13-baseline-result.json
p14-baseline-result.json
p14-e2e-result.json
p14-upgrade-result.json
p14-delivery-result.json
release-gate-result.json
production-readiness-result.json
artifact-manifest.json
```

## Preflight requirements

Local isolated runtime must fail closed unless all are true:

- `ENVIRONMENT=test`
- `P14_LOCAL_RUNTIME_ACCEPTANCE=true`
- `CHAOS_ENABLED=true`
- Docker, kubectl, Helm, Python, Node.js, pnpm are available
- kind or k3d is available
- Kubernetes context is local/non-production
- configured database, NATS and MinIO endpoints are non-production
- working tree is clean

## Current local result evidence

The exact current local full-revalidation result is the machine-generated
`COMPLETED.json` under:

```text
artifacts/acceptance/<p14-local-run-id>/COMPLETED.json
```

That file is intentionally not committed because it is per-run evidence and
includes the exact `source_commit`, environment fingerprint, command timings,
stdout/stderr hashes and artifact hashes for the run that was actually
executed.

The required successful local full-revalidation shape is:

```text
valid=true
status=VERIFIED
passed>0
failed=0
skipped=0
blocked=0
working_tree_clean_before=true
working_tree_clean_after=true
```

Latest local isolated runtime status must likewise be read from:

```text
artifacts/acceptance/<p14-local-runtime-run-id>/
```

If the local runtime does not produce the required runtime result files,
`solve_p14_local_authoritative.py verify --json` must return
`valid=false`, `local_isolated_runtime_accepted=false` and
`production_ready=false`.

At the time this closure was added, the local runtime failed closed while kind
was ensuring `kindest/node:v1.32.2` before the controlled timeout. That
environmental failure does not create P14 production runtime acceptance.

Current required boundary remains:

```json
{
  "local_isolated_runtime_accepted": false,
  "local_full_revalidation_passed": true,
  "github_runtime_not_claimed": true,
  "runtime_not_claimed": true,
  "production_ready": false
}
```
