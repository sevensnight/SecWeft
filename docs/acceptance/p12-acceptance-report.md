# P12 Acceptance Report

Version: `2.12.1-p12r`

Scope: high availability, horizontal scalability, bounded overload, evidence consistency, backup/restore, disaster recovery, and fault-injection guards.

Out of scope:

- P13
- new vulnerability types
- new validation templates
- new scanners
- arbitrary PoC upload
- arbitrary shell or command execution

## Deterministic local baseline

Entry:

```sh
python solve_p12_baseline.py
python solve_p12_baseline.py --full
```

Expected deterministic coverage:

- P12 repository layout
- OpenAPI runtime projection
- migration 0012
- no dangerous API paths
- no new validation templates
- production fallback guard
- P12 operational resilience unit tests
- Helm static rendering
- web-console typecheck
- P0-P11 compatibility in full mode

## Runtime acceptance

Separate entries:

```sh
python solve_p12_scale.py --runtime --namespace vulnlab --release p12 --values runtime-values.yaml
python solve_p12_disaster_recovery.py backup --runtime
python solve_p12_disaster_recovery.py restore --runtime --backup-id <id>
python solve_p12_chaos.py --runtime --target validation-worker
```

Runtime acceptance must record whether the environment is Windows development runtime or Linux authoritative runtime. Linux CI/kind/k3d remains the authoritative environment for network isolation, multi-replica scheduling, and chaos validation.

## Current status field discipline

Only commands actually executed may be marked as passed. Unexecuted runtime drills remain "not claimed" and do not establish production RPO/RTO SLA.

P12-R adds executable runtime preconditions and environment fingerprinting to the scale, disaster-recovery, and chaos scripts. A missing kind/k3d cluster, missing runtime values, missing isolated runtime marker, or missing chaos acknowledgement is a failed runtime precondition, not a skip and not a pass.

## Executed on 2026-07-18

Passed:

- `python solve_p12_baseline.py`: 9 passed, 0 failed, 0 skipped.
- `python solve_p12_baseline.py --full`: 18 passed, 0 failed, 0 skipped.
- `python solve_p12_scale.py`: 3 passed, 0 failed, 0 skipped; readiness only, runtime not claimed.
- `python solve_p12_disaster_recovery.py`: 3 passed, 0 failed, 0 skipped; runtime not claimed.
- `python solve_p12_chaos.py`: 2 passed, 0 failed, 0 skipped; runtime not claimed.
- `pytest -q -rs`: passed; no skip summary emitted.
- `mypy apps/control-plane/src`: passed.
- `ruff format --check .`: passed.
- `ruff check .`: passed.
- `pnpm lint`: passed.
- `pnpm typecheck`: passed.
- `pnpm test`: passed.
- `pnpm build`: passed; bundle budget passed.
- `helm lint infrastructure/kubernetes/helm/vulnlab-platform --strict`: passed.
- `helm template p12 infrastructure/kubernetes/helm/vulnlab-platform --namespace vulnlab --set global.imagePullPolicy=Never`: passed.
- `git diff --check`: passed.

Not executed:

- `solve_p12_scale.py --runtime` against kind/k3d with runtime values.
- `solve_p12_disaster_recovery.py backup --runtime`.
- `solve_p12_disaster_recovery.py restore --runtime`.
- `solve_p12_chaos.py --runtime`.
- Linux CI hosted execution after pushing this commit.

Runtime RPO/RTO and Linux multi-replica chaos acceptance therefore remain unclaimed until those runtime commands pass in an isolated Linux environment.

## P12-R runtime acceptance gates

Runtime passing criteria:

- `python solve_p12_scale.py --runtime --namespace vulnlab --release p12 --values runtime-values.yaml`
- `python solve_p12_disaster_recovery.py backup --runtime`
- `python solve_p12_disaster_recovery.py restore --runtime --backup-id <id>`
- `python solve_p12_chaos.py --runtime --all`

Each passing runtime command must return:

- `valid=true`
- `runtime=true`
- `runtime_not_claimed=false`
- `summary.failed=0`
- `summary.skipped=0`

Required isolated runtime markers:

- `ENVIRONMENT=test`
- `P12R_RUNTIME_ENV=isolated`
- `P12R_TEST_CLUSTER_MARKER=isolated-runtime`
- `CHAOS_ENABLED=true` for chaos only
- `VULNLAB_P12_CHAOS_ACK=isolated-chaos` for chaos only

The detailed runtime status for this revision is tracked in `docs/acceptance/p12-runtime-acceptance-report.md`.

## Executed during P12-R hardening on 2026-07-19

Passed:

- `python solve_p12_baseline.py`: 9 passed, 0 failed, 0 skipped.
- `python solve_p12_baseline.py --full`: 18 passed, 0 failed, 0 skipped.
- `python solve_p12_scale.py`: 3 passed, 0 failed, 0 skipped; readiness only, runtime not claimed.
- `python solve_p12_disaster_recovery.py`: 3 passed, 0 failed, 0 skipped; readiness only, runtime not claimed.
- `python solve_p12_chaos.py`: 2 passed, 0 failed, 0 skipped; readiness only, runtime not claimed.
- `pytest -q -rs`: passed; no skip summary emitted.
- `ruff format --check .`: passed.
- `ruff check .`: passed.
- `mypy apps/control-plane/src`: passed.
- `pnpm lint`: passed.
- `pnpm typecheck`: passed through `solve_p12_baseline.py --full`.
- `pnpm test`: passed through `solve_p12_baseline.py --full`.
- `pnpm build`: passed through `solve_p12_baseline.py --full`.
- `helm lint infrastructure/kubernetes/helm/vulnlab-platform --strict`: passed.
- `helm template p12 infrastructure/kubernetes/helm/vulnlab-platform --namespace vulnlab --set global.imagePullPolicy=Never`: passed.
- `git diff --check`: passed.
- `python solve_p9_baseline.py`: 6 passed, 0 failed, 0 skipped.
- `python solve_p10_baseline.py`: 8 passed, 0 failed, 0 skipped.
- P11 compatibility passed through `solve_p12_baseline.py --full`.

Runtime fail-closed checks executed locally:

- `python solve_p12_scale.py --runtime --namespace vulnlab --release p12 --values work/p12r/missing-runtime-values.yaml`: failed closed, `runtime_not_claimed=true`, 1 failed, 0 skipped.
- `python solve_p12_disaster_recovery.py backup --runtime`: failed closed, `runtime_not_claimed=true`, 1 failed, 0 skipped.
- `python solve_p12_disaster_recovery.py restore --runtime`: failed closed, `runtime_not_claimed=true`, 1 failed, 0 skipped.
- `python solve_p12_chaos.py --runtime --all`: failed closed, `runtime_not_claimed=true`, 9 failed, 0 skipped.

Not executed as passing runtime acceptance:

- kind/k3d Helm installation with runtime values.
- real multi-pod control-plane and worker recovery.
- real two-tenant load and overload runtime.
- real backup/restore RPO/RTO measurement.
- real chaos injection against NATS, PostgreSQL, MinIO, sandbox timeout, duplicate message, and poison message.

Reason: this local checkout has no configured Git remote, no `gh` CLI, no kind/k3d on PATH, and no active `kubectl` cluster context. Authoritative Linux runtime acceptance remains unclaimed until the runtime job is run with an isolated cluster and runtime values.
