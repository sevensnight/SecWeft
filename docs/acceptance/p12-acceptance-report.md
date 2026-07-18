# P12 Acceptance Report

Version: `2.12.0-p12`

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
