# Changelog

## 2.14.1

Release date: 2026-07-28

### Improved

- Added explicit React and React-DOM version alignment validation with unit coverage and CI enforcement.
- Improved Dependabot grouping so React ecosystem updates are isolated from the general workspace group, and Monaco Editor and Playwright updates are excluded from broad minor/patch workspace updates.
- Improved P0 from-scratch acceptance so a clean detached Git worktree is recognized as a valid verification checkout.

### Updated

- Updated React and React-DOM from `19.2.7` to `19.2.8`.
- Updated workspace minor/patch frontend dependencies, including `@hookform/resolvers`, TanStack React packages, `antd`, `react-hook-form`, `@testing-library/jest-dom`, `@vitejs/plugin-react`, `eslint`, `typescript-eslint`, `turbo`, and `vite`.
- Updated development dependency constraint ranges in `requirements-dev.txt` for `mypy`, `pip-audit`, `pip-tools`, `ruff`, and `types-PyYAML`; deterministic CI continues to install from `requirements-dev.lock`.

### Fixed

- Fixed React/React-DOM dependency drift by aligning both runtime packages at `19.2.8`.
- Fixed overly broad Dependabot workspace grouping that previously mixed dependencies with different compatibility risk profiles.
- Fixed clean detached-worktree release validation compatibility in the P0 baseline runner.

### Security and compatibility

- No new vulnerability validation templates.
- No new exploit execution capabilities, scanner capabilities, PoC upload, arbitrary shell execution, or arbitrary command execution product capabilities.
- No database migration changes; the migration set remains `0001` through `0014`.
- No OpenAPI contract changes.
- No Helm template or production runtime behavior changes.
- The v2.14.1 maintenance release does not rerun destructive isolated runtime acceptance. It reuses the accepted v2.14.0 authoritative runtime evidence because the release diff is limited to dependency maintenance, CI/dependency governance, validation tooling, and release documentation.
- `pnpm audit --audit-level high` improved from the v2.14.0 baseline of 3 high / 1 low advisories to 2 high / 1 low advisories; no new high or critical advisory was introduced.

## 2.14.0-p14

- Added enterprise requirement traceability and final acceptance APIs.
- Added candidate delivery package generation with checksum and sensitive-marker checks.
- Added compliance control mapping export. Control mapping is not certification.
- Added data governance metadata APIs for redacted export, deletion request, and Legal Hold.
- Added production readiness gate that remains fail-closed while authoritative runtime evidence is absent.
- Added PostgreSQL migration `0014_p14_enterprise_acceptance_delivery`.
- Extended `/system` with P14 readiness, delivery, governance, secret lifecycle, and compliance views.
- Added `solve_p14_baseline.py`, `solve_p14_e2e.py`, `solve_p14_upgrade.py`, and `solve_p14_delivery.py`.
- Recorded authoritative GitHub/Linux isolated runtime acceptance from run `30195998389` for source commit `59efe16144563f57033724c00ea70cfe895ba890`.
- Verified production readiness with `runtime=true`, `runtime_not_claimed=false`, `production_ready=true`, `failed=0`, `skipped=0`, and `critical_gates_failed=0`.
- Verified 3 Control Plane pods, 3 Worker pods, PostgreSQL migrations `0001`-`0014`, Helm install, DR backup/restore, evidence consistency, chaos recovery, P9-P14 regression, P13 release gate, P14 production readiness, and artifact integrity.

Artifact manifest digest: `b3e93251400c8bbc54ce7472904a1202eada16c2b4a70a5fcddd1c8e55f66465`.
