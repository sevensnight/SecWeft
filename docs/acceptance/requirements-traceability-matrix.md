# Requirements Traceability Matrix

The authoritative machine-readable matrix is exposed at:

```text
GET /api/v1/acceptance/requirements
```

Each item records:

- `requirement_id`
- `requirement_description`
- `implementation_status`
- backend modules
- frontend routes
- API operations
- database migrations
- policy actions
- tests
- acceptance scripts
- documents
- known limitations
- runtime evidence classification

Valid statuses:

- `IMPLEMENTED`
- `PARTIALLY_IMPLEMENTED`
- `NOT_IMPLEMENTED`
- `NOT_APPLICABLE`
- `BLOCKED`

The matrix distinguishes static implementation, deterministic testing, runtime validation, and manual acceptance.

## Authoritative acceptance closure

Final runtime evidence was recorded from GitHub Actions run `30195998389` for source commit `59efe16144563f57033724c00ea70cfe895ba890`.

| Requirement group | Runtime evidence | Result |
| --- | --- | --- |
| P0-P14 deterministic baselines | P9-P14 baseline result JSON artifacts | `valid=true`, `failed=0`, `skipped=0` |
| P12 authoritative runtime | `scale-runtime-result.json`, DR, chaos, evidence consistency, RPO/RTO reports | `valid=true`, `runtime=true`, `runtime_not_claimed=false` |
| P11 evaluation gates | P11 baseline result in runtime artifact set | `valid=true`, `failed=0`, `skipped=0` |
| P13 release gates | `release-gate-result.json` | `valid=true`, `critical_gates_failed=0` |
| P14 production readiness | `production-readiness-result.json` | `production_ready=true` |
| Migration coverage | `migration-result.json` | migrations `0001` through `0014` applied |
| Frontend build | `web-console-dist` artifact | uploaded by the same workflow run |
| SBOM | `repository-sbom` artifact | uploaded by the same workflow run |
| Delivery manifest integrity | `artifact-manifest.json` | all required SHA-256 entries verified |
| Secret leakage guard | `artifact-secret-scan-result.json` | `valid=true`, `failed=0` |

The runtime artifact manifest digest is `b3e93251400c8bbc54ce7472904a1202eada16c2b4a70a5fcddd1c8e55f66465`.
