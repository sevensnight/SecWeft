# Changelog

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
