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

Authoritative GitHub/Linux runtime acceptance was not recorded in this local workspace; `runtime_not_claimed=true` remains the correct state.
