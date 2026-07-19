# P14 Enterprise Acceptance and Delivery Architecture

P14 is the productization closure layer for P0-P13. It does not add scanners, validation templates, exploit types, arbitrary PoC upload, or arbitrary command execution. It aggregates existing evidence, exposes final acceptance APIs, generates candidate delivery packages, and keeps production readiness fail-closed when critical runtime evidence is absent.

## Reused capability map

- P0-P8: enterprise API baseline, RBAC, model gateway, task orchestration, knowledge, audit, OpenAPI, frontend shell.
- P9/P9-R/P9-H: controlled validation execution plane, worker queue, sandbox and evidence store abstractions, PostgreSQL hardening.
- P10: remediation verification lifecycle.
- P11: AI evaluation governance and regression gates.
- P12/P12-R: HA/readiness/runtime workflow gates.
- P13: release artifacts, SBOM, provenance, signatures, gates, promotion, rollback, drift, compliance package.

## P14 additions

- `EnterpriseAcceptanceService`
- `/api/v1/acceptance/*`
- `/api/v1/delivery-packages`
- `/api/v1/compliance/*`
- `/api/v1/data-governance/*`
- `/api/v1/readiness/production`
- migration `0014_p14_enterprise_acceptance_delivery`
- `/system` frontend cards for final readiness, traceability, delivery, data governance, secret lifecycle, and compliance mapping

## Readiness invariant

`production_ready` is computed from critical gates. It cannot be changed from the UI. If P12 authoritative runtime evidence is not present, P14 returns:

```json
{
  "production_ready": false,
  "runtime": false,
  "runtime_not_claimed": true
}
```

This is intentional. Deterministic local baseline is not a substitute for Linux authoritative runtime acceptance.
