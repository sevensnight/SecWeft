# P13 Acceptance Report

Target version: `2.13.0-p13`

## Implemented

- Release artifact registration with immutable digest validation.
- SBOM, provenance, signature, security scan, and license scan metadata.
- Release candidate freeze.
- Gate evaluation for development, integration, staging, and production.
- P12 authoritative runtime production gate.
- Human approval and creator/approver separation for production.
- Time-bounded release exceptions.
- Ordered environment promotion using the same digest.
- Deployment records, rollback records, drift detection, and compliance package generation.
- OpenAPI, shared types, API client, and web console release views.

## Runtime boundary

`solve_p13_baseline.py` is deterministic and reports `runtime=false` and `runtime_not_claimed=true`. It does not claim GitHub Actions isolated runtime success.

Only the P12-R isolated Linux workflow can produce authoritative runtime acceptance for P12 gates.
