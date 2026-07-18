# P13 Release Testing Matrix

| Area | Coverage |
| --- | --- |
| Artifact immutability | Container identity must be `repo@sha256`, mutable tags rejected. |
| SBOM | Missing SBOM blocks RC freeze. |
| Provenance | Verified provenance subject and source commit are required for passing gates. |
| Signature | Verified signature is required for RC freeze and production gates. |
| Security scan | Unresolved critical vulnerabilities fail gates unless active exception exists. |
| License scan | Failed or missing license scan fails gates. |
| P11/P12 | P11 gate metadata is evaluated; P12 authoritative runtime is mandatory for production. |
| Promotion | Order is development → integration → staging → production. |
| Approval | Production approver cannot be the RC creator. |
| Exceptions | Exceptions require expiry and compensating controls; critical exceptions require separation of duties. |
| Rollback | Rollback creates immutable rollback record and updates deployment status. |
| Drift | Report-only drift detects image, config, replica, resource, security-context, and secret-reference drift. |
| Compliance | Compliance package hashes release evidence and audit-relevant metadata. |
| Isolation | Cross-tenant release artifact access returns not found. |
| Idempotency | POST operations require Idempotency-Key and reject key reuse with different payload. |

`solve_p13_baseline.py` is deterministic and does not claim runtime acceptance.
