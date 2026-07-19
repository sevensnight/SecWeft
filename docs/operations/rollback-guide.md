# Rollback Guide

Rollback requires a backup taken immediately before upgrade and matching down migrations.

P14 rollback boundary:

- remove `delivery.secret_rotation_records`
- remove `delivery.compliance_evidence_packages`
- remove `delivery.legal_holds`
- remove `delivery.deletion_requests`
- remove `delivery.data_exports`
- remove `delivery.delivery_packages`
- remove `delivery.acceptance_runs`
- remove schema `delivery`

Do not roll back through untested version gaps. Validate data integrity after restore before accepting traffic.
