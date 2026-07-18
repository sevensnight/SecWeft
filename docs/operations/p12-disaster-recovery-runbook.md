# P12 Disaster Recovery Runbook

P12 disaster recovery is a staged drill, not a claimed production SLA until runtime acceptance passes.

## Required drill data

Create representative data before backup:

- tenant and project
- task
- validation execution
- evidence
- vulnerability case
- retest and comparison
- evaluation run
- audit events

## Drill sequence

1. Create the representative data.
2. Run backup for PostgreSQL, MinIO, and required message state.
3. Destroy the isolated test data and environment.
4. Redeploy infrastructure.
5. Run restore.
6. Verify record counts.
7. Verify foreign keys, unique constraints, indexes, and tenant isolation.
8. Verify evidence SHA-256 against restored objects.
9. Verify audit chain continuity.
10. Verify unfinished validation work resumes or is safely terminal.
11. Rerun P9, P10, P11, and P12 acceptance.

## Success criteria

- RPO observed value is recorded and is at or below 15 minutes.
- RTO observed value is recorded and is at or below 60 minutes.
- No restore failure is marked as success.
- Any incomplete evidence or broken relationship blocks success.
- Runtime report is attached to `docs/acceptance/p12-acceptance-report.md`.

## Safety

Never run restore against production unless a human operator has explicitly selected the target and backup. `solve_p12_disaster_recovery.py restore --runtime` requires isolated restore confirmation.
