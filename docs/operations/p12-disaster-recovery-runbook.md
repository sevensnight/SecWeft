# P12 Disaster Recovery Runbook

P12 disaster recovery is a staged drill, not a claimed production SLA until runtime acceptance passes.

## Required drill data

Create representative data before backup:

- tenant and project
- task
- validation execution
- validation execution events
- evidence
- vulnerability case
- finding
- remediation
- retest and comparison
- evaluation run
- metric
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
12. Save `solve_p12_disaster_recovery.py` runtime JSON reports and attach their summarized result to the acceptance report.

## Success criteria

- RPO observed value is recorded and is at or below 15 minutes.
- RTO observed value is recorded and is at or below 60 minutes.
- No restore failure is marked as success.
- Any incomplete evidence or broken relationship blocks success.
- Runtime report is attached to `docs/acceptance/p12-acceptance-report.md`.
- Runtime JSON contains `runtime=true`, `runtime_not_claimed=false`, `failed=0`, and `skipped=0`.

## Safety

Never run restore against production unless a human operator has explicitly selected the target and backup. `solve_p12_disaster_recovery.py restore --runtime` requires isolated restore confirmation.

P12-R runtime scripts additionally require:

- `ENVIRONMENT=test`
- `P12R_RUNTIME_ENV=isolated`
- `P12R_TEST_CLUSTER_MARKER=isolated-runtime`

If any of these are missing, the script fails as a runtime precondition and must not be counted as a skipped or passed runtime drill.
