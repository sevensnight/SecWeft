# P12 Backup and Restore Runbook

P12 defines targets:

- RPO target: 15 minutes
- RTO target: 60 minutes

These are targets until a real isolated runtime drill passes. The deterministic baseline must not be interpreted as a production SLA.

## Local deterministic mode

`solve_p12_disaster_recovery.py` without `--runtime` validates runbooks, backup manifest shape, and acceptance wiring only.

## Runtime backup drill

Use an isolated environment:

```sh
export ENVIRONMENT=test
export P12R_RUNTIME_ENV=isolated
export P12R_TEST_CLUSTER_MARKER=isolated-runtime
export VULNLAB_P12_DR_MODE=isolated
python solve_p12_disaster_recovery.py backup --runtime
```

The existing compose backup flow captures:

- PostgreSQL logical dump
- API data archive
- Redis volume archive
- NATS volume archive
- MinIO volume archive
- manifest and SHA-256 checksums

## Runtime restore drill

Use an isolated environment only:

```sh
export ENVIRONMENT=test
export P12R_RUNTIME_ENV=isolated
export P12R_TEST_CLUSTER_MARKER=isolated-runtime
export VULNLAB_P12_DR_MODE=isolated
export VULNLAB_P12_DR_CONFIRM=isolated-restore
python solve_p12_disaster_recovery.py restore --runtime --backup-id <backup-directory-name>
```

Restore must validate checksums before replacing state and must rerun `solve_p12_baseline.py --full` after state is restored. If restore does not complete, stateful services remain stopped to prevent use of partial data.

Runtime backup and restore reports record measured elapsed time as test-environment RPO/RTO evidence only. These values are not production SLA claims.

## Kubernetes

The Helm chart includes:

- backup CronJob
- restore Job disabled by default

Runtime values must supply production dependencies and secrets. Restore requires an explicit backup ID and should be run only in an isolated recovery namespace before production use.

## P12-R report artifacts

Use `--report-json` to persist the exact machine-readable runtime result:

```sh
python solve_p12_disaster_recovery.py backup --runtime --report-json work/p12r-backup.json
python solve_p12_disaster_recovery.py restore --runtime --backup-id <id> --report-json work/p12r-restore.json
```

The JSON report includes environment fingerprint, command output tails, start/end timestamps, measured backup/restore elapsed time, and whether runtime was actually claimed.
