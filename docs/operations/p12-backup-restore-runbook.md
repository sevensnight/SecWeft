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
export VULNLAB_P12_DR_MODE=isolated
export VULNLAB_P12_DR_CONFIRM=isolated-restore
python solve_p12_disaster_recovery.py restore --runtime --backup-id <backup-directory-name>
```

Restore must validate checksums before replacing state. If restore does not complete, stateful services remain stopped to prevent use of partial data.

## Kubernetes

The Helm chart includes:

- backup CronJob
- restore Job disabled by default

Runtime values must supply production dependencies and secrets. Restore requires an explicit backup ID and should be run only in an isolated recovery namespace before production use.
