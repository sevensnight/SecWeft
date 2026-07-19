# Upgrade Guide

Supported P14 upgrade paths:

- `2.11.x -> 2.14.0-p14`
- `2.12.x -> 2.14.0-p14`
- `2.13.x -> 2.14.0-p14`

Required sequence:

1. Back up PostgreSQL.
2. Back up MinIO evidence.
3. Export current Helm/Compose configuration.
4. Apply migrations through `0014_p14_enterprise_acceptance_delivery`.
5. Deploy control plane, web console, and workers tagged `2.14.0-p14`.
6. Run `solve_p14_upgrade.py`.
7. Run P13/P14 deterministic baselines.

Do not claim unsupported cross-version upgrades as tested.
