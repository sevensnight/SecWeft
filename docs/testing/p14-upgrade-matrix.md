# P14 Upgrade and Rollback Matrix

Supported upgrade paths are explicit:

- `2.11.x -> 2.14.0-p14`
- `2.12.x -> 2.14.0-p14`
- `2.13.x -> 2.14.0-p14`

Unsupported paths, including `2.10.x` and arbitrary cross-version upgrades, must not be described as supported.

`solve_p14_upgrade.py` checks:

- migration order `0001` through `0014`;
- matching down migrations;
- P14 down migration boundary;
- Helm version/tag targeting `2.14.0-p14`;
- Docker Compose runtime service presence;
- production repository fail-closed configuration.

This is deterministic upgrade acceptance. It is not a live database restore drill.
