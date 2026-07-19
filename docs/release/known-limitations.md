# Known Limitations

- Authoritative GitHub/Linux isolated runtime artifacts were not available in this workspace during P14.
- `production_ready` remains `false` while `runtime_not_claimed=true`.
- Candidate delivery packages can be generated for review; formal delivery packages require all critical production gates.
- Compliance mapping is not certification.
- P14 does not add new validation templates, scanners, PoC upload, or arbitrary command execution.
- Unsupported cross-version upgrades must not be claimed as tested.
