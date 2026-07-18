# P12 Availability Security Boundaries

P12 is an operational hardening phase. It must not expand offensive capability.

## Preserved boundaries

- No new validation templates.
- No new scanners.
- No arbitrary PoC upload.
- No arbitrary shell or command execution.
- No bypass of P9 scope, approval, policy, sandbox, or evidence rules.
- No bypass of P10 human remediation decisions.
- No bypass of P11 human promotion decisions.

## Availability-specific boundaries

- Priority only affects queue ordering after authorization and quota checks.
- Overload returns bounded 429/503 errors; it must not silently drop work.
- Production mode refuses SQLite queue/repository, in-process sandbox, and filesystem evidence store.
- Evidence consistency checker reads, reports, and performs only explicit controlled repair. It does not delete objects by default.
- Chaos entry refuses production mode.
- Kubernetes chart must not use host network or mount Docker socket.

## Evidence consistency states

- `healthy`
- `missing_object`
- `orphan_object`
- `hash_mismatch`
- `metadata_mismatch`

An inconsistent report must never be displayed as healthy.
