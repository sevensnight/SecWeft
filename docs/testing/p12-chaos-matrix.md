# P12 Chaos and Failure-Injection Matrix

Fault injection is allowed only in isolated test environments. `solve_p12_chaos.py --runtime` refuses production mode and requires `CHAOS_ENABLED=true`, `ENVIRONMENT=test`, `P12R_RUNTIME_ENV=isolated`, `P12R_TEST_CLUSTER_MARKER=isolated-runtime`, and `VULNLAB_P12_CHAOS_ACK=isolated-chaos`.

| Target | Injection | Expected invariant |
| --- | --- | --- |
| control-plane | delete one pod | requests continue through remaining replicas |
| idle-worker | delete one idle worker pod | idle capacity returns without execution impact |
| running-worker | delete one worker during active validation | lease expires or work completes exactly once |
| validation-worker | delete one worker pod | compatibility alias for worker pod deletion |
| nats | pause or restart service | publisher retry is bounded, backlog recovers |
| postgres | pause or restart service | retry is bounded, no silent SQLite fallback |
| minio | pause or restart service | evidence upload reports dependency failure or recovers |
| sandbox-timeout | force template timeout | execution terminates with timeout status |
| model-timeout | force model provider timeout | P11 evaluation errors are classified |
| duplicate-message | redeliver queue message | no duplicate execution or evidence |
| poison-message | publish unsupported schema version | message enters dead-letter without silent loss |
| delayed-message | delay queue delivery | scheduling delay is recorded |
| reordered-message | deliver out of order | state machine/CAS remains consistent |

## Required checks

- errors are classified
- bounded retry only
- no duplicate execution
- no duplicate evidence
- no cross-tenant leakage
- recovery resumes after dependency return
- production mode refuses fault injection

## P12-R execution discipline

`solve_p12_chaos.py --runtime --all` is the authoritative target set for Linux runtime acceptance. Targets backed only by static configuration are not marked as passed. If a target needs a live workload, NATS redelivery, or sandbox timeout injection and the runtime harness cannot perform it, the script returns a failed check with `dedicated_runtime_workload_required`.

Each target must be isolated and recovered before the next target. A passing runtime result must contain:

- `valid=true`
- `runtime=true`
- `runtime_not_claimed=false`
- `failed=0`
- `skipped=0`

Precondition failures are not skips. They are explicit failures that keep runtime unclaimed.
