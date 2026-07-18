# P12 Chaos and Failure-Injection Matrix

Fault injection is allowed only in isolated test environments. `solve_p12_chaos.py --runtime` refuses production mode and requires `VULNLAB_P12_CHAOS_ACK=isolated-chaos`.

| Target | Injection | Expected invariant |
| --- | --- | --- |
| control-plane | delete one pod | requests continue through remaining replicas |
| validation-worker | delete one pod | lease expires or work completes exactly once |
| nats | pause or restart service | publisher retry is bounded, backlog recovers |
| postgres | pause or restart service | retry is bounded, no silent SQLite fallback |
| minio | pause or restart service | evidence upload reports dependency failure or recovers |
| sandbox-timeout | force template timeout | execution terminates with timeout status |
| model-timeout | force model provider timeout | P11 evaluation errors are classified |
| duplicate-message | redeliver queue message | no duplicate execution or evidence |
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
