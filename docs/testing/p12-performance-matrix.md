# P12 Performance and Capacity Matrix

P12 performance testing must exercise business paths, not only health checks.

## Profiles

| Profile | Purpose | Expected result |
| --- | --- | --- |
| Small | developer and PR sanity | all requests pass, queue drains |
| Medium | expected operational load | p95/p99 recorded, no duplicate execution |
| Stress | bounded failure | 429/503 responses appear, no data loss, recovery continues |

## Required paths

| Area | Required measurement |
| --- | --- |
| API reads | throughput, p50, p95, p99, error rate |
| API writes | idempotency conflicts, latency, error classification |
| task creation | tenant isolation and audit latency |
| execution creation | approval/policy/quota gate latency |
| outbox publish | queue wait and publish attempts |
| NATS consume | redelivery, ack timeout, backlog recovery |
| worker scheduling | scheduling delay and lease recovery |
| event ingestion | event write latency |
| evidence metadata | PostgreSQL write latency and hash coverage |
| MinIO upload/download | throughput, hash verification, error rate |
| case list/detail | P10 compatibility latency |
| evaluation run creation | P11 gate latency |
| audit queries | pagination latency |

## Baselines

- `solve_p12_baseline.py`: deterministic local correctness and static capacity guards.
- `solve_p12_scale.py --runtime`: Linux/kind/k3d multi-replica rollout and recovery.
- Runtime load tools must target isolated lab endpoints only; stress tests must not connect to real internet targets.

## P12-R runtime acceptance gate

`solve_p12_scale.py --runtime` is a real runtime gate. It must not be satisfied by Helm rendering alone.

Required runtime markers:

- `ENVIRONMENT=test`
- `P12R_RUNTIME_ENV=isolated`
- `P12R_TEST_CLUSTER_MARKER=isolated-runtime`
- Linux kind or k3d available on PATH
- active `kubectl` context pointing at the isolated test cluster
- runtime values file containing PostgreSQL, Redis, NATS JetStream, MinIO, gateway, telemetry, and local authorized training-lab configuration

The scale gate records the Linux distribution, Docker, kind/k3d, Kubernetes, Helm, start/end time, replica counts, HPA/PDB presence, and termination-recovery probes. If any precondition is missing, the result is a failed runtime precondition and `runtime_not_claimed=true`.

Required runtime behavior:

- at least 3 control-plane pods available
- at least 3 validation-worker pods available
- HPA objects present for scalable components
- PDB objects present for disruption boundaries
- topology spread rendered and honored by the cluster scheduler where enough nodes exist
- deleting one control-plane pod does not stop rollout recovery
- deleting one validation-worker pod does not produce duplicate effective execution or duplicate evidence
- overload responses remain explicit: `429 rate_limited`, `429 quota_exceeded`, `503 queue_saturated`, or `503 dependency_unavailable`
