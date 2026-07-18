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
