# P12 Capacity and Backpressure Model

P12 capacity controls are explicit guardrails around validation execution creation and worker scheduling.

## Limits

- `VULNLAB_P12_QUEUE_DEPTH_THRESHOLD`
- `VULNLAB_P12_MAX_PENDING_EXECUTIONS`
- `VULNLAB_P12_GLOBAL_CONCURRENCY_LIMIT`
- `VULNLAB_P12_TENANT_CONCURRENCY_LIMIT`
- `VULNLAB_P12_PROJECT_CONCURRENCY_LIMIT`
- `VULNLAB_P12_MODEL_CONCURRENCY_LIMIT`
- `VULNLAB_P12_SANDBOX_CAPACITY_LIMIT`
- `VULNLAB_P12_API_RATE_LIMIT_PER_MINUTE`
- `VULNLAB_P12_MINIO_UPLOAD_CONCURRENCY_LIMIT`
- `VULNLAB_DATABASE_POOL_MAX_SIZE`

## Rejection semantics

- `429 rate_limited`: API or provider rate limit.
- `429 quota_exceeded`: global, tenant, project, model, or sandbox quota.
- `503 dependency_unavailable`: PostgreSQL, NATS, MinIO, or sandbox dependency unavailable.
- `503 queue_saturated`: queue depth threshold or maximum pending executions reached.

Priority affects ordering only after scope, approval, policy, and quota checks pass. Priority cannot bypass P9 authorization, P10 human remediation decisions, or P11 promotion gates.

## Fairness

The SQLite development queue and P9 durable queue adapter prefer tenants with lower leased pressure, then priority, then creation time. Production fairness must be validated against JetStream redelivery and worker lease state in Linux CI.

## Bounded retry

Database and transport retries must have:

- maximum attempt count
- backoff
- visible error classification
- dead-letter status for poison messages
- manual replay through operator runbook

No P12 component may retry forever.
