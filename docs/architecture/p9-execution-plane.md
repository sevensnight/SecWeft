# P9 controlled validation execution plane

P9 extends the existing P0-P8 control plane without replacing the FastAPI, React/Vite, OpenAPI, TypeScript client, OIDC, PostgreSQL/SQLite, Redis, NATS, MinIO, Prometheus, OpenTelemetry, Docker Compose, or Helm architecture.

## Reused P0-P8 modules

- `ValidationPlanService`: plan draft, submit, approve/reject, immutable plan hash, and policy preflight.
- `PolicyService`: persisted policy decisions and enforced denial path.
- `ScopeService`: approved scope, expiry, DNS rebinding guard, target/port/protocol validation, and bounded HTTP probe.
- `EvidenceService`: evidence metadata, content scrubbing, trust level, and SHA-256 hash.
- `AuditService`: append-only audit log.
- Existing OpenAPI/shared-types/api-client generation chain and web-console routes.

## Controlled execution flow

```text
Validation Plan approved
→ POST /api/v1/validation-plans/{plan_id}/executions
→ Idempotency-Key checked
→ policy action validation.execute persisted
→ validation_executions row created as QUEUED
→ validation_queue_messages row created for validation.executions.requested
→ Worker leases message
→ Worker re-checks plan approval, tenant ownership, scope, and policy
→ Worker provisions sandbox metadata
→ Worker runs registered template only
→ Worker stores evidence metadata and SHA-256
→ Worker verifies assertions
→ SUCCEEDED / FAILED / exception status
→ human review persisted
```

The local deterministic test path uses the durable SQLite queue adapter. Production message protocol is modeled as NATS JetStream:

- stream: `VALIDATION_EXECUTIONS`
- subject: `validation.executions.requested`
- durable consumer: `validation-worker`
- message key: `execution_id`
- payload: `execution_id`, `tenant_id`, `plan_id`, `task_id`, `template_id`, `template_version`, `trace_id`, `sandbox_id`, `approval_id`, `policy_decision_id`
- delivery: at least once
- idempotency: execution state and queue message lease/token are database-backed

## State machine

Normal states:

```text
QUEUED
→ PROVISIONING
→ RUNNING
→ COLLECTING_EVIDENCE
→ VERIFYING
→ SUCCEEDED / FAILED / CANCELLED / EXPIRED
```

Exception states:

```text
POLICY_REJECTED
APPROVAL_REVOKED
SCOPE_INVALID
SANDBOX_FAILED
RESOURCE_EXCEEDED
EXECUTION_TIMEOUT
EVIDENCE_INCOMPLETE
```

## Database changes

SQLite schema and PostgreSQL migration `infrastructure/migrations/0007_p9_validation_execution_plane.up.sql` add:

- `validation_executions`
- `validation_execution_events`
- `validation_execution_evidence`
- `validation_queue_messages`

The rows persist `trace_id`, `execution_id`, `sandbox_id`, `approval_id`, `policy_decision_id`, queue state, evidence hash, artifact reference, and human review state.

## API additions

- `POST /api/v1/validation-plans/{plan_id}/executions`
- `GET /api/v1/validation-executions`
- `GET /api/v1/validation-executions/{execution_id}`
- `POST /api/v1/validation-executions/{execution_id}/cancel`
- `POST /api/v1/validation-executions/{execution_id}/retry`
- `GET /api/v1/validation-executions/{execution_id}/events`
- `GET /api/v1/validation-executions/{execution_id}/events/stream`
- `GET /api/v1/validation-executions/{execution_id}/evidence`
- `POST /api/v1/validation-executions/{execution_id}/reviews`
- `GET /api/v1/validation-templates`
- `GET /api/v1/validation-templates/{template_id}`

Creation returns `202 Accepted` and requires `Idempotency-Key`.

## Template registry

Current implemented templates:

- `http.response@1.0.0`: bounded `GET`/`HEAD` request against an approved HTTP target, status assertion, optional body substring assertion, standardized evidence JSON.
- `sbom.dependency-version@1.0.0`: reads fixed repository manifest and lock files, records dependency evidence hashes, and does not execute package manager commands.
- `local.training-lab@1.0.0`: validates the fixed local synthetic lab fixture and Dockerfile safety markers without starting arbitrary code.

Explicitly not implemented in this phase:

- arbitrary PoC upload
- arbitrary shell execution
- model-generated command execution

## Local execution caveat

The current local acceptance path proves API, durable queue, worker idempotency, HTTP template, evidence metadata/hash, and front-end visibility. It does not claim that NATS JetStream, Docker runtime sandbox, or MinIO upload were exercised unless those services are explicitly started and tested.
