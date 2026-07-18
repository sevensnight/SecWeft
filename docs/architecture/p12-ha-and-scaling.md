# P12 High Availability and Horizontal Scaling

P12 adds availability, scaling, overload, evidence-consistency, backup, and disaster-recovery controls around the existing P0-P11 platform. It does not add vulnerability types, scanners, validation templates, arbitrary PoC upload, shell execution, or new business domains.

## Reused authoritative state

- PostgreSQL remains the production repository.
- NATS JetStream remains the validation execution transport.
- MinIO remains the evidence object store.
- DockerSandboxBackend remains the controlled sandbox runtime from P9-R.
- P10/P11 human decision boundaries remain unchanged.

SQLite, in-process queue/sandbox, and filesystem evidence stores remain deterministic development adapters only. Production configuration fails startup if those adapters are selected.

## Control-plane replicas

FastAPI replicas share PostgreSQL, NATS, MinIO, OIDC, and telemetry. The P12 contract exposes `/api/v1/system/resilience` and `/api/v1/system/resilience/evidence-consistency/check`; liveness is `/live` and readiness is `/ready`.

Multi-replica risks and mitigations:

- Idempotency-Key races are resolved through repository uniqueness and transactions.
- Optimistic locking remains repository-backed.
- Local disk is not authoritative in production.
- SSE resume uses `Last-Event-ID`; sticky sessions are not a correctness requirement.
- Service instances are reported through `operational_service_instances`.

## Worker replicas

Validation workers continue to use P9 lease/CAS semantics and durable queue state. P12 adds heartbeat reporting and fair queue leasing pressure. Duplicate NATS delivery or worker restarts must not duplicate execution outcome or evidence metadata.

## Kubernetes delivery

The Helm chart defaults to:

- control-plane min replicas: 3
- validation-worker min replicas: 3
- HPA for gateway, console, control plane, and worker
- PDB for gateway, console, control plane, and worker
- rolling updates
- topology spread constraints and anti-affinity
- backup CronJob
- restore Job disabled by default

Real cluster validation must use kind/k3d or Linux CI. `helm template` is only a static guard.
