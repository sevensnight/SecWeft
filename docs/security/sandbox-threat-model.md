# P9 sandbox threat model

## Assets protected

- Host filesystem and process namespace.
- Docker daemon and host Docker socket.
- Tenant data, task data, validation plan approvals, policy decisions, and evidence artifacts.
- Network boundaries outside the approved test scope.
- Audit integrity and evidence integrity.

## Threats

| Threat | Control |
|---|---|
| Model generates arbitrary shell | No shell template exists; request schemas reject extra `argv`; Worker executes registered templates only. |
| User uploads arbitrary PoC | No upload API exists for validation execution. |
| Approval revoked after queueing | Worker re-checks plan status before execution; result becomes `APPROVAL_REVOKED`. |
| Scope expires or changes | Worker re-runs `ScopeService` validation and DNS snapshot checks; result becomes `SCOPE_INVALID`. |
| Cross-tenant read | API object ownership checks return 404 for non-admin non-owner callers. |
| NATS duplicate delivery | Queue and execution state are persisted; terminal executions are acked without re-execution. |
| Sandbox breakout via root/privileged container | Required sandbox profile is non-root, non-privileged, no host network, no Docker socket, read-only rootfs, `no-new-privileges`, `cap-drop=ALL`. |
| Resource exhaustion | Sandbox policy requires CPU, memory, PID, and timeout limits; exception status is `RESOURCE_EXCEEDED` or `EXECUTION_TIMEOUT`. |
| Internet egress | Default policy is deny; only the approved current test network may be reachable. |
| Evidence tampering | Evidence metadata is in DB, artifact reference is immutable, and full content SHA-256 is persisted. |

## Required Docker sandbox profile

Production sandbox creation must enforce:

```text
--user non-root
--privileged=false
--network <approved-isolated-network-only>
--read-only
--cap-drop ALL
--security-opt no-new-privileges:true
--pids-limit 64
--memory 256m
--cpus 0.5
--tmpfs /tmp:rw,noexec,nosuid,size=32m
```

Forbidden mounts:

- `/var/run/docker.sock`
- host root filesystem
- host network namespace
- broad workspace directories unrelated to the execution

## Current implementation status

Implemented and tested locally:

- fixed template registry
- HTTP response, SBOM metadata, and fixed local lab validation templates
- schema-level rejection of arbitrary shell fields
- plan approval requirement
- Worker re-checks approval, scope, and policy
- evidence SHA-256
- durable DB queue idempotency
- cross-tenant API guard

Not claimed as locally executed:

- actual Docker container launch for validation template
- actual NATS JetStream delivery
- actual MinIO upload
- actual external egress firewall validation

Those are deployment/runtime validations and must be executed only when the corresponding services are configured.
