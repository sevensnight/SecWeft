# Linux Runtime Matrix

Linux CI is the authoritative P9-H runtime environment. Windows Docker Desktop remains a development runtime signal.

| Check | Linux authority |
|---|---|
| PostgreSQL migrations/outbox/lease | `solve_p9_runtime.py` and `solve_p9_hardening.py` |
| NATS JetStream publish/consume | `solve_p9_runtime.py` |
| Worker idempotency and redelivery behavior | `solve_p9_runtime.py` plus P9-H PostgreSQL idempotency test |
| Docker sandbox creation/destruction | `solve_p9_runtime.py` |
| default internet egress blocked | runtime behavior in Docker sandbox |
| authorized lab network allowed | runtime behavior against local training lab |
| non-root / non-privileged / no host network | Docker backend runtime plus static threat model |
| read-only root filesystem | Docker backend runtime config and CI execution |
| memory limit kill | `p9r_docker_sandbox_memory_limit_kill` |
| timeout termination | `p9r_docker_sandbox_timeout_cleanup` |
| MinIO upload/download hash verification | `p9r_nats_worker_docker_minio_internal_network` |
| container and temporary resource cleanup | runtime runner cleanup checks |

The CI job `p9h-linux-runtime` runs on `ubuntu-24.04` and executes `python solve_p9_hardening.py`.
