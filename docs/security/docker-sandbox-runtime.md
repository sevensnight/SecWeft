# Docker sandbox runtime security model

P9-R Docker sandboxing exists to run only registered validation templates. It is not a general command runner and must not execute model-generated shell, uploaded PoC code, or user-supplied entrypoints.

## Security boundary

The worker may create containers through `DockerSandboxBackend`. The sandbox container must not receive:

- host network
- privileged mode
- Docker socket
- writable root filesystem
- root user
- Linux capabilities
- unbounded CPU, memory, PID count, or runtime

## Current Docker run controls

`DockerSandboxBackend` applies:

- `--user 65534:65534`
- `--privileged=false` by omission
- `--network {configured network}`, with `host` rejected by configuration
- `--read-only`
- `--cap-drop ALL`
- `--security-opt no-new-privileges:true`
- `--pids-limit`
- `--memory`
- `--cpus`
- bounded timeout with cleanup via `docker rm -f`
- `--tmpfs /tmp:rw,noexec,nosuid,size=32m`

The HTTP response template uses a fixed Python entrypoint embedded by the application and passes a JSON payload as data. There is no shell interpolation and no user-controlled command string.

## Network policy

Default target runtime should use an isolated authorized lab network. `host` networking is rejected. For Windows Docker Desktop local acceptance, `host.docker.internal` may be enabled with `VULNLAB_VALIDATION_SANDBOX_ADD_HOST_GATEWAY=true` to reach a local test server; this is a development exception and not the production network model.

Runtime egress blocking must be validated by behavior, not configuration inspection. The current Windows run has not completed that test. Linux CI or a Linux host should be treated as authoritative for network isolation.

## Residual risks

| Risk | Current control | Required runtime proof |
|---|---|---|
| Docker daemon exposure | sandbox container receives no Docker socket | inspect created sandbox container mounts |
| Internet egress | configured isolated network; host network rejected | runtime outbound connection attempt must fail |
| Resource exhaustion | CPU/memory/PID/timeout flags | runtime memory/timeout tests must terminate container |
| Container residue | timeout cleanup and normal cleanup paths | runtime check must show container removed |
| Template confusion | fixed template registry and schema validation | negative test with unknown template and `argv` payload |

## Non-goals

P9-R does not add exploitation templates, arbitrary PoC uploads, shell execution, reverse shells, credential access, persistence, or scope expansion.
