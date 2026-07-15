# VulnLab platform Helm chart

This chart is a runnable P0 deployment boundary for the gateway, static web
console, and modular control plane. It deliberately keeps the control plane at
one replica because its compatibility runtime still owns SQLite state. The
gateway and console can scale independently.

Render without cluster access:

```sh
helm lint . --strict
helm template p0 . --namespace vulnlab > rendered.yaml
```

For a real deployment, build and publish the three images, provide their tags,
and create an Opaque Secret named `vulnlab-platform-secrets` with
`VULNLAB_ADMIN_KEY` and `VULNLAB_MASTER_KEY`. The master key must be a Fernet
key and credentials must come from the deployment secret manager, not a values
file.

The chart does not install PostgreSQL, Redis, NATS, MinIO, or a telemetry
backend. Production clusters should consume managed or separately operated
instances after the control-plane adapters are activated in later phases. The
local Compose model provides those integration dependencies for engineering.
