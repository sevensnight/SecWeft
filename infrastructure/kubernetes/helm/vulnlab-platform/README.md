# VulnLab platform Helm chart

This chart is the P12 Kubernetes deployment boundary for:

- API gateway and web console.
- Three-or-more FastAPI control-plane replicas.
- Three-or-more validation worker replicas.
- HPA, PDB, rolling updates, readiness/liveness separation, topology spreading, and anti-affinity.
- Backup CronJob and disabled-by-default restore Job.

The chart does not install PostgreSQL, NATS JetStream, MinIO, OIDC, Docker runtime, or telemetry backends for production. Production mode must receive those dependencies through managed services or separately operated in-cluster charts. Runtime secrets must be provided by `runtimeSecrets.existingSecret`; values files must not contain credentials.

The manual P12-R isolated GitHub runtime job is the exception for acceptance infrastructure only: it creates ephemeral PostgreSQL, NATS JetStream, MinIO, and training-lab resources inside a temporary kind namespace, generates run-scoped credentials, creates the `runtimeSecrets.existingSecret` Kubernetes Secret, and deletes the cluster during cleanup. Those credentials are not stored in Git, repository secrets, or uploaded artifacts.

Required secret keys include at least:

- `VULNLAB_ADMIN_KEY`
- `VULNLAB_MASTER_KEY`
- `DATABASE_URL`
- `VULNLAB_NATS_URL`
- `VULNLAB_MINIO_ENDPOINT`
- `VULNLAB_MINIO_ACCESS_KEY`
- `VULNLAB_MINIO_SECRET_KEY`

OIDC production deployments additionally require:

- `VULNLAB_OIDC_ISSUER`
- `VULNLAB_OIDC_AUDIENCE`
- `VULNLAB_OIDC_JWKS_URL`

Render and static validation:

```sh
helm lint infrastructure/kubernetes/helm/vulnlab-platform --strict
helm template p12 infrastructure/kubernetes/helm/vulnlab-platform --namespace vulnlab > rendered.yaml
```

Authoritative multi-replica validation is not `helm template`. Use `solve_p12_scale.py --runtime --kind-cluster <cluster>` or the Linux CI job added in P12 to install into kind/k3d, wait for rollouts, terminate one control-plane pod and one worker pod, and verify that queued validation executions complete exactly once without duplicate evidence.
