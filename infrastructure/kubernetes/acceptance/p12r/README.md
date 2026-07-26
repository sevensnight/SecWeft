# P12-R isolated runtime acceptance inputs

This directory contains repository-managed, non-secret inputs for the manual
GitHub Actions P12-R isolated runtime job.

The tracked `runtime-values.yaml` is safe to commit. It must not contain
passwords, API keys, access keys, tokens, production endpoints, localhost
endpoints, or customer assets.

The workflow generates run-scoped credentials at execution time, masks them,
writes them only to `work/p12r/private/`, creates the Kubernetes Secret in the
temporary namespace, and deletes the kind cluster during cleanup.
