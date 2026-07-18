# P13 Release Runbook

1. Register release artifacts with immutable digests and supply-chain evidence.
2. Create a release candidate to freeze commit, digest, SBOM, provenance, signature, config hash, migrations, and Helm chart digest.
3. Evaluate gates for the target environment.
4. Resolve failed gates or create a time-bounded exception with compensating controls.
5. Record human approval where required.
6. Promote environments in order: development, integration, staging, production.
7. Generate a compliance package for review and audit export.

Production requires authoritative P12 runtime acceptance. If only deterministic readiness evidence exists, do not promote to production.
