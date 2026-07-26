# P14 Final Acceptance Report

Version: `2.14.0-p14`

Status: enterprise acceptance and authoritative isolated runtime accepted.

Production readiness: accepted by the GitHub Actions isolated Linux runtime and P14 production readiness gate.

Current invariant:

```json
{
  "runtime": true,
  "runtime_not_claimed": false,
  "production_ready": true
}
```

## Authoritative runtime evidence

| Field | Value |
| --- | --- |
| GitHub Actions run ID | `30195998389` |
| Workflow event | `workflow_dispatch` |
| Source commit | `59efe16144563f57033724c00ea70cfe895ba890` |
| Runtime start | `2026-07-26T09:11:23Z` |
| Runtime end | `2026-07-26T09:37:56Z` |
| Runner OS | `ubuntu-24.04` / `Linux-6.17.0-1020-azure-x86_64-with-glibc2.39` |
| Docker | `28.0.4` |
| kind | `v0.27.0` |
| Kubernetes | `v1.32.2` |
| Helm | `v3.17.3` |
| Control Plane replicas | desired `3`, available `3`, ready `3` |
| Worker replicas | desired `3`, available `3`, ready `3` |
| RPO target | `15` minutes |
| RTO target | `60` minutes |
| Backup drill elapsed | `614 ms` |
| Restore drill elapsed | `5003 ms` |
| Runtime artifact zip digest | `d0bb0769c16f4721fb9d96d6c0e7a25ad3e2503296a11cfcd55afbcf25cb9273` |
| Artifact manifest digest | `b3e93251400c8bbc54ce7472904a1202eada16c2b4a70a5fcddd1c8e55f66465` |
| Helm chart digest | `b1b05f65d98e9f1d588ca92b599e9286edf098b6a925d0700e2e684a0c611933` |
| Rendered manifest digest | `933682cc02e3c706e212dcfee46e30c492e8145bb917d5bc4266813215dbb536` |

Image IDs built from the source commit and loaded into the isolated kind cluster:

| Image | ID |
| --- | --- |
| `vulnlab/control-plane:p12r-59efe16144563f57033724c00ea70cfe895ba890` | `sha256:7aabcb31d3379cfc098ec7578e8f1d782dc7c30e5a4eb3acac3b8417f467892c` |
| `vulnlab/api-gateway:p12r-59efe16144563f57033724c00ea70cfe895ba890` | `sha256:13b9e73d1e6609c35b930d4084dfc070cd6b57c69217bddf5df51e9cf70f43fe` |
| `vulnlab/web-console:p12r-59efe16144563f57033724c00ea70cfe895ba890` | `sha256:3de89cb895894c6efaf3bba45fe110c177aa8fc411671ad76ae55d3efd6beac8` |
| `vulnlab/local-training-lab:p12r-59efe16144563f57033724c00ea70cfe895ba890` | `sha256:95595ba54a34f7c84082e41bcf3304509cc6add2949684fb382e784a98dcab3c` |

Runtime result:

```json
{
  "valid": true,
  "runtime": true,
  "runtime_not_claimed": false,
  "failed": 0,
  "skipped": 0,
  "critical_gates_failed": 0,
  "production_ready": true
}
```

Validated artifacts:

- `environment-fingerprint.json`
- `scale-runtime-result.json`
- `dr-backup-result.json`
- `dr-restore-result.json`
- `chaos-runtime-result.json`
- `evidence-consistency-result.json`
- `rpo-rto-result.json`
- `release-gate-result.json`
- `production-readiness-result.json`
- `artifact-manifest.json`
- P9-P14 baseline result JSON files

All required JSON artifacts parsed successfully, used `source_commit=59efe16144563f57033724c00ea70cfe895ba890`, reported `failed=0` and `skipped=0`, matched the artifact manifest SHA-256 entries, and passed the runtime secret scan.

P14 completed:

- requirement traceability matrix;
- final deterministic E2E script;
- upgrade/rollback deterministic checks;
- data governance metadata flows;
- secret lifecycle evidence posture;
- enterprise delivery package generation;
- compliance evidence mapping;
- final production readiness gate.

Control mapping is not certification.
