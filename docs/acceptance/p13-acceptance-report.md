# P13 Acceptance Report

Target version: `2.13.0-p13`

## Implemented

- Release artifact registration with immutable digest validation.
- SBOM, provenance, signature, security scan, and license scan metadata.
- Release candidate freeze.
- Gate evaluation for development, integration, staging, and production.
- P12 authoritative runtime production gate.
- Human approval and creator/approver separation for production.
- Time-bounded release exceptions.
- Ordered environment promotion using the same digest.
- Deployment records, rollback records, drift detection, and compliance package generation.
- OpenAPI, shared types, API client, and web console release views.

## Runtime boundary

`solve_p13_baseline.py` is deterministic and reports `runtime=false` and `runtime_not_claimed=true`. It does not claim GitHub Actions isolated runtime success.

Only the P12-R isolated Linux workflow can produce authoritative runtime acceptance for P12 gates.

## Authoritative runtime gate result

The P13 production release gate is accepted by GitHub Actions isolated runtime evidence:

| Field | Value |
| --- | --- |
| GitHub Actions run ID | `30195998389` |
| Source commit | `59efe16144563f57033724c00ea70cfe895ba890` |
| Release gate result | `valid=true` |
| Runtime | `true` |
| Runtime not claimed | `false` |
| Critical gates failed | `0` |
| Failed | `0` |
| Skipped | `0` |
| Artifact manifest digest | `b3e93251400c8bbc54ce7472904a1202eada16c2b4a70a5fcddd1c8e55f66465` |

This records release-governance acceptance evidence only. It does not change the rule that deterministic local P13 checks cannot claim isolated runtime success.
