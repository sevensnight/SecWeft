# P13 Release Governance Architecture

P13 adds a production release-governance control plane on top of the existing P0-P12 platform. It does not add vulnerability types, validation templates, scanner execution, PoC upload, or arbitrary command execution.

## Core flow

```text
ReleaseArtifact
→ SBOM / provenance / signature / scan records
→ ReleaseCandidate freeze
→ ReleaseGate evaluation
→ human approval / time-bounded exception
→ environment promotion
→ deployment record
→ drift / rollback / compliance package
```

## Immutability

Deployment identity is the artifact digest, not a mutable tag. Container artifacts must use:

```text
repository/name@sha256:<64 hex>
```

The release candidate freezes source commit, image digest, SBOM digest, provenance digest, signature digest, configuration hash, migration set, and Helm chart digest.

## Promotion order

Environments are ordered:

```text
development → integration → staging → production
```

The same frozen digest is promoted across environments. Rebuild-per-environment is rejected by design.

## Production boundary

Production promotion requires:

- evaluated gates with no unexcepted failures;
- P12 authoritative runtime acceptance, not readiness-only status;
- human approval by someone other than the release-candidate creator;
- policy decision and audit record.

If P12 authoritative runtime has not executed, production remains blocked.
