# P13 Supply Chain Security

P13 records supply-chain evidence without running scanners or signing tools from the API path.

## Evidence records

- SBOMDocument: format, generator, generated_at, artifact digest, document digest, component count, license summary, vulnerability summary.
- ProvenanceStatement: subject digest, source repository, source commit, builder workflow, statement digest, predicate type, verification status.
- SignatureRecord: signature digest, identity, certificate issuer, verification status.
- SecurityScanResult: scanner, severity summary, critical/high counts, unresolved critical marker.
- LicenseScanResult: scanner, license summary, prohibited licenses, pass/fail.

## Sigstore/SLSA compatibility

The data model is compatible with Cosign/Sigstore/SLSA/OIDC keyless verification. Local development may record test verification results, but no long-term signing private key is stored in the repository.

Production policy verifies the recorded digest, signature identity, certificate issuer, provenance subject, source repository, source commit, and builder workflow.

## Non-goals

P13 does not execute scanners, upload PoC artifacts, generate exploit code, or run arbitrary shell from release APIs.
