# P13 Signing and Promotion Boundaries

## Signing boundary

The control plane records signature verification results. It does not keep long-term signing private keys and does not sign artifacts during API requests.

Required production evidence:

- artifact digest equals the signed subject;
- signature identity matches the approved workflow identity;
- certificate issuer is trusted;
- provenance source repository and commit match the release candidate;
- builder workflow is recorded.

## Promotion boundary

Production promotion is fail-closed when:

- P12 authoritative runtime has not produced `RUNTIME_ACCEPTED`;
- a required gate failed without an active exception;
- approval is missing;
- the only approval is from the release-candidate creator;
- the artifact identity is mutable or digest mismatched.

Readiness-only evidence may support development, integration, or staging policy decisions, but it is not production runtime acceptance.
