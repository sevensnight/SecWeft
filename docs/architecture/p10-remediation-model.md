# P10 Remediation Model

P10 separates remediation proposal, approval, implementation, and verification.

## Proposal sources

Allowed proposal sources:

- `AI_GENERATED`
- `KNOWLEDGE_BASE`
- `VENDOR_ADVISORY`
- `MANUAL`

Proposals persist knowledge references, optional model invocation ID, and provenance metadata. AI-generated proposals remain `PROPOSED` until an authorized human actor records a decision.

## Decisions

Decision values:

- `APPROVED`
- `REJECTED`
- `CHANGES_REQUESTED`

Automated decisions cannot approve remediation. High-risk proposals cannot be self-approved by the same actor who submitted them.

## Implementation records

Implementation records are audit artifacts, not deployment automation. They capture:

- approved decision ID
- implementation reference
- description
- implementer
- implemented timestamp
- verification notes

After implementation is recorded, P10 may request a P9 retest.

## Comparison result

Comparison values:

- `REMEDIATED`
- `PARTIALLY_REMEDIATED`
- `NOT_REMEDIATED`
- `REGRESSION`
- `INCONCLUSIVE`

Comparison includes execution statuses, success condition diff, observed response/component diff, evidence SHA-256 values, risk-level change, residual risk, and a system recommendation. Final disposition still requires human confirmation.
