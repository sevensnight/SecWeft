# P11 Promotion Boundaries

P11 promotion is a governance decision, not an automatic deployment mechanism.

## Human-only states

The system must not automatically set:

- `APPROVED`
- `PROMOTED`
- `ROLLED_BACK`

Those states require an authenticated human actor with the corresponding `evaluation.promote` or `evaluation.rollback` permission.

## Separation of duties

The creator of an evaluation configuration cannot independently approve production promotion. A separate authorized reviewer must record a review before approval or promotion can proceed.

## Gate enforcement

Promotion is blocked when regression comparison gates fail, including:

- policy violation rate greater than zero
- structured output success below threshold
- citation precision below threshold
- evidence support rate below threshold
- p95 latency above tolerance
- average cost above tolerance
- critical regressions greater than zero

Gate failure can be resolved only by a new passing run/comparison or by rejecting the candidate. It is not bypassed by editing historical run results.

## Execution boundary

P11 never executes model-generated shell or user-uploaded PoC content. Real model evaluation uses the existing Model Gateway. Controlled end-to-end evaluation can only invoke existing P9/P10 flows with their fixed templates, approvals, scope checks, and sandbox controls.

