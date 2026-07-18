# P10 Case Lifecycle Architecture

P10 adds remediation verification and case management on top of the existing P9 controlled validation execution plane. It does not introduce new validation templates, arbitrary PoC upload, arbitrary shell execution, or a new runtime path.

The lifecycle is:

```text
vulnerability candidate
-> Vulnerability Case
-> initial validation
-> human confirmation
-> remediation proposal
-> remediation decision
-> remediation implementation record
-> Retest through P9 Validation Execution
-> before/after evidence comparison
-> human disposition
-> report
-> close
```

## Aggregation boundary

`VulnerabilityCase` is the aggregate root. The following records are tenant/project scoped children:

- `CaseFinding`
- `RemediationProposal`
- `RemediationDecision`
- `RemediationImplementation`
- `RetestRequest`
- `ValidationComparison`
- `CaseDisposition`
- `CaseReport`

Every write records a policy decision and an audit event. Versioned updates use optimistic locking.

## State machine

Allowed transitions:

```text
DRAFT -> TRIAGE
TRIAGE -> VALIDATION_PENDING
VALIDATION_PENDING -> VALIDATED / FALSE_POSITIVE / INCONCLUSIVE
VALIDATED -> REMEDIATION_PLANNED / ACCEPTED_RISK
REMEDIATION_PLANNED -> REMEDIATION_IN_PROGRESS / ACCEPTED_RISK
REMEDIATION_IN_PROGRESS -> RETEST_PENDING / ACCEPTED_RISK
RETEST_PENDING -> REMEDIATED / ACCEPTED_RISK / FALSE_POSITIVE / INCONCLUSIVE
REMEDIATED|ACCEPTED_RISK|FALSE_POSITIVE|INCONCLUSIVE -> CLOSED
```

Closed cases cannot be silently modified.

## Reuse of P9

Retest requests call the existing `ValidationExecutionService.create()` with the original plan/template. The P10 layer stores linkage only:

```text
case_id
finding_id
original_execution_id
remediation_implementation_id
retest_execution_id
```

The existing P9 queue, worker, sandbox, evidence, and review APIs remain responsible for controlled execution.
