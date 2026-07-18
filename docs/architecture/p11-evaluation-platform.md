# P11 Evaluation Platform Architecture

Target version: `2.11.0-p11`

P11 adds an auditable AI and workflow evaluation layer over the existing P2/P3/P4 model, policy, knowledge, agent, and audit capabilities plus the P9/P10 controlled execution and case lifecycle. It does not add validation templates, scanners, arbitrary PoC upload, arbitrary command execution, or a new sandbox path.

## Reused modules

- Model execution: existing Model Gateway is the only path for real model evaluation.
- Policy: existing policy service evaluates `evaluation.*` and `metric.definition.manage` actions.
- Audit: every governance write records an audit event.
- P9: controlled end-to-end evaluation may reference only approved validation executions and existing fixed templates.
- P10: remediation and case lifecycle outputs are evaluated as workflow artifacts, not as new execution capabilities.

## Aggregate boundaries

The P11 aggregate roots are:

- `EvaluationSuite`
- `EvaluationDataset`
- `EvaluationRun`
- `RegressionComparison`
- `PromotionDecision`

Tenant and project isolation are enforced on every lookup and write. The service layer depends on domain operations and repository-style database access; frontend/API code does not directly bypass the governance service.

## Minimum closed loop

```text
EvaluationDataset
-> EvaluationCase
-> baseline EvaluationRunVariant
-> candidate EvaluationRunVariant
-> EvaluationRun
-> ConfigurationSnapshot
-> EvaluationResult
-> MetricResult
-> RegressionComparison
-> GateResult
-> EvaluationReview
-> PromotionDecision
```

## Immutable snapshots

Every run stores immutable variant snapshots for:

- model configuration
- prompt template
- agent definition
- skill definition
- knowledge package
- retrieval configuration
- policy version
- workflow definition
- evaluation dataset
- metric definition

The run stores `configuration_hash`; each variant stores `config_hash`; each snapshot stores `snapshot_hash`. Hashes are SHA-256 over canonical JSON. Historical referenced objects may later change or be removed without changing the reproducibility record.

## Evaluation types

P11 supports:

- deterministic offline evaluation
- real model evaluation through the existing Model Gateway
- controlled end-to-end evaluation through existing P9/P10 flows
- human blind review

End-to-end evaluation is explicitly bounded to existing approved local training flows. P11 is not an exploit runner.

