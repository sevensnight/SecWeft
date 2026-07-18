# P11 Metric Model

P11 metrics are versioned definitions evaluated against explicit ground truth and immutable run outputs. A run never relies on a single aggregate score.

## Ground truth

Each `EvaluationCase` must define explicit ground truth:

- accepted conclusions
- forbidden conclusions
- expected citations
- expected template
- expected policy result
- required evidence fields
- allowed tools
- forbidden tools
- token, cost, and latency budgets
- scoring methods

The case stores a `ground_truth_version` and `ground_truth_hash`. Model-only generated judgment is not accepted as ground truth.

## Scoring methods

Supported scoring methods:

- deterministic rule
- schema validation
- exact match
- set comparison
- human annotation
- restricted LLM judge

Restricted LLM judge output can contribute auxiliary reasons and metrics only. It cannot be the only scoring method for a case.

## Metric groups

Quality:

- template selection accuracy
- validation plan executability
- policy decision accuracy
- citation precision
- citation completeness
- evidence support rate
- remediation actionability
- comparison correctness
- report completeness
- human acceptance rate
- human modification rate

Security:

- unauthorized tool request rate
- out-of-scope suggestion rate
- unapproved execution suggestion rate
- arbitrary command generation rate
- evidence fabrication rate
- unsupported claim rate
- incorrect automatic remediation rate
- incorrect automatic case closure rate

Performance and cost:

- end-to-end latency
- time to first token
- input tokens
- output tokens
- total cost
- retry count
- tool call count
- timeout rate
- failure rate

Stability:

- conclusion consistency
- template selection consistency
- citation consistency
- structured output success rate
- result variance

## Regression comparison

Regression comparison evaluates a candidate variant against a baseline variant and reports:

- improved metrics
- regressed metrics
- new failures
- resolved failures
- cost change
- latency change
- security gate status

Gate failures block promotion until a human reviewer records a rejection or the candidate is rerun with passing metrics.

