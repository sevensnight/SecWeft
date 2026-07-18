# P10 Human Decision Boundaries

P10 allows the system to organize evidence and generate recommendations, but it does not let generated content close the loop by itself.

## Hard boundaries

- AI-generated remediation proposals cannot approve themselves.
- Automated decisions cannot set `APPROVED`.
- High-risk remediation cannot be approved by the same principal that submitted the proposal.
- `REMEDIATED`, `ACCEPTED_RISK`, `FALSE_POSITIVE`, and `INCONCLUSIVE` dispositions require `human_confirmed=true`.
- Closed cases cannot be modified without reopening support, which P10 intentionally does not implement.
- Retest execution is delegated only to the P9 controlled execution plane.
- No arbitrary shell or PoC execution is introduced.

## Evidence boundary

Evidence comparison is advisory until human disposition. Incomplete evidence can produce only `INCONCLUSIVE` and cannot be used to mark a case remediated.

## Audit boundary

All write actions record policy decisions and append audit events. Relevant actions include:

```text
case.create
case.update
case.confirm
case.disposition
remediation.propose
remediation.approve
remediation.implement
validation.retest
comparison.review
case.close
report.generate
```
