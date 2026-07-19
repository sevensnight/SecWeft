# P14 E2E Acceptance Matrix

`solve_p14_e2e.py` runs a deterministic local scenario through the control plane.

| Area | Covered by script | Runtime claim |
|---|---:|---:|
| User and RBAC | yes | no |
| Approved scope | yes | no |
| Task creation | yes | no |
| Validation plan submit/review | yes | no |
| P9 local training template execution | yes | deterministic only |
| Evidence review | yes | deterministic only |
| P10 case creation | yes | no |
| P13 artifact/candidate/gate/compliance | yes | no production promotion |
| P14 acceptance run | yes | no |
| P14 candidate delivery package | yes | no |
| P14 compliance mapping package | yes | no certification |
| Production readiness | fail-closed | no |

The script outputs a JSON `trace_chain` containing `trace_id`, `execution_id`, `acceptance_run_id`, `delivery_package_id`, and `policy_decision_id`.
