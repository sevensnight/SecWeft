# P5 acceptance criteria

P5 is accepted when policy decisions are explicit, persisted, and enforced at the compatibility execution boundary.

## Runtime criteria

- `policy_decisions` exists and stores every policy evaluation.
- `/api/v1/policies/evaluate` returns a persisted decision and policy hash.
- Destructive requests are denied by policy.
- Task execution requests require current task approval.
- Scope-bound actions revalidate current scope.
- Sandbox argv is prechecked before runtime execution.
- Legacy disabled execution endpoints still return 503 and write deny decisions.

## Validation commands

```powershell
.\.venv\Scripts\python.exe solve_p5_baseline.py
.\.venv\Scripts\python.exe -m pytest tests\test_p5_policy.py tests\test_p0_safety.py tests\test_security.py::test_sandbox_is_not_a_generic_shell tests\contract\test_openapi_contract.py -q
```

Full gate:

```powershell
.\.venv\Scripts\python.exe solve_p5_baseline.py --full
```
