# P6 acceptance criteria

P6 is accepted when validation plans are auditable, policy-preflighted, and reviewable without introducing execution capability.

## Runtime criteria

- `validation_plans` exists and stores plan JSON, plan hash, policy decision ids, lifecycle state, and review metadata.
- Creating a validation plan preflights every step through `PolicyService.evaluate`.
- Out-of-scope validation steps are denied before a plan is persisted.
- Plans can be submitted only from `draft`.
- Plans can be approved or rejected only from `submitted`.
- Review requires administrator permissions.
- Approval does not create task executions or call sandbox/asset-probe runtime execution.

## Contract criteria

- OpenAPI version is `1.6.0-p6`.
- Operation count is 62.
- Validation schemas are present: `ValidationProbeStep`, `ValidationPlanCreate`, `ValidationPlanReview`, and `ValidationPlan`.
- Contract exposes validation-plan CRUD/review paths only; it does not expose validation-run execution paths.

## Validation commands

```powershell
.\.venv\Scripts\python.exe solve_p6_baseline.py
.\.venv\Scripts\python.exe -m pytest tests\test_p6_validation_plans.py tests\test_p5_policy.py tests\contract\test_openapi_contract.py -q
```

Full gate:

```powershell
.\.venv\Scripts\python.exe solve_p6_baseline.py --full
```
