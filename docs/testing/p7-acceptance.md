# P7 acceptance criteria

P7 is accepted when the frontend exposes the enterprise console domains through type-safe, code-split routes without adding runtime execution shortcuts.

## Runtime criteria

- P7 routes are registered and visible in navigation.
- Route modules are lazy-loaded.
- API calls use the generated OpenAPI client through the shared facade.
- Model, Agent/Skill, Knowledge, Asset, Validation, Sandbox, Policy, Audit, Report, Task, Access, and System views are present.
- Validation center supports creating, submitting, and reviewing non-executing validation plans.
- Policy page supports auditable policy preflight.
- Sandbox and report pages are read-only over task execution and evidence ledgers.

## Safety criteria

- No frontend call dispatches task execution.
- No frontend call invokes `/assets/probe`, `/sandbox/runs`, `/validation-runs`, or exploit endpoints.
- High-risk controls remain backend-gated by scope, policy, approval, and audit.

## Validation commands

```powershell
.\.venv\Scripts\python.exe solve_p7_baseline.py
pnpm --filter @vulnlab/web-console lint
pnpm --filter @vulnlab/web-console typecheck
pnpm --filter @vulnlab/web-console test
pnpm --filter @vulnlab/web-console build
```

Full gate:

```powershell
.\.venv\Scripts\python.exe solve_p7_baseline.py --full
```
