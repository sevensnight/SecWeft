# Module 2 P7: Enterprise Web Console

## Goal

P7 turns the stabilized P1-P6 backend contract into a usable enterprise console. It adds route-level pages for model management, Agent/Skill governance, knowledge retrieval, authorized asset visibility, non-executing validation plans, sandbox execution records, policy preflight, audit, reports, tasks, access, and system status.

## Implemented scope

- Added a central P7 navigation catalog and route-level lazy loading for all enterprise console domains.
- Expanded the generated API-client facade for model gateway, Agent/Skill, RAG, policy, validation plans, task executions, evidence, and audit endpoints.
- Added data-backed pages:
  - Model Management
  - Agent / Skill Management
  - Knowledge Base
  - Authorized Assets
  - Validation Center
  - Sandbox Center
  - Policy Review
  - Audit Center
  - Report Center
- Fixed user-facing text in common loading/error/API-key components and existing task/system/dashboard pages.
- Added a navigation regression test to protect the P7 route surface.

## Safety boundary

P7 does not introduce execution capability. The console does not call task dispatch, asset probe, sandbox run, validation-run, or exploit endpoints. Validation-plan approval remains a ledger state change only. Policy evaluation from the UI only creates an auditable policy decision and does not grant runtime permission.

## Validation

```powershell
.\.venv\Scripts\python.exe solve_p7_baseline.py
.\.venv\Scripts\python.exe solve_p7_baseline.py --full
```

Frontend-specific checks:

```powershell
pnpm --filter @vulnlab/web-console lint
pnpm --filter @vulnlab/web-console typecheck
pnpm --filter @vulnlab/web-console test
pnpm --filter @vulnlab/web-console build
```
