# P10 Validation Matrix

| Area | Acceptance coverage |
| --- | --- |
| Case creation | `POST /vulnerability-cases`, idempotency, tenant/project metadata |
| State machine | Valid transitions, stale optimistic version rejection |
| Finding binding | Links accepted P9 execution/evidence to CaseFinding |
| Remediation proposal | Manual and AI proposal source handling |
| Remediation decision | Human approval, automated approval rejection |
| Implementation record | Approved decision to implementation linkage |
| Retest | Existing P9 Validation Execution is reused |
| Comparison | Before/after result and SHA-256 evidence metadata |
| Disposition | Human-confirmed disposition only |
| Report | Case report from case, evidence, comparison, disposition |
| Closure | Closed case rejects silent mutation |
| Isolation | Cross-tenant execution binding rejected |
| Project boundary | Cross-project finding binding rejected |
| P0-P9 compatibility | `solve_p9_baseline.py` remains part of full P10 gate |

Baseline command:

```powershell
.\.venv\Scripts\python.exe solve_p10_baseline.py --full
```

The deterministic P10 baseline does not run Docker/NATS/MinIO runtime acceptance. Those remain P9-H runtime responsibilities.
