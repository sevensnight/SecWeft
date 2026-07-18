# P11 Evaluation Test Matrix

P11 acceptance is split into deterministic local governance checks and existing P9/P10 runtime compatibility checks. It does not require new sandbox/runtime behavior beyond what P9-R/P9-H already validate.

## Deterministic acceptance

Run:

```powershell
.\.venv\Scripts\python.exe solve_p11_baseline.py
```

Required coverage:

| Area | Coverage |
| --- | --- |
| suite | create/list/get with policy and audit |
| dataset | versioned dataset creation and immutable published versions |
| case | explicit ground truth, scoring methods, tool boundaries |
| run | baseline/candidate variants and immutable config snapshots |
| scoring | deterministic result generation and missing ground truth marking |
| metrics | quality, security, cost, latency, and stability metrics |
| comparison | improved/regressed/new/resolved failures and gate status |
| review | human review records with tenant/project isolation |
| promotion | gate-aware approval/rejection/promotion/rollback decisions |
| API contract | OpenAPI, generated shared types, and frontend route typecheck |
| persistence | SQLite deterministic schema plus PostgreSQL migration guard |

## Negative tests

Required negative coverage:

- published dataset cannot be silently modified
- LLM judge cannot be the sole scoring method
- gate failure blocks promotion
- evaluation creator cannot independently approve production promotion
- cross-tenant data cannot be referenced
- cross-project data cannot be referenced
- missing ground truth is explicitly marked
- stale optimistic version is rejected
- duplicate `Idempotency-Key` does not duplicate writes
- P9 fixed templates remain unchanged
- no arbitrary shell/subprocess execution is introduced

## Full compatibility

Run:

```powershell
.\.venv\Scripts\python.exe solve_p11_baseline.py --full
```

The full profile additionally runs P9/P10 deterministic baselines, Python compile/lint/tests, and workspace typecheck/test/build.

