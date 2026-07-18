# P11 Evaluation Runbook

## Local deterministic mode

Use this mode for fast development and regression checks:

```powershell
.\.venv\Scripts\python.exe solve_p11_baseline.py
```

Expected summary:

```json
{
  "phase": "P11",
  "valid": true,
  "summary": {
    "failed": 0
  }
}
```

## Full local compatibility

Use this before committing:

```powershell
.\.venv\Scripts\python.exe solve_p11_baseline.py --full
```

This runs P11 checks plus P9/P10 compatibility, Python tests/lint, and workspace frontend/package checks.

## API flow

1. Create an evaluation suite.
2. Create a versioned evaluation dataset.
3. Add cases with explicit ground truth.
4. Create an evaluation run with baseline and candidate variants.
5. Inspect results, metrics, and failures.
6. Create a regression comparison.
7. Record a human review.
8. Submit a promotion decision.

Key write APIs accept `Idempotency-Key`. Promotion and rollback require a current optimistic `expected_version`.

## Troubleshooting

- If a promotion is blocked, inspect the latest regression comparison gate results.
- If a case is marked `GROUND_TRUTH_MISSING`, update the dataset by creating a new dataset version with explicit ground truth.
- If frontend typecheck fails after OpenAPI changes, regenerate shared types with `pnpm --filter @vulnlab/shared-types generate`.
- If runtime validation is needed, use the existing P9 runtime baseline; P11 does not introduce a new sandbox runtime.

