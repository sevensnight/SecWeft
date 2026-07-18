# P11 Acceptance Report

Target version: `2.11.0-p11`

## Implemented

- Evaluation Suite, Dataset, Case, Run, Variant, Result, Metric, Comparison, Review, Promotion Decision, and Configuration Snapshot models
- Explicit versioned ground truth with SHA-256 hashes
- Immutable run and variant configuration snapshots
- Deterministic offline evaluation
- Real model evaluation path through existing Model Gateway
- Controlled end-to-end evaluation boundary through existing P9/P10 flows
- Quality, security, cost, latency, and stability metrics
- Candidate-vs-baseline regression comparison
- Configurable regression gates
- Human-only promotion states and separation-of-duties checks
- P11 API routes and OpenAPI/shared-types synchronization
- `/evaluations` and `/evaluations/:runId` frontend surfaces
- PostgreSQL migration `0011_p11_evaluation_governance`
- SQLite deterministic compatibility schema
- `solve_p11_baseline.py`

## Not introduced

- No P12 work
- No new validation templates
- No new scanners
- No arbitrary PoC upload
- No arbitrary command or shell execution
- No replacement of the P9 sandbox/runtime path

## Required acceptance

```powershell
.\.venv\Scripts\python.exe solve_p11_baseline.py --full
```

Expected result:

```json
{
  "phase": "P11",
  "valid": true,
  "summary": {
    "failed": 0
  }
}
```

