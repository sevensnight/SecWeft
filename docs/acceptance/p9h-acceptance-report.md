# P9-H Acceptance Report

Target version: `2.9.1-p9h`

## Completed scope

- `ControlPlaneRepository` protocol
- SQLite deterministic adapter retained
- PostgreSQL production adapter added
- Production startup rejects SQLite repository backend
- Real PostgreSQL API integration tests
- Real PostgreSQL concurrency, FK, unique, JSONB, sorting, race, isolation, and audit checks
- Linux CI hardening job
- `solve_p9_hardening.py`

## Non-goals

- No P10 work
- No new validation templates
- No arbitrary PoC upload
- No arbitrary shell execution
- No new front-end routes

## Acceptance commands

```bash
python solve_p9_baseline.py --full
python solve_p9_runtime.py
python solve_p9_hardening.py
python -m pytest -q -rs
python -m mypy apps/control-plane/src
python -m ruff check .
pnpm typecheck
pnpm test
pnpm build
```

The final local run results must be recorded in the implementation handoff. Linux CI remains the authoritative network-isolation verdict.

## Local acceptance on Windows Docker Desktop

Recorded on 2026-07-18:

| Command | Result |
|---|---|
| `python solve_p9_baseline.py --full` | 12 passed, 0 skipped, 0 failed |
| `python solve_p9_runtime.py` | 4 passed, 0 failed |
| `python solve_p9_hardening.py` | 9 passed, 0 skipped, 0 failed |
| `python -m pytest -q -rs` | passed, no skip output |
| `python -m mypy apps/control-plane/src` | passed |
| `python -m ruff check .` | passed |
| `pnpm build` | passed |
