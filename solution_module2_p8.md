# Module 2 P8: Operations Readiness, Performance Smoke, and Release Gates

## Goal

P8 closes Module 2 with repeatable local acceptance gates for deployment readiness. It does not add new product capability; it verifies that the P1-P7 system can be checked consistently before handoff or deployment.

## Implemented scope

- Added `tools/p8/operational_readiness.py` for static Compose, Helm, secret-handling, healthcheck, and hardening checks.
- Added `tools/p8/perf_smoke.py` for a bounded in-process ASGI smoke test against the authorized API surface.
- Added `tests/test_p8_operational_readiness.py` to protect the P8 readiness and performance utilities.
- Added `solve_p8_baseline.py` as the deterministic P8 acceptance runner.
- Updated `Taskfile.yml`, `Makefile`, `infrastructure/scripts/test.ps1`, and `infrastructure/scripts/test.sh` so the standard command surface covers P0-P8 rather than stopping at P1.
- Updated historical P2-P5 baseline contract checks to validate compatibility floors instead of requiring the OpenAPI operation count to remain frozen at an earlier phase.

## Safety boundary

The P8 performance smoke test runs in-process with a temporary database and test credentials. It does not start Docker containers, contact external model providers, scan networks, probe assets, or execute validation/exploit actions.

The operational readiness check is static by default. Docker Compose and Helm rendering are only invoked by the full gate when the required local tools are installed.

## Validation

Quick P8 gate:

```powershell
.\.venv\Scripts\python.exe solve_p8_baseline.py
```

Full local gate:

```powershell
.\.venv\Scripts\python.exe solve_p8_baseline.py --full
```

Standard project entry points:

```powershell
task p8:check
task p8:check:full
make p8-check
make p8-check-full
powershell -NoProfile -ExecutionPolicy Bypass -File infrastructure\scripts\test.ps1 -Python .\.venv\Scripts\python.exe
```
