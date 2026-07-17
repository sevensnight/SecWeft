# P8 acceptance criteria

P8 is accepted when all of the following pass locally:

1. Repository layout contains the P8 readiness tools, tests, documentation, and command entry points.
2. Compose and Helm static configuration enforce expected service hardening:
   - control-plane services use read-only filesystems where applicable;
   - Linux capabilities are dropped;
   - healthchecks are declared;
   - the backend network remains internal;
   - the gateway binds to loopback by default;
   - legacy execution is disabled by default.
3. Secret examples remain template-only, local platform env files remain untracked, and generated backup output is not committed.
4. In-process API performance smoke completes within the P95 latency budget.
5. The OpenAPI operation count remains stable at 62 for P8.
6. `Taskfile.yml`, `Makefile`, and shared test scripts expose P8 checks.
7. Historical P2-P5 baseline checks remain forward-compatible with the completed P8 contract.
8. Full mode completes all Python and pnpm quality gates, with Docker/Helm gates executed when those tools are installed.

Run:

```powershell
.\.venv\Scripts\python.exe solve_p8_baseline.py
.\.venv\Scripts\python.exe solve_p8_baseline.py --full
```
