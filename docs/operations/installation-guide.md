# Installation Guide

Production installation requires:

- PostgreSQL repository backend
- NATS JetStream validation queue
- MinIO evidence store
- Docker sandbox backend
- OIDC authentication
- Helm or Docker Compose deployment configuration

Development and deterministic baseline mode may use SQLite, in-process sandbox, and filesystem evidence store. Production mode must not silently fall back to those adapters.

Run deterministic validation:

```powershell
.\.venv\Scripts\python.exe solve_p14_baseline.py
```

Run full local gates:

```powershell
.\.venv\Scripts\python.exe solve_p14_baseline.py --full
```
