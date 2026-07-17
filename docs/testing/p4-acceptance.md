# P4 acceptance criteria

P4 accepts the knowledge-context increment only when the following gates pass.

## Required files

- `apps/control-plane/src/vulnlab/context.py`
- `apps/control-plane/src/vulnlab/rag.py`
- `apps/control-plane/src/vulnlab/evidence.py`
- `apps/control-plane/src/vulnlab/api/routers/knowledge.py`
- `tests/test_p4_knowledge.py`
- `solve_p4_baseline.py`
- `packages/api-contracts/openapi/v1.yaml`
- `tools/contracts/snapshots/openapi-v1.snapshot.json`

## Runtime criteria

- Context messages are secret-scrubbed, sequenced, and hashed.
- Checkpoints include summary, state, evidence count, and restore-policy hashes.
- Evidence is task-bound, classified, hashed, and non-executable.
- RAG documents are chunked; search returns chunk-level citations.
- RAG search performs ACL classification filtering before scoring.
- Restored context and knowledge packs never restore or imply execution authority.

## Validation commands

```powershell
.\.venv\Scripts\python.exe solve_p4_baseline.py
.\.venv\Scripts\python.exe -m pytest tests\test_p4_knowledge.py tests\test_rag.py tests\contract\test_openapi_contract.py -q
.\.venv\Scripts\python.exe tools\contracts\openapi_snapshot.py check --runtime
```

Full gate:

```powershell
.\.venv\Scripts\python.exe solve_p4_baseline.py --full
```
