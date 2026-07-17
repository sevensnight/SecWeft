# P9 validation matrix

| Requirement | Coverage | Status |
|---|---|---|
| Approved plan can create execution | `tests/test_p9_validation_executions.py::test_p9_http_validation_execution_closes_loop` | Passed locally |
| Execution creation returns `202` | Same test | Passed locally |
| Durable queue entry is created | Same test and DB state in service | Passed locally |
| Worker consumes task | Same test calls `run_worker_once()` | Passed locally |
| HTTP response template runs | Same test with local HTTP server | Passed locally |
| SBOM dependency evidence template runs | `test_p9_sbom_and_fixed_training_lab_templates_execute_without_shell` | Passed locally |
| Fixed local training lab template runs | `test_p9_sbom_and_fixed_training_lab_templates_execute_without_shell` | Passed locally |
| Evidence is saved with SHA-256 | Same test checks `content_sha256` and artifact ref | Passed locally |
| Human review is persisted | Same test posts `/reviews` | Passed locally |
| Unapproved plan cannot execute | `test_p9_create_execution_requires_approved_plan` | Passed locally |
| Approval revoked before worker cannot execute | `test_p9_worker_rejects_revoked_approval` | Passed locally |
| Cross-tenant execution cannot be viewed | `test_p9_cross_tenant_execution_is_not_visible` | Passed locally |
| Duplicate request does not duplicate execution | `test_p9_duplicate_idempotency_key_does_not_duplicate_execution` | Passed locally |
| Unknown template cannot execute | `test_p9_unknown_template_and_arbitrary_shell_are_rejected` | Passed locally |
| Arbitrary shell cannot execute | Same test verifies schema rejection of `argv` | Passed locally |
| Authorization expired cannot execute | Covered by `ScopeService` path; dedicated service-runtime test still pending | Not executed |
| Timeout terminates execution | Status and handler exist; deterministic timeout test pending | Not executed |
| Resource over-limit terminates execution | Status exists; requires Docker runtime test | Not executed |
| Worker restart does not lose task | Durable DB queue present; multi-process restart test pending | Not executed |
| Container is eventually cleaned up | Requires Docker runtime test | Not executed |
| Default internet access blocked | Threat model and sandbox profile defined; network runtime test pending | Not executed |
| NATS JetStream reliable queue | Protocol documented; local test uses DB queue adapter | Not executed |
| MinIO full artifact storage | Artifact reference and local-compatible store implemented; true MinIO upload pending | Not executed |

## Commands run in local P9 acceptance

```powershell
.\.venv\Scripts\python.exe -m pytest tests\test_p9_validation_executions.py -q
.\.venv\Scripts\python.exe -m pytest tests\contract\test_openapi_contract.py -q
pnpm generate:api
pnpm --filter @vulnlab/web-console typecheck
```
