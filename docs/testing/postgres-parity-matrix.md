# PostgreSQL Parity Matrix

P9-H parity is verified with a disposable real PostgreSQL container. Tests create isolated schemas and remove containers after completion.

| Area | Verification |
|---|---|
| transaction commit / rollback | `tests/integration/test_p9h_postgres_repository.py` forced rollback leaves no row |
| foreign keys | invalid task scope insert raises PostgreSQL FK violation |
| unique constraints | duplicate username maps to API `409 conflict` |
| JSONB | PostgreSQL `jsonb_typeof` behavior is exercised |
| timezone-aware timestamps | PostgreSQL connections set UTC and migrations use `timestamptz` |
| pagination and sorting | validation execution list ordering with `limit=1` |
| optimistic/CAS behavior | validation queue lease compare-and-swap |
| Idempotency-Key concurrency | concurrent execution create calls replay one execution |
| approval revocation race | worker rechecks revoked plan and returns `APPROVAL_REVOKED` |
| execution cancellation race | cancellation request updates execution and queue state |
| tenant/principal isolation | cross-principal validation execution read returns `404` |
| audit atomicity | audit chain verifies after execution/review |

SQLite remains the deterministic development baseline. PostgreSQL is the production/integration persistence mode.
