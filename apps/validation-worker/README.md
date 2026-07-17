# P9 validation worker

This worker consumes durably queued validation execution messages through the control-plane service layer.

The local acceptance path uses the SQLite-backed queue adapter so the worker can be tested without a running NATS server. The production message contract is `validation.executions.requested` with a `validation-worker` durable consumer, as documented in `docs/architecture/p9-execution-plane.md`.
