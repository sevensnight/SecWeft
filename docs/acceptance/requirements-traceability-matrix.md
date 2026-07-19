# Requirements Traceability Matrix

The authoritative machine-readable matrix is exposed at:

```text
GET /api/v1/acceptance/requirements
```

Each item records:

- `requirement_id`
- `requirement_description`
- `implementation_status`
- backend modules
- frontend routes
- API operations
- database migrations
- policy actions
- tests
- acceptance scripts
- documents
- known limitations
- runtime evidence classification

Valid statuses:

- `IMPLEMENTED`
- `PARTIALLY_IMPLEMENTED`
- `NOT_IMPLEMENTED`
- `NOT_APPLICABLE`
- `BLOCKED`

The matrix distinguishes static implementation, deterministic testing, runtime validation, and manual acceptance.
