# P14 Data Governance

P14 adds metadata records for redacted tenant export, deletion request, legal hold, compliance evidence package, and secret rotation status.

## Retention domains

- Evidence metadata: retained for auditability.
- Evidence object bodies: governed by evidence retention policy and storage lifecycle.
- Audit events: append-only and not physically deleted by ordinary users.
- Reports: retained until a governed deletion request is approved.
- Release evidence: retained as immutable release provenance.

## Controlled deletion

The deletion lifecycle is:

```text
request -> approval -> scope preview -> dry-run -> execution -> audit -> deletion certificate
```

The P14 API implements request and dry-run preview metadata. It does not expose unaudited bulk permanent deletion.

Legal hold blocks deletion requests for the held tenant/project scope.
