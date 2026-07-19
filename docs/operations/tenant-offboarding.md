# Tenant Offboarding

Tenant offboarding is a governed workflow:

1. Create an export manifest.
2. Check legal hold status.
3. Create a deletion request.
4. Review scope preview.
5. Execute dry-run.
6. Require approval for destructive cleanup.
7. Preserve audit, evidence metadata, and release evidence according to retention policy.
8. Issue a deletion certificate only after governed completion.

P14 implements export metadata, deletion request metadata, dry-run preview, and Legal Hold blocking.
