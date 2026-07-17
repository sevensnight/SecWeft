BEGIN;

SET LOCAL lock_timeout = '10s';
SET LOCAL statement_timeout = '60s';

REVOKE EXECUTE ON FUNCTION iam.enforce_user_role_scope() FROM vulnlab_app;
DROP TRIGGER trg_user_roles_scope ON iam.user_roles;
DROP FUNCTION iam.enforce_user_role_scope();

ALTER TABLE iam.roles DROP CONSTRAINT ck_roles_scope;
UPDATE iam.roles
SET scope_type = CASE WHEN code = 'auditor' THEN 'TENANT' ELSE 'PROJECT' END,
    updated_at = CURRENT_TIMESTAMP,
    version = version + 1
WHERE scope_type = 'BOTH';
ALTER TABLE iam.roles
    ADD CONSTRAINT ck_roles_scope CHECK (scope_type IN ('TENANT', 'PROJECT'));

COMMIT;
