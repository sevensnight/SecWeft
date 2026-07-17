BEGIN;

SET LOCAL lock_timeout = '10s';
SET LOCAL statement_timeout = '60s';

REVOKE EXECUTE ON FUNCTION iam.current_tenant_id() FROM vulnlab_app;

DO $rls$
DECLARE
    target text;
BEGIN
    FOREACH target IN ARRAY ARRAY[
        'audit.chain_heads',
        'audit.events',
        'control.config_entries',
        'control.idempotency_records',
        'control.inbox_messages',
        'control.outbox_events',
        'control.task_events',
        'control.task_stages',
        'control.tasks',
        'iam.user_roles',
        'iam.role_permissions',
        'iam.permissions',
        'iam.roles',
        'iam.users',
        'iam.projects',
        'iam.organizations'
    ]
    LOOP
        EXECUTE format('DROP POLICY IF EXISTS tenant_isolation ON %s', target);
        EXECUTE format('ALTER TABLE %s NO FORCE ROW LEVEL SECURITY', target);
        EXECUTE format('ALTER TABLE %s DISABLE ROW LEVEL SECURITY', target);
    END LOOP;
END
$rls$;

DROP POLICY IF EXISTS tenant_isolation ON iam.tenants;
ALTER TABLE iam.tenants NO FORCE ROW LEVEL SECURITY;
ALTER TABLE iam.tenants DISABLE ROW LEVEL SECURITY;
DROP FUNCTION iam.current_tenant_id();

DROP TABLE control.config_entries;

DROP INDEX iam.idx_user_roles_active;
DROP INDEX iam.uq_user_roles_project_scope_active;
DROP INDEX iam.uq_user_roles_tenant_scope_active;
ALTER TABLE iam.user_roles DROP CONSTRAINT ck_user_roles_revocation;
ALTER TABLE iam.user_roles DROP CONSTRAINT ck_user_roles_start;
ALTER TABLE iam.user_roles DROP CONSTRAINT ck_user_roles_reason;
ALTER TABLE iam.user_roles DROP CONSTRAINT fk_user_roles_revoker;
ALTER TABLE iam.user_roles
    DROP COLUMN revocation_reason,
    DROP COLUMN revoked_by,
    DROP COLUMN revoked_at,
    DROP COLUMN starts_at,
    DROP COLUMN reason;
CREATE UNIQUE INDEX uq_user_roles_project_scope
    ON iam.user_roles (tenant_id, project_id, user_id, role_id)
    WHERE project_id IS NOT NULL;
CREATE UNIQUE INDEX uq_user_roles_tenant_scope
    ON iam.user_roles (tenant_id, user_id, role_id)
    WHERE project_id IS NULL;

DROP INDEX iam.idx_users_identity;
ALTER TABLE iam.users DROP CONSTRAINT ck_users_issuer;
ALTER TABLE iam.users DROP CONSTRAINT uq_users_tenant_issuer_subject;
ALTER TABLE iam.users DROP COLUMN issuer;
ALTER TABLE iam.users
    ADD CONSTRAINT uq_users_tenant_subject UNIQUE (tenant_id, subject);

DROP INDEX iam.idx_projects_organization;
ALTER TABLE iam.projects DROP CONSTRAINT fk_projects_organization;
ALTER TABLE iam.projects DROP COLUMN organization_id;

DROP TABLE iam.organizations;

COMMIT;
