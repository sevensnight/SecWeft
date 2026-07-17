BEGIN;

SET LOCAL lock_timeout = '10s';
SET LOCAL statement_timeout = '60s';

CREATE TABLE iam.organizations (
    id uuid NOT NULL,
    tenant_id uuid NOT NULL,
    slug varchar(63) NOT NULL,
    display_name varchar(200) NOT NULL,
    status varchar(24) NOT NULL DEFAULT 'ACTIVE',
    created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    version bigint NOT NULL DEFAULT 1,
    CONSTRAINT pk_organizations PRIMARY KEY (id),
    CONSTRAINT uq_organizations_tenant_slug UNIQUE (tenant_id, slug),
    CONSTRAINT uq_organizations_tenant_id UNIQUE (tenant_id, id),
    CONSTRAINT fk_organizations_tenant FOREIGN KEY (tenant_id)
        REFERENCES iam.tenants (id) ON UPDATE RESTRICT ON DELETE RESTRICT,
    CONSTRAINT ck_organizations_slug CHECK (slug ~ '^[a-z0-9][a-z0-9-]{1,61}[a-z0-9]$'),
    CONSTRAINT ck_organizations_status CHECK (status IN ('ACTIVE', 'ARCHIVED', 'DISABLED')),
    CONSTRAINT ck_organizations_version CHECK (version > 0),
    CONSTRAINT ck_organizations_timestamps CHECK (updated_at >= created_at)
);

ALTER TABLE iam.projects
    ADD COLUMN organization_id uuid;
ALTER TABLE iam.projects
    ADD CONSTRAINT fk_projects_organization FOREIGN KEY (tenant_id, organization_id)
        REFERENCES iam.organizations (tenant_id, id) ON UPDATE RESTRICT ON DELETE RESTRICT;
CREATE INDEX idx_projects_organization
    ON iam.projects (tenant_id, organization_id, status, slug);

ALTER TABLE iam.users
    ADD COLUMN issuer varchar(512) NOT NULL DEFAULT 'urn:vulnlab:legacy';
ALTER TABLE iam.users ALTER COLUMN issuer DROP DEFAULT;
ALTER TABLE iam.users DROP CONSTRAINT uq_users_tenant_subject;
ALTER TABLE iam.users
    ADD CONSTRAINT uq_users_tenant_issuer_subject UNIQUE (tenant_id, issuer, subject);
ALTER TABLE iam.users
    ADD CONSTRAINT ck_users_issuer CHECK (issuer ~ '^https?://|^urn:');
CREATE INDEX idx_users_identity ON iam.users (issuer, subject, tenant_id) WHERE active;

ALTER TABLE iam.user_roles
    ADD COLUMN reason text NOT NULL DEFAULT 'migration',
    ADD COLUMN starts_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    ADD COLUMN revoked_at timestamptz,
    ADD COLUMN revoked_by uuid,
    ADD COLUMN revocation_reason text;
ALTER TABLE iam.user_roles ALTER COLUMN reason DROP DEFAULT;
ALTER TABLE iam.user_roles
    ADD CONSTRAINT fk_user_roles_revoker FOREIGN KEY (tenant_id, revoked_by)
        REFERENCES iam.users (tenant_id, id) ON UPDATE RESTRICT ON DELETE RESTRICT,
    ADD CONSTRAINT ck_user_roles_reason CHECK (length(reason) BETWEEN 3 AND 500),
    ADD CONSTRAINT ck_user_roles_start CHECK (starts_at >= created_at),
    ADD CONSTRAINT ck_user_roles_revocation CHECK (
        (revoked_at IS NULL AND revoked_by IS NULL AND revocation_reason IS NULL)
        OR
        (revoked_at IS NOT NULL AND revoked_by IS NOT NULL
            AND length(revocation_reason) BETWEEN 3 AND 500 AND revoked_at >= starts_at)
    );
DROP INDEX iam.uq_user_roles_tenant_scope;
DROP INDEX iam.uq_user_roles_project_scope;
CREATE UNIQUE INDEX uq_user_roles_tenant_scope_active
    ON iam.user_roles (tenant_id, user_id, role_id)
    WHERE project_id IS NULL AND revoked_at IS NULL;
CREATE UNIQUE INDEX uq_user_roles_project_scope_active
    ON iam.user_roles (tenant_id, project_id, user_id, role_id)
    WHERE project_id IS NOT NULL AND revoked_at IS NULL;
CREATE INDEX idx_user_roles_active
    ON iam.user_roles (tenant_id, user_id, project_id, starts_at, expires_at)
    WHERE revoked_at IS NULL;

CREATE TABLE control.config_entries (
    id uuid NOT NULL,
    tenant_id uuid NOT NULL,
    project_id uuid,
    user_id uuid,
    scope_type varchar(16) NOT NULL,
    config_key varchar(160) NOT NULL,
    config_value jsonb NOT NULL,
    created_by uuid NOT NULL,
    updated_by uuid NOT NULL,
    created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    version bigint NOT NULL DEFAULT 1,
    CONSTRAINT pk_config_entries PRIMARY KEY (id),
    CONSTRAINT uq_config_entries_tenant_id UNIQUE (tenant_id, id),
    CONSTRAINT fk_config_entries_tenant FOREIGN KEY (tenant_id)
        REFERENCES iam.tenants (id) ON UPDATE RESTRICT ON DELETE RESTRICT,
    CONSTRAINT fk_config_entries_project FOREIGN KEY (tenant_id, project_id)
        REFERENCES iam.projects (tenant_id, id) ON UPDATE RESTRICT ON DELETE RESTRICT,
    CONSTRAINT fk_config_entries_user FOREIGN KEY (tenant_id, user_id)
        REFERENCES iam.users (tenant_id, id) ON UPDATE RESTRICT ON DELETE RESTRICT,
    CONSTRAINT fk_config_entries_creator FOREIGN KEY (tenant_id, created_by)
        REFERENCES iam.users (tenant_id, id) ON UPDATE RESTRICT ON DELETE RESTRICT,
    CONSTRAINT fk_config_entries_updater FOREIGN KEY (tenant_id, updated_by)
        REFERENCES iam.users (tenant_id, id) ON UPDATE RESTRICT ON DELETE RESTRICT,
    CONSTRAINT ck_config_entries_scope CHECK (scope_type IN ('TENANT', 'PROJECT', 'USER')),
    CONSTRAINT ck_config_entries_shape CHECK (
        (scope_type = 'TENANT' AND project_id IS NULL AND user_id IS NULL)
        OR (scope_type = 'PROJECT' AND project_id IS NOT NULL AND user_id IS NULL)
        OR (scope_type = 'USER' AND user_id IS NOT NULL)
    ),
    CONSTRAINT ck_config_entries_key CHECK (config_key ~ '^[a-z][a-z0-9_.-]{2,159}$'),
    CONSTRAINT ck_config_entries_version CHECK (version > 0),
    CONSTRAINT ck_config_entries_timestamps CHECK (updated_at >= created_at)
);
CREATE UNIQUE INDEX uq_config_entries_tenant
    ON control.config_entries (tenant_id, config_key) WHERE scope_type = 'TENANT';
CREATE UNIQUE INDEX uq_config_entries_project
    ON control.config_entries (tenant_id, project_id, config_key) WHERE scope_type = 'PROJECT';
CREATE UNIQUE INDEX uq_config_entries_user_tenant
    ON control.config_entries (tenant_id, user_id, config_key)
    WHERE scope_type = 'USER' AND project_id IS NULL;
CREATE UNIQUE INDEX uq_config_entries_user_project
    ON control.config_entries (tenant_id, project_id, user_id, config_key)
    WHERE scope_type = 'USER' AND project_id IS NOT NULL;
CREATE INDEX idx_config_entries_effective
    ON control.config_entries (tenant_id, project_id, user_id, config_key);

CREATE FUNCTION iam.current_tenant_id()
RETURNS uuid
LANGUAGE sql
STABLE
SET search_path = pg_catalog
AS $$
    SELECT NULLIF(current_setting('app.tenant_id', true), '')::uuid
$$;

ALTER TABLE iam.tenants ENABLE ROW LEVEL SECURITY;
ALTER TABLE iam.tenants FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON iam.tenants
    USING (id = iam.current_tenant_id())
    WITH CHECK (id = iam.current_tenant_id());

DO $rls$
DECLARE
    target text;
BEGIN
    FOREACH target IN ARRAY ARRAY[
        'iam.organizations',
        'iam.projects',
        'iam.users',
        'iam.roles',
        'iam.permissions',
        'iam.role_permissions',
        'iam.user_roles',
        'control.tasks',
        'control.task_stages',
        'control.task_events',
        'control.outbox_events',
        'control.inbox_messages',
        'control.idempotency_records',
        'control.config_entries',
        'audit.events',
        'audit.chain_heads'
    ]
    LOOP
        EXECUTE format('ALTER TABLE %s ENABLE ROW LEVEL SECURITY', target);
        EXECUTE format('ALTER TABLE %s FORCE ROW LEVEL SECURITY', target);
        EXECUTE format(
            'CREATE POLICY tenant_isolation ON %s USING (tenant_id = iam.current_tenant_id()) '
            'WITH CHECK (tenant_id = iam.current_tenant_id())',
            target
        );
    END LOOP;
END
$rls$;

DO $role$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'vulnlab_app') THEN
        CREATE ROLE vulnlab_app NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT;
    END IF;
END
$role$;

GRANT USAGE ON SCHEMA iam, control, audit TO vulnlab_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA iam TO vulnlab_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA control TO vulnlab_app;
GRANT SELECT, INSERT ON audit.events TO vulnlab_app;
GRANT SELECT, INSERT, UPDATE ON audit.chain_heads TO vulnlab_app;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA audit TO vulnlab_app;
GRANT EXECUTE ON FUNCTION iam.current_tenant_id() TO vulnlab_app;
ALTER DEFAULT PRIVILEGES IN SCHEMA iam
    GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO vulnlab_app;
ALTER DEFAULT PRIVILEGES IN SCHEMA control
    GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO vulnlab_app;
ALTER DEFAULT PRIVILEGES IN SCHEMA audit
    GRANT USAGE, SELECT ON SEQUENCES TO vulnlab_app;

COMMIT;
