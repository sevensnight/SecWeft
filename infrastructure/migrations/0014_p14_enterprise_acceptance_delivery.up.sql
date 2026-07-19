BEGIN;

SET LOCAL lock_timeout = '10s';
SET LOCAL statement_timeout = '60s';

CREATE SCHEMA IF NOT EXISTS delivery;

CREATE TABLE delivery.acceptance_runs (
    id uuid NOT NULL,
    tenant_id uuid NOT NULL,
    project_id uuid NOT NULL,
    scenario_id varchar(120) NOT NULL,
    status varchar(80) NOT NULL,
    valid boolean NOT NULL DEFAULT false,
    production_ready boolean NOT NULL DEFAULT false,
    runtime boolean NOT NULL DEFAULT false,
    runtime_not_claimed boolean NOT NULL DEFAULT true,
    trace_id varchar(64) NOT NULL,
    policy_decision_id uuid NOT NULL,
    request jsonb NOT NULL DEFAULT '{}'::jsonb,
    result jsonb NOT NULL DEFAULT '{}'::jsonb,
    created_by uuid NOT NULL,
    created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    version bigint NOT NULL DEFAULT 1,
    PRIMARY KEY (tenant_id, id),
    CONSTRAINT fk_delivery_acceptance_tenant FOREIGN KEY (tenant_id)
        REFERENCES iam.tenants (id) ON UPDATE RESTRICT ON DELETE RESTRICT,
    CONSTRAINT fk_delivery_acceptance_project FOREIGN KEY (tenant_id, project_id)
        REFERENCES iam.projects (tenant_id, id) ON UPDATE RESTRICT ON DELETE RESTRICT,
    CONSTRAINT fk_delivery_acceptance_creator FOREIGN KEY (tenant_id, created_by)
        REFERENCES iam.users (tenant_id, id) ON UPDATE RESTRICT ON DELETE RESTRICT,
    CONSTRAINT ck_delivery_acceptance_status CHECK (
        status IN ('passed','failed','blocked','completed_with_blocked_production')
    ),
    CONSTRAINT ck_delivery_acceptance_request CHECK (jsonb_typeof(request) = 'object'),
    CONSTRAINT ck_delivery_acceptance_result CHECK (jsonb_typeof(result) = 'object'),
    CONSTRAINT ck_delivery_acceptance_version CHECK (version > 0),
    CONSTRAINT ck_delivery_acceptance_timestamps CHECK (updated_at >= created_at)
);

CREATE TABLE delivery.delivery_packages (
    id uuid NOT NULL,
    tenant_id uuid NOT NULL,
    project_id uuid NOT NULL,
    package_type varchar(40) NOT NULL,
    formal boolean NOT NULL DEFAULT false,
    status varchar(80) NOT NULL,
    root_path text NOT NULL,
    package_digest varchar(128) NOT NULL,
    manifest jsonb NOT NULL DEFAULT '{}'::jsonb,
    policy_decision_id uuid NOT NULL,
    generated_by uuid NOT NULL,
    created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    version bigint NOT NULL DEFAULT 1,
    PRIMARY KEY (tenant_id, id),
    CONSTRAINT uq_delivery_package_digest UNIQUE (tenant_id, package_digest),
    CONSTRAINT fk_delivery_package_tenant FOREIGN KEY (tenant_id)
        REFERENCES iam.tenants (id) ON UPDATE RESTRICT ON DELETE RESTRICT,
    CONSTRAINT fk_delivery_package_project FOREIGN KEY (tenant_id, project_id)
        REFERENCES iam.projects (tenant_id, id) ON UPDATE RESTRICT ON DELETE RESTRICT,
    CONSTRAINT fk_delivery_package_generator FOREIGN KEY (tenant_id, generated_by)
        REFERENCES iam.users (tenant_id, id) ON UPDATE RESTRICT ON DELETE RESTRICT,
    CONSTRAINT ck_delivery_package_type CHECK (package_type IN ('candidate','formal')),
    CONSTRAINT ck_delivery_package_status CHECK (
        status IN ('candidate_generated','formal_generated','blocked')
    ),
    CONSTRAINT ck_delivery_package_manifest CHECK (jsonb_typeof(manifest) = 'object'),
    CONSTRAINT ck_delivery_package_formal CHECK (
        (package_type = 'formal' AND formal = true) OR (package_type = 'candidate' AND formal = false)
    ),
    CONSTRAINT ck_delivery_package_version CHECK (version > 0),
    CONSTRAINT ck_delivery_package_timestamps CHECK (updated_at >= created_at)
);

CREATE TABLE delivery.data_exports (
    id uuid NOT NULL,
    tenant_id uuid NOT NULL,
    project_id uuid NOT NULL,
    export_type varchar(40) NOT NULL,
    status varchar(40) NOT NULL,
    manifest jsonb NOT NULL DEFAULT '{}'::jsonb,
    redacted boolean NOT NULL DEFAULT true,
    secret_count integer NOT NULL DEFAULT 0,
    policy_decision_id uuid NOT NULL,
    requested_by uuid NOT NULL,
    created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    version bigint NOT NULL DEFAULT 1,
    PRIMARY KEY (tenant_id, id),
    CONSTRAINT fk_delivery_export_tenant FOREIGN KEY (tenant_id)
        REFERENCES iam.tenants (id) ON UPDATE RESTRICT ON DELETE RESTRICT,
    CONSTRAINT fk_delivery_export_project FOREIGN KEY (tenant_id, project_id)
        REFERENCES iam.projects (tenant_id, id) ON UPDATE RESTRICT ON DELETE RESTRICT,
    CONSTRAINT fk_delivery_export_requester FOREIGN KEY (tenant_id, requested_by)
        REFERENCES iam.users (tenant_id, id) ON UPDATE RESTRICT ON DELETE RESTRICT,
    CONSTRAINT ck_delivery_export_type CHECK (export_type IN ('tenant')),
    CONSTRAINT ck_delivery_export_status CHECK (status IN ('completed','blocked','failed')),
    CONSTRAINT ck_delivery_export_manifest CHECK (jsonb_typeof(manifest) = 'object'),
    CONSTRAINT ck_delivery_export_secret_count CHECK (secret_count = 0),
    CONSTRAINT ck_delivery_export_version CHECK (version > 0),
    CONSTRAINT ck_delivery_export_timestamps CHECK (updated_at >= created_at)
);

CREATE TABLE delivery.deletion_requests (
    id uuid NOT NULL,
    tenant_id uuid NOT NULL,
    project_id uuid NOT NULL,
    target_type varchar(80) NOT NULL,
    target_id varchar(200) NOT NULL,
    dry_run boolean NOT NULL DEFAULT true,
    status varchar(80) NOT NULL,
    scope_preview jsonb NOT NULL DEFAULT '{}'::jsonb,
    deletion_certificate jsonb NOT NULL DEFAULT '{}'::jsonb,
    policy_decision_id uuid NOT NULL,
    requested_by uuid NOT NULL,
    approved_by uuid,
    created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    version bigint NOT NULL DEFAULT 1,
    PRIMARY KEY (tenant_id, id),
    CONSTRAINT fk_delivery_delete_tenant FOREIGN KEY (tenant_id)
        REFERENCES iam.tenants (id) ON UPDATE RESTRICT ON DELETE RESTRICT,
    CONSTRAINT fk_delivery_delete_project FOREIGN KEY (tenant_id, project_id)
        REFERENCES iam.projects (tenant_id, id) ON UPDATE RESTRICT ON DELETE RESTRICT,
    CONSTRAINT fk_delivery_delete_requester FOREIGN KEY (tenant_id, requested_by)
        REFERENCES iam.users (tenant_id, id) ON UPDATE RESTRICT ON DELETE RESTRICT,
    CONSTRAINT fk_delivery_delete_approver FOREIGN KEY (tenant_id, approved_by)
        REFERENCES iam.users (tenant_id, id) ON UPDATE RESTRICT ON DELETE RESTRICT,
    CONSTRAINT ck_delivery_delete_target CHECK (
        target_type IN ('tenant','project','case','report','validation_metadata')
    ),
    CONSTRAINT ck_delivery_delete_status CHECK (
        status IN ('dry_run_completed','approval_required','blocked_by_legal_hold','approved','rejected','completed')
    ),
    CONSTRAINT ck_delivery_delete_scope CHECK (jsonb_typeof(scope_preview) = 'object'),
    CONSTRAINT ck_delivery_delete_certificate CHECK (jsonb_typeof(deletion_certificate) = 'object'),
    CONSTRAINT ck_delivery_delete_no_self_approval CHECK (
        approved_by IS NULL OR approved_by <> requested_by
    ),
    CONSTRAINT ck_delivery_delete_version CHECK (version > 0),
    CONSTRAINT ck_delivery_delete_timestamps CHECK (updated_at >= created_at)
);

CREATE TABLE delivery.legal_holds (
    id uuid NOT NULL,
    tenant_id uuid NOT NULL,
    project_id uuid NOT NULL,
    hold_type varchar(80) NOT NULL,
    status varchar(40) NOT NULL,
    reason text NOT NULL,
    scope jsonb NOT NULL DEFAULT '{}'::jsonb,
    policy_decision_id uuid NOT NULL,
    created_by uuid NOT NULL,
    released_by uuid,
    created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    version bigint NOT NULL DEFAULT 1,
    PRIMARY KEY (tenant_id, id),
    CONSTRAINT fk_delivery_hold_tenant FOREIGN KEY (tenant_id)
        REFERENCES iam.tenants (id) ON UPDATE RESTRICT ON DELETE RESTRICT,
    CONSTRAINT fk_delivery_hold_project FOREIGN KEY (tenant_id, project_id)
        REFERENCES iam.projects (tenant_id, id) ON UPDATE RESTRICT ON DELETE RESTRICT,
    CONSTRAINT fk_delivery_hold_creator FOREIGN KEY (tenant_id, created_by)
        REFERENCES iam.users (tenant_id, id) ON UPDATE RESTRICT ON DELETE RESTRICT,
    CONSTRAINT fk_delivery_hold_releaser FOREIGN KEY (tenant_id, released_by)
        REFERENCES iam.users (tenant_id, id) ON UPDATE RESTRICT ON DELETE RESTRICT,
    CONSTRAINT ck_delivery_hold_type CHECK (
        hold_type IN ('litigation','incident','regulatory','customer_request')
    ),
    CONSTRAINT ck_delivery_hold_status CHECK (status IN ('active','released')),
    CONSTRAINT ck_delivery_hold_scope CHECK (jsonb_typeof(scope) = 'object'),
    CONSTRAINT ck_delivery_hold_version CHECK (version > 0),
    CONSTRAINT ck_delivery_hold_timestamps CHECK (updated_at >= created_at)
);

CREATE TABLE delivery.compliance_evidence_packages (
    id uuid NOT NULL,
    tenant_id uuid NOT NULL,
    project_id uuid NOT NULL,
    package_digest varchar(128) NOT NULL,
    controls jsonb NOT NULL DEFAULT '{}'::jsonb,
    policy_decision_id uuid NOT NULL,
    generated_by uuid NOT NULL,
    created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    version bigint NOT NULL DEFAULT 1,
    PRIMARY KEY (tenant_id, id),
    CONSTRAINT uq_delivery_compliance_digest UNIQUE (tenant_id, package_digest),
    CONSTRAINT fk_delivery_compliance_tenant FOREIGN KEY (tenant_id)
        REFERENCES iam.tenants (id) ON UPDATE RESTRICT ON DELETE RESTRICT,
    CONSTRAINT fk_delivery_compliance_project FOREIGN KEY (tenant_id, project_id)
        REFERENCES iam.projects (tenant_id, id) ON UPDATE RESTRICT ON DELETE RESTRICT,
    CONSTRAINT fk_delivery_compliance_generator FOREIGN KEY (tenant_id, generated_by)
        REFERENCES iam.users (tenant_id, id) ON UPDATE RESTRICT ON DELETE RESTRICT,
    CONSTRAINT ck_delivery_compliance_controls CHECK (jsonb_typeof(controls) = 'object'),
    CONSTRAINT ck_delivery_compliance_version CHECK (version > 0),
    CONSTRAINT ck_delivery_compliance_timestamps CHECK (updated_at >= created_at)
);

CREATE TABLE delivery.secret_rotation_records (
    id uuid NOT NULL,
    tenant_id uuid NOT NULL,
    project_id uuid NOT NULL,
    secret_type varchar(80) NOT NULL,
    status varchar(40) NOT NULL,
    metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
    rotated_by uuid NOT NULL,
    created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    version bigint NOT NULL DEFAULT 1,
    PRIMARY KEY (tenant_id, id),
    CONSTRAINT fk_delivery_secret_tenant FOREIGN KEY (tenant_id)
        REFERENCES iam.tenants (id) ON UPDATE RESTRICT ON DELETE RESTRICT,
    CONSTRAINT fk_delivery_secret_project FOREIGN KEY (tenant_id, project_id)
        REFERENCES iam.projects (tenant_id, id) ON UPDATE RESTRICT ON DELETE RESTRICT,
    CONSTRAINT fk_delivery_secret_rotator FOREIGN KEY (tenant_id, rotated_by)
        REFERENCES iam.users (tenant_id, id) ON UPDATE RESTRICT ON DELETE RESTRICT,
    CONSTRAINT ck_delivery_secret_type CHECK (
        secret_type IN ('api_key','keycloak_client','minio_credential','nats_credential','database_credential','signing_identity')
    ),
    CONSTRAINT ck_delivery_secret_status CHECK (
        status IN ('created','rotated','revoked','expired','failed')
    ),
    CONSTRAINT ck_delivery_secret_metadata CHECK (jsonb_typeof(metadata) = 'object'),
    CONSTRAINT ck_delivery_secret_version CHECK (version > 0),
    CONSTRAINT ck_delivery_secret_timestamps CHECK (updated_at >= created_at)
);

CREATE INDEX idx_delivery_acceptance_tenant
    ON delivery.acceptance_runs (tenant_id, project_id, created_at DESC);
CREATE INDEX idx_delivery_packages_tenant
    ON delivery.delivery_packages (tenant_id, project_id, created_at DESC);
CREATE INDEX idx_delivery_exports_tenant
    ON delivery.data_exports (tenant_id, project_id, created_at DESC);
CREATE INDEX idx_delivery_deletion_tenant
    ON delivery.deletion_requests (tenant_id, project_id, created_at DESC);
CREATE INDEX idx_delivery_legal_holds_active
    ON delivery.legal_holds (tenant_id, project_id, status);
CREATE INDEX idx_delivery_compliance_tenant
    ON delivery.compliance_evidence_packages (tenant_id, project_id, created_at DESC);
CREATE INDEX idx_delivery_secret_rotations_tenant
    ON delivery.secret_rotation_records (tenant_id, project_id, created_at DESC);

ALTER TABLE delivery.acceptance_runs ENABLE ROW LEVEL SECURITY;
ALTER TABLE delivery.acceptance_runs FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation_delivery_acceptance_runs ON delivery.acceptance_runs
    USING (tenant_id = current_setting('vulnlab.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('vulnlab.tenant_id', true)::uuid);

ALTER TABLE delivery.delivery_packages ENABLE ROW LEVEL SECURITY;
ALTER TABLE delivery.delivery_packages FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation_delivery_delivery_packages ON delivery.delivery_packages
    USING (tenant_id = current_setting('vulnlab.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('vulnlab.tenant_id', true)::uuid);

ALTER TABLE delivery.data_exports ENABLE ROW LEVEL SECURITY;
ALTER TABLE delivery.data_exports FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation_delivery_data_exports ON delivery.data_exports
    USING (tenant_id = current_setting('vulnlab.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('vulnlab.tenant_id', true)::uuid);

ALTER TABLE delivery.deletion_requests ENABLE ROW LEVEL SECURITY;
ALTER TABLE delivery.deletion_requests FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation_delivery_deletion_requests ON delivery.deletion_requests
    USING (tenant_id = current_setting('vulnlab.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('vulnlab.tenant_id', true)::uuid);

ALTER TABLE delivery.legal_holds ENABLE ROW LEVEL SECURITY;
ALTER TABLE delivery.legal_holds FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation_delivery_legal_holds ON delivery.legal_holds
    USING (tenant_id = current_setting('vulnlab.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('vulnlab.tenant_id', true)::uuid);

ALTER TABLE delivery.compliance_evidence_packages ENABLE ROW LEVEL SECURITY;
ALTER TABLE delivery.compliance_evidence_packages FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation_delivery_compliance_evidence_packages
    ON delivery.compliance_evidence_packages
    USING (tenant_id = current_setting('vulnlab.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('vulnlab.tenant_id', true)::uuid);

ALTER TABLE delivery.secret_rotation_records ENABLE ROW LEVEL SECURITY;
ALTER TABLE delivery.secret_rotation_records FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation_delivery_secret_rotation_records
    ON delivery.secret_rotation_records
    USING (tenant_id = current_setting('vulnlab.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('vulnlab.tenant_id', true)::uuid);

GRANT USAGE ON SCHEMA delivery TO vulnlab_app;
GRANT SELECT, INSERT, UPDATE ON ALL TABLES IN SCHEMA delivery TO vulnlab_app;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA delivery TO vulnlab_app;

COMMIT;
