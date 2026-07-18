BEGIN;

SET LOCAL lock_timeout = '10s';
SET LOCAL statement_timeout = '60s';

CREATE SCHEMA IF NOT EXISTS release;

CREATE TABLE release.artifacts (
    id uuid NOT NULL,
    tenant_id uuid NOT NULL,
    project_id uuid NOT NULL,
    name varchar(200) NOT NULL,
    artifact_type varchar(40) NOT NULL,
    digest varchar(256) NOT NULL,
    repository text NOT NULL DEFAULT '',
    source_commit varchar(80) NOT NULL,
    metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
    created_by uuid NOT NULL,
    created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    version bigint NOT NULL DEFAULT 1,
    PRIMARY KEY (tenant_id, id),
    CONSTRAINT uq_release_artifact_digest UNIQUE (tenant_id, digest),
    CONSTRAINT fk_release_artifact_tenant FOREIGN KEY (tenant_id)
        REFERENCES iam.tenants (id) ON UPDATE RESTRICT ON DELETE RESTRICT,
    CONSTRAINT fk_release_artifact_project FOREIGN KEY (tenant_id, project_id)
        REFERENCES iam.projects (tenant_id, id) ON UPDATE RESTRICT ON DELETE RESTRICT,
    CONSTRAINT fk_release_artifact_creator FOREIGN KEY (tenant_id, created_by)
        REFERENCES iam.users (tenant_id, id) ON UPDATE RESTRICT ON DELETE RESTRICT,
    CONSTRAINT ck_release_artifact_type CHECK (
        artifact_type IN ('container','helm_chart','python_package','node_package','release_package')
    ),
    CONSTRAINT ck_release_artifact_digest CHECK (digest ~ '(^sha256:[a-f0-9]{64}$)|(@sha256:[a-f0-9]{64}$)'),
    CONSTRAINT ck_release_artifact_metadata CHECK (jsonb_typeof(metadata) = 'object'),
    CONSTRAINT ck_release_artifact_version CHECK (version > 0),
    CONSTRAINT ck_release_artifact_timestamps CHECK (updated_at >= created_at)
);

CREATE TABLE release.sbom_documents (
    id uuid NOT NULL,
    tenant_id uuid NOT NULL,
    artifact_id uuid NOT NULL,
    format varchar(80) NOT NULL,
    generator varchar(160) NOT NULL,
    generated_at timestamptz NOT NULL,
    artifact_digest varchar(256) NOT NULL,
    document_digest varchar(256) NOT NULL,
    component_count integer NOT NULL DEFAULT 0,
    license_summary jsonb NOT NULL DEFAULT '{}'::jsonb,
    vulnerability_summary jsonb NOT NULL DEFAULT '{}'::jsonb,
    document_ref text NOT NULL DEFAULT '',
    created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    version bigint NOT NULL DEFAULT 1,
    PRIMARY KEY (tenant_id, id),
    CONSTRAINT uq_release_sbom_digest UNIQUE (tenant_id, artifact_id, document_digest),
    CONSTRAINT fk_release_sbom_artifact FOREIGN KEY (tenant_id, artifact_id)
        REFERENCES release.artifacts (tenant_id, id) ON UPDATE RESTRICT ON DELETE RESTRICT,
    CONSTRAINT ck_release_sbom_component_count CHECK (component_count >= 0),
    CONSTRAINT ck_release_sbom_license_json CHECK (jsonb_typeof(license_summary) = 'object'),
    CONSTRAINT ck_release_sbom_vuln_json CHECK (jsonb_typeof(vulnerability_summary) = 'object'),
    CONSTRAINT ck_release_sbom_version CHECK (version > 0)
);

CREATE TABLE release.provenance_statements (
    id uuid NOT NULL,
    tenant_id uuid NOT NULL,
    artifact_id uuid NOT NULL,
    subject_digest varchar(256) NOT NULL,
    source_repository text NOT NULL,
    source_commit varchar(80) NOT NULL,
    builder_workflow text NOT NULL,
    statement_digest varchar(256) NOT NULL,
    predicate_type varchar(200) NOT NULL,
    verified boolean NOT NULL DEFAULT false,
    metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
    created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    version bigint NOT NULL DEFAULT 1,
    PRIMARY KEY (tenant_id, id),
    CONSTRAINT uq_release_provenance_digest UNIQUE (tenant_id, artifact_id, statement_digest),
    CONSTRAINT fk_release_provenance_artifact FOREIGN KEY (tenant_id, artifact_id)
        REFERENCES release.artifacts (tenant_id, id) ON UPDATE RESTRICT ON DELETE RESTRICT,
    CONSTRAINT ck_release_provenance_metadata CHECK (jsonb_typeof(metadata) = 'object'),
    CONSTRAINT ck_release_provenance_version CHECK (version > 0)
);

CREATE TABLE release.signature_records (
    id uuid NOT NULL,
    tenant_id uuid NOT NULL,
    artifact_id uuid NOT NULL,
    signature_digest varchar(256) NOT NULL,
    signature_identity text NOT NULL,
    certificate_issuer text NOT NULL,
    verified boolean NOT NULL DEFAULT false,
    verification_error text NOT NULL DEFAULT '',
    created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    version bigint NOT NULL DEFAULT 1,
    PRIMARY KEY (tenant_id, id),
    CONSTRAINT uq_release_signature_digest UNIQUE (tenant_id, artifact_id, signature_digest),
    CONSTRAINT fk_release_signature_artifact FOREIGN KEY (tenant_id, artifact_id)
        REFERENCES release.artifacts (tenant_id, id) ON UPDATE RESTRICT ON DELETE RESTRICT,
    CONSTRAINT ck_release_signature_version CHECK (version > 0)
);

CREATE TABLE release.security_scan_results (
    id uuid NOT NULL,
    tenant_id uuid NOT NULL,
    artifact_id uuid NOT NULL,
    scanner varchar(160) NOT NULL,
    severity_summary jsonb NOT NULL DEFAULT '{}'::jsonb,
    critical_count integer NOT NULL DEFAULT 0,
    high_count integer NOT NULL DEFAULT 0,
    unresolved_critical boolean NOT NULL DEFAULT false,
    scan_digest varchar(256) NOT NULL,
    created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    version bigint NOT NULL DEFAULT 1,
    PRIMARY KEY (tenant_id, id),
    CONSTRAINT uq_release_security_scan_digest UNIQUE (tenant_id, artifact_id, scan_digest),
    CONSTRAINT fk_release_security_scan_artifact FOREIGN KEY (tenant_id, artifact_id)
        REFERENCES release.artifacts (tenant_id, id) ON UPDATE RESTRICT ON DELETE RESTRICT,
    CONSTRAINT ck_release_security_scan_counts CHECK (critical_count >= 0 AND high_count >= 0),
    CONSTRAINT ck_release_security_scan_summary CHECK (jsonb_typeof(severity_summary) = 'object'),
    CONSTRAINT ck_release_security_scan_version CHECK (version > 0)
);

CREATE TABLE release.license_scan_results (
    id uuid NOT NULL,
    tenant_id uuid NOT NULL,
    artifact_id uuid NOT NULL,
    scanner varchar(160) NOT NULL,
    license_summary jsonb NOT NULL DEFAULT '{}'::jsonb,
    prohibited_licenses jsonb NOT NULL DEFAULT '[]'::jsonb,
    passed boolean NOT NULL DEFAULT false,
    scan_digest varchar(256) NOT NULL,
    created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    version bigint NOT NULL DEFAULT 1,
    PRIMARY KEY (tenant_id, id),
    CONSTRAINT uq_release_license_scan_digest UNIQUE (tenant_id, artifact_id, scan_digest),
    CONSTRAINT fk_release_license_scan_artifact FOREIGN KEY (tenant_id, artifact_id)
        REFERENCES release.artifacts (tenant_id, id) ON UPDATE RESTRICT ON DELETE RESTRICT,
    CONSTRAINT ck_release_license_summary CHECK (jsonb_typeof(license_summary) = 'object'),
    CONSTRAINT ck_release_prohibited_licenses CHECK (jsonb_typeof(prohibited_licenses) = 'array'),
    CONSTRAINT ck_release_license_scan_version CHECK (version > 0)
);

CREATE TABLE release.candidates (
    id uuid NOT NULL,
    tenant_id uuid NOT NULL,
    project_id uuid NOT NULL,
    name varchar(200) NOT NULL,
    artifact_id uuid NOT NULL,
    source_commit varchar(80) NOT NULL,
    image_digest varchar(256) NOT NULL,
    sbom_digest varchar(256) NOT NULL,
    provenance_digest varchar(256) NOT NULL,
    signature_digest varchar(256) NOT NULL,
    configuration_hash varchar(128) NOT NULL,
    migration_set jsonb NOT NULL DEFAULT '[]'::jsonb,
    helm_chart_digest varchar(256) NOT NULL,
    status varchar(40) NOT NULL DEFAULT 'frozen',
    freeze_hash varchar(128) NOT NULL,
    metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
    created_by uuid NOT NULL,
    created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    version bigint NOT NULL DEFAULT 1,
    PRIMARY KEY (tenant_id, id),
    CONSTRAINT uq_release_candidate_name UNIQUE (tenant_id, name),
    CONSTRAINT uq_release_candidate_freeze UNIQUE (tenant_id, freeze_hash),
    CONSTRAINT fk_release_candidate_artifact FOREIGN KEY (tenant_id, artifact_id)
        REFERENCES release.artifacts (tenant_id, id) ON UPDATE RESTRICT ON DELETE RESTRICT,
    CONSTRAINT fk_release_candidate_project FOREIGN KEY (tenant_id, project_id)
        REFERENCES iam.projects (tenant_id, id) ON UPDATE RESTRICT ON DELETE RESTRICT,
    CONSTRAINT fk_release_candidate_creator FOREIGN KEY (tenant_id, created_by)
        REFERENCES iam.users (tenant_id, id) ON UPDATE RESTRICT ON DELETE RESTRICT,
    CONSTRAINT ck_release_candidate_status CHECK (
        status IN ('created','frozen','evaluated','approved','promoting','deployed','blocked','rolled_back')
    ),
    CONSTRAINT ck_release_candidate_migrations CHECK (jsonb_typeof(migration_set) = 'array'),
    CONSTRAINT ck_release_candidate_metadata CHECK (jsonb_typeof(metadata) = 'object'),
    CONSTRAINT ck_release_candidate_version CHECK (version > 0),
    CONSTRAINT ck_release_candidate_timestamps CHECK (updated_at >= created_at)
);

CREATE TABLE release.gate_results (
    id uuid NOT NULL,
    tenant_id uuid NOT NULL,
    candidate_id uuid NOT NULL,
    gate_id varchar(120) NOT NULL,
    environment varchar(40) NOT NULL,
    status varchar(40) NOT NULL,
    reason text NOT NULL,
    evidence jsonb NOT NULL DEFAULT '{}'::jsonb,
    evaluated_by uuid NOT NULL,
    policy_decision_id uuid,
    created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    version bigint NOT NULL DEFAULT 1,
    PRIMARY KEY (tenant_id, id),
    CONSTRAINT uq_release_gate_result UNIQUE (tenant_id, candidate_id, gate_id, environment),
    CONSTRAINT fk_release_gate_candidate FOREIGN KEY (tenant_id, candidate_id)
        REFERENCES release.candidates (tenant_id, id) ON UPDATE RESTRICT ON DELETE RESTRICT,
    CONSTRAINT fk_release_gate_evaluator FOREIGN KEY (tenant_id, evaluated_by)
        REFERENCES iam.users (tenant_id, id) ON UPDATE RESTRICT ON DELETE RESTRICT,
    CONSTRAINT ck_release_gate_environment CHECK (
        environment IN ('development','integration','staging','production')
    ),
    CONSTRAINT ck_release_gate_status CHECK (status IN ('passed','failed','warning')),
    CONSTRAINT ck_release_gate_evidence CHECK (jsonb_typeof(evidence) = 'object'),
    CONSTRAINT ck_release_gate_version CHECK (version > 0)
);

CREATE TABLE release.approvals (
    id uuid NOT NULL,
    tenant_id uuid NOT NULL,
    candidate_id uuid NOT NULL,
    environment varchar(40) NOT NULL,
    decision varchar(40) NOT NULL,
    reason text NOT NULL DEFAULT '',
    approved_by uuid NOT NULL,
    created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    version bigint NOT NULL DEFAULT 1,
    PRIMARY KEY (tenant_id, id),
    CONSTRAINT fk_release_approval_candidate FOREIGN KEY (tenant_id, candidate_id)
        REFERENCES release.candidates (tenant_id, id) ON UPDATE RESTRICT ON DELETE RESTRICT,
    CONSTRAINT fk_release_approval_user FOREIGN KEY (tenant_id, approved_by)
        REFERENCES iam.users (tenant_id, id) ON UPDATE RESTRICT ON DELETE RESTRICT,
    CONSTRAINT ck_release_approval_environment CHECK (
        environment IN ('development','integration','staging','production')
    ),
    CONSTRAINT ck_release_approval_decision CHECK (decision IN ('approved','rejected')),
    CONSTRAINT ck_release_approval_version CHECK (version > 0)
);

CREATE TABLE release.exceptions (
    id uuid NOT NULL,
    tenant_id uuid NOT NULL,
    candidate_id uuid NOT NULL,
    gate_id varchar(120) NOT NULL,
    reason text NOT NULL,
    risk varchar(40) NOT NULL,
    scope text NOT NULL,
    requested_by uuid NOT NULL,
    approved_by uuid,
    expires_at timestamptz NOT NULL,
    compensating_controls jsonb NOT NULL DEFAULT '[]'::jsonb,
    status varchar(40) NOT NULL,
    created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    version bigint NOT NULL DEFAULT 1,
    PRIMARY KEY (tenant_id, id),
    CONSTRAINT fk_release_exception_candidate FOREIGN KEY (tenant_id, candidate_id)
        REFERENCES release.candidates (tenant_id, id) ON UPDATE RESTRICT ON DELETE RESTRICT,
    CONSTRAINT fk_release_exception_requester FOREIGN KEY (tenant_id, requested_by)
        REFERENCES iam.users (tenant_id, id) ON UPDATE RESTRICT ON DELETE RESTRICT,
    CONSTRAINT fk_release_exception_approver FOREIGN KEY (tenant_id, approved_by)
        REFERENCES iam.users (tenant_id, id) ON UPDATE RESTRICT ON DELETE RESTRICT,
    CONSTRAINT ck_release_exception_risk CHECK (risk IN ('low','medium','high','critical')),
    CONSTRAINT ck_release_exception_status CHECK (status IN ('requested','approved','expired','rejected')),
    CONSTRAINT ck_release_exception_controls CHECK (jsonb_typeof(compensating_controls) = 'array'),
    CONSTRAINT ck_release_exception_no_self_critical CHECK (
        risk <> 'critical' OR approved_by IS NULL OR approved_by <> requested_by
    ),
    CONSTRAINT ck_release_exception_version CHECK (version > 0),
    CONSTRAINT ck_release_exception_timestamps CHECK (updated_at >= created_at AND expires_at > created_at)
);

CREATE TABLE release.environment_promotions (
    id uuid NOT NULL,
    tenant_id uuid NOT NULL,
    candidate_id uuid NOT NULL,
    environment varchar(40) NOT NULL,
    status varchar(40) NOT NULL,
    promoted_by uuid NOT NULL,
    policy_decision_id uuid,
    created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    version bigint NOT NULL DEFAULT 1,
    PRIMARY KEY (tenant_id, id),
    CONSTRAINT uq_release_promotion UNIQUE (tenant_id, candidate_id, environment),
    CONSTRAINT fk_release_promotion_candidate FOREIGN KEY (tenant_id, candidate_id)
        REFERENCES release.candidates (tenant_id, id) ON UPDATE RESTRICT ON DELETE RESTRICT,
    CONSTRAINT fk_release_promotion_user FOREIGN KEY (tenant_id, promoted_by)
        REFERENCES iam.users (tenant_id, id) ON UPDATE RESTRICT ON DELETE RESTRICT,
    CONSTRAINT ck_release_promotion_environment CHECK (
        environment IN ('development','integration','staging','production')
    ),
    CONSTRAINT ck_release_promotion_status CHECK (status IN ('requested','deployed','blocked','failed')),
    CONSTRAINT ck_release_promotion_version CHECK (version > 0),
    CONSTRAINT ck_release_promotion_timestamps CHECK (updated_at >= created_at)
);

CREATE TABLE release.deployment_records (
    id uuid NOT NULL,
    tenant_id uuid NOT NULL,
    promotion_id uuid NOT NULL,
    candidate_id uuid NOT NULL,
    environment varchar(40) NOT NULL,
    image_digest varchar(256) NOT NULL,
    canary_percentage integer NOT NULL DEFAULT 100,
    status varchar(40) NOT NULL,
    health jsonb NOT NULL DEFAULT '{}'::jsonb,
    created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    version bigint NOT NULL DEFAULT 1,
    PRIMARY KEY (tenant_id, id),
    CONSTRAINT fk_release_deployment_promotion FOREIGN KEY (tenant_id, promotion_id)
        REFERENCES release.environment_promotions (tenant_id, id) ON UPDATE RESTRICT ON DELETE RESTRICT,
    CONSTRAINT fk_release_deployment_candidate FOREIGN KEY (tenant_id, candidate_id)
        REFERENCES release.candidates (tenant_id, id) ON UPDATE RESTRICT ON DELETE RESTRICT,
    CONSTRAINT ck_release_deployment_environment CHECK (
        environment IN ('development','integration','staging','production')
    ),
    CONSTRAINT ck_release_deployment_status CHECK (
        status IN ('deployed','failed','rollback_recommended','rolled_back')
    ),
    CONSTRAINT ck_release_deployment_canary CHECK (canary_percentage BETWEEN 0 AND 100),
    CONSTRAINT ck_release_deployment_health CHECK (jsonb_typeof(health) = 'object'),
    CONSTRAINT ck_release_deployment_version CHECK (version > 0),
    CONSTRAINT ck_release_deployment_timestamps CHECK (updated_at >= created_at)
);

CREATE TABLE release.rollback_records (
    id uuid NOT NULL,
    tenant_id uuid NOT NULL,
    deployment_id uuid NOT NULL,
    candidate_id uuid NOT NULL,
    environment varchar(40) NOT NULL,
    reason text NOT NULL,
    requested_by uuid NOT NULL,
    approved_by uuid,
    status varchar(40) NOT NULL,
    created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    version bigint NOT NULL DEFAULT 1,
    PRIMARY KEY (tenant_id, id),
    CONSTRAINT fk_release_rollback_deployment FOREIGN KEY (tenant_id, deployment_id)
        REFERENCES release.deployment_records (tenant_id, id) ON UPDATE RESTRICT ON DELETE RESTRICT,
    CONSTRAINT fk_release_rollback_candidate FOREIGN KEY (tenant_id, candidate_id)
        REFERENCES release.candidates (tenant_id, id) ON UPDATE RESTRICT ON DELETE RESTRICT,
    CONSTRAINT fk_release_rollback_requester FOREIGN KEY (tenant_id, requested_by)
        REFERENCES iam.users (tenant_id, id) ON UPDATE RESTRICT ON DELETE RESTRICT,
    CONSTRAINT fk_release_rollback_approver FOREIGN KEY (tenant_id, approved_by)
        REFERENCES iam.users (tenant_id, id) ON UPDATE RESTRICT ON DELETE RESTRICT,
    CONSTRAINT ck_release_rollback_status CHECK (status IN ('requested','approved','completed','rejected')),
    CONSTRAINT ck_release_rollback_version CHECK (version > 0),
    CONSTRAINT ck_release_rollback_timestamps CHECK (updated_at >= created_at)
);

CREATE TABLE release.configuration_snapshots (
    id uuid NOT NULL,
    tenant_id uuid NOT NULL,
    candidate_id uuid NOT NULL,
    environment varchar(40) NOT NULL,
    approved_snapshot jsonb NOT NULL DEFAULT '{}'::jsonb,
    snapshot_hash varchar(128) NOT NULL,
    created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    version bigint NOT NULL DEFAULT 1,
    PRIMARY KEY (tenant_id, id),
    CONSTRAINT uq_release_snapshot UNIQUE (tenant_id, candidate_id, environment),
    CONSTRAINT fk_release_snapshot_candidate FOREIGN KEY (tenant_id, candidate_id)
        REFERENCES release.candidates (tenant_id, id) ON UPDATE RESTRICT ON DELETE RESTRICT,
    CONSTRAINT ck_release_snapshot_environment CHECK (
        environment IN ('development','integration','staging','production')
    ),
    CONSTRAINT ck_release_snapshot_json CHECK (jsonb_typeof(approved_snapshot) = 'object'),
    CONSTRAINT ck_release_snapshot_version CHECK (version > 0)
);

CREATE TABLE release.drift_detection_results (
    id uuid NOT NULL,
    tenant_id uuid NOT NULL,
    deployment_id uuid NOT NULL,
    status varchar(40) NOT NULL,
    drift_types jsonb NOT NULL DEFAULT '[]'::jsonb,
    expected jsonb NOT NULL DEFAULT '{}'::jsonb,
    actual jsonb NOT NULL DEFAULT '{}'::jsonb,
    reviewed_by uuid,
    created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    version bigint NOT NULL DEFAULT 1,
    PRIMARY KEY (tenant_id, id),
    CONSTRAINT fk_release_drift_deployment FOREIGN KEY (tenant_id, deployment_id)
        REFERENCES release.deployment_records (tenant_id, id) ON UPDATE RESTRICT ON DELETE RESTRICT,
    CONSTRAINT fk_release_drift_reviewer FOREIGN KEY (tenant_id, reviewed_by)
        REFERENCES iam.users (tenant_id, id) ON UPDATE RESTRICT ON DELETE RESTRICT,
    CONSTRAINT ck_release_drift_status CHECK (status IN ('healthy','drift_detected','unknown')),
    CONSTRAINT ck_release_drift_types CHECK (jsonb_typeof(drift_types) = 'array'),
    CONSTRAINT ck_release_drift_expected CHECK (jsonb_typeof(expected) = 'object'),
    CONSTRAINT ck_release_drift_actual CHECK (jsonb_typeof(actual) = 'object'),
    CONSTRAINT ck_release_drift_version CHECK (version > 0)
);

CREATE TABLE release.compliance_evidence_packages (
    id uuid NOT NULL,
    tenant_id uuid NOT NULL,
    candidate_id uuid NOT NULL,
    package_digest varchar(128) NOT NULL,
    contents jsonb NOT NULL DEFAULT '{}'::jsonb,
    generated_by uuid NOT NULL,
    created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    version bigint NOT NULL DEFAULT 1,
    PRIMARY KEY (tenant_id, id),
    CONSTRAINT uq_release_compliance_package UNIQUE (tenant_id, candidate_id, package_digest),
    CONSTRAINT fk_release_compliance_candidate FOREIGN KEY (tenant_id, candidate_id)
        REFERENCES release.candidates (tenant_id, id) ON UPDATE RESTRICT ON DELETE RESTRICT,
    CONSTRAINT fk_release_compliance_generator FOREIGN KEY (tenant_id, generated_by)
        REFERENCES iam.users (tenant_id, id) ON UPDATE RESTRICT ON DELETE RESTRICT,
    CONSTRAINT ck_release_compliance_contents CHECK (jsonb_typeof(contents) = 'object'),
    CONSTRAINT ck_release_compliance_version CHECK (version > 0)
);

CREATE INDEX idx_release_artifacts_project
    ON release.artifacts (tenant_id, project_id, created_at DESC);
CREATE INDEX idx_release_candidates_project
    ON release.candidates (tenant_id, project_id, updated_at DESC);
CREATE INDEX idx_release_gates_candidate
    ON release.gate_results (tenant_id, candidate_id, environment, gate_id);
CREATE INDEX idx_release_exceptions_candidate
    ON release.exceptions (tenant_id, candidate_id, gate_id, status);
CREATE INDEX idx_release_promotions_candidate
    ON release.environment_promotions (tenant_id, candidate_id, environment);
CREATE INDEX idx_release_deployments_candidate
    ON release.deployment_records (tenant_id, candidate_id, environment, created_at DESC);
CREATE INDEX idx_release_drift_deployment
    ON release.drift_detection_results (tenant_id, deployment_id, created_at DESC);
CREATE INDEX idx_release_compliance_candidate
    ON release.compliance_evidence_packages (tenant_id, candidate_id, created_at DESC);

ALTER TABLE release.artifacts ENABLE ROW LEVEL SECURITY;
ALTER TABLE release.artifacts FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation_release_artifacts ON release.artifacts
    USING (tenant_id = current_setting('vulnlab.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('vulnlab.tenant_id', true)::uuid);

ALTER TABLE release.sbom_documents ENABLE ROW LEVEL SECURITY;
ALTER TABLE release.sbom_documents FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation_release_sbom_documents ON release.sbom_documents
    USING (tenant_id = current_setting('vulnlab.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('vulnlab.tenant_id', true)::uuid);

ALTER TABLE release.provenance_statements ENABLE ROW LEVEL SECURITY;
ALTER TABLE release.provenance_statements FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation_release_provenance_statements ON release.provenance_statements
    USING (tenant_id = current_setting('vulnlab.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('vulnlab.tenant_id', true)::uuid);

ALTER TABLE release.signature_records ENABLE ROW LEVEL SECURITY;
ALTER TABLE release.signature_records FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation_release_signature_records ON release.signature_records
    USING (tenant_id = current_setting('vulnlab.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('vulnlab.tenant_id', true)::uuid);

ALTER TABLE release.security_scan_results ENABLE ROW LEVEL SECURITY;
ALTER TABLE release.security_scan_results FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation_release_security_scan_results ON release.security_scan_results
    USING (tenant_id = current_setting('vulnlab.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('vulnlab.tenant_id', true)::uuid);

ALTER TABLE release.license_scan_results ENABLE ROW LEVEL SECURITY;
ALTER TABLE release.license_scan_results FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation_release_license_scan_results ON release.license_scan_results
    USING (tenant_id = current_setting('vulnlab.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('vulnlab.tenant_id', true)::uuid);

ALTER TABLE release.candidates ENABLE ROW LEVEL SECURITY;
ALTER TABLE release.candidates FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation_release_candidates ON release.candidates
    USING (tenant_id = current_setting('vulnlab.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('vulnlab.tenant_id', true)::uuid);

ALTER TABLE release.gate_results ENABLE ROW LEVEL SECURITY;
ALTER TABLE release.gate_results FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation_release_gate_results ON release.gate_results
    USING (tenant_id = current_setting('vulnlab.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('vulnlab.tenant_id', true)::uuid);

ALTER TABLE release.approvals ENABLE ROW LEVEL SECURITY;
ALTER TABLE release.approvals FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation_release_approvals ON release.approvals
    USING (tenant_id = current_setting('vulnlab.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('vulnlab.tenant_id', true)::uuid);

ALTER TABLE release.exceptions ENABLE ROW LEVEL SECURITY;
ALTER TABLE release.exceptions FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation_release_exceptions ON release.exceptions
    USING (tenant_id = current_setting('vulnlab.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('vulnlab.tenant_id', true)::uuid);

ALTER TABLE release.environment_promotions ENABLE ROW LEVEL SECURITY;
ALTER TABLE release.environment_promotions FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation_release_environment_promotions ON release.environment_promotions
    USING (tenant_id = current_setting('vulnlab.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('vulnlab.tenant_id', true)::uuid);

ALTER TABLE release.deployment_records ENABLE ROW LEVEL SECURITY;
ALTER TABLE release.deployment_records FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation_release_deployment_records ON release.deployment_records
    USING (tenant_id = current_setting('vulnlab.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('vulnlab.tenant_id', true)::uuid);

ALTER TABLE release.rollback_records ENABLE ROW LEVEL SECURITY;
ALTER TABLE release.rollback_records FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation_release_rollback_records ON release.rollback_records
    USING (tenant_id = current_setting('vulnlab.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('vulnlab.tenant_id', true)::uuid);

ALTER TABLE release.configuration_snapshots ENABLE ROW LEVEL SECURITY;
ALTER TABLE release.configuration_snapshots FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation_release_configuration_snapshots ON release.configuration_snapshots
    USING (tenant_id = current_setting('vulnlab.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('vulnlab.tenant_id', true)::uuid);

ALTER TABLE release.drift_detection_results ENABLE ROW LEVEL SECURITY;
ALTER TABLE release.drift_detection_results FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation_release_drift_detection_results ON release.drift_detection_results
    USING (tenant_id = current_setting('vulnlab.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('vulnlab.tenant_id', true)::uuid);

ALTER TABLE release.compliance_evidence_packages ENABLE ROW LEVEL SECURITY;
ALTER TABLE release.compliance_evidence_packages FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation_release_compliance_evidence_packages ON release.compliance_evidence_packages
    USING (tenant_id = current_setting('vulnlab.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('vulnlab.tenant_id', true)::uuid);

GRANT USAGE ON SCHEMA release TO vulnlab_app;
GRANT SELECT, INSERT, UPDATE ON ALL TABLES IN SCHEMA release TO vulnlab_app;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA release TO vulnlab_app;

COMMIT;
