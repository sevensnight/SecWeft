BEGIN;

CREATE SCHEMA IF NOT EXISTS case_mgmt;

CREATE TABLE case_mgmt.vulnerability_cases (
    id uuid NOT NULL,
    tenant_id uuid NOT NULL,
    project_id uuid NOT NULL,
    title varchar(240) NOT NULL,
    summary text NOT NULL,
    severity varchar(24) NOT NULL,
    status varchar(40) NOT NULL,
    source varchar(40) NOT NULL DEFAULT 'MANUAL',
    external_ref varchar(240),
    metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
    created_by uuid NOT NULL,
    updated_by uuid NOT NULL,
    created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    version bigint NOT NULL DEFAULT 1,
    PRIMARY KEY (tenant_id, id),
    CONSTRAINT fk_case_tenant FOREIGN KEY (tenant_id)
        REFERENCES iam.tenants (id) ON UPDATE RESTRICT ON DELETE RESTRICT,
    CONSTRAINT fk_case_project FOREIGN KEY (tenant_id, project_id)
        REFERENCES iam.projects (tenant_id, id) ON UPDATE RESTRICT ON DELETE RESTRICT,
    CONSTRAINT fk_case_creator FOREIGN KEY (tenant_id, created_by)
        REFERENCES iam.users (tenant_id, id) ON UPDATE RESTRICT ON DELETE RESTRICT,
    CONSTRAINT fk_case_updater FOREIGN KEY (tenant_id, updated_by)
        REFERENCES iam.users (tenant_id, id) ON UPDATE RESTRICT ON DELETE RESTRICT,
    CONSTRAINT ck_case_severity CHECK (severity IN ('informational','low','medium','high','critical')),
    CONSTRAINT ck_case_status CHECK (
        status IN (
            'DRAFT','TRIAGE','VALIDATION_PENDING','VALIDATED',
            'REMEDIATION_PLANNED','REMEDIATION_IN_PROGRESS',
            'RETEST_PENDING','REMEDIATED','ACCEPTED_RISK',
            'FALSE_POSITIVE','INCONCLUSIVE','CLOSED'
        )
    ),
    CONSTRAINT ck_case_metadata CHECK (jsonb_typeof(metadata) = 'object'),
    CONSTRAINT ck_case_version CHECK (version > 0),
    CONSTRAINT ck_case_timestamps CHECK (updated_at >= created_at)
);

CREATE INDEX idx_case_mgmt_cases_project_status
    ON case_mgmt.vulnerability_cases (tenant_id, project_id, status, updated_at DESC);

CREATE TABLE case_mgmt.case_findings (
    id uuid NOT NULL,
    case_id uuid NOT NULL,
    tenant_id uuid NOT NULL,
    project_id uuid NOT NULL,
    validation_execution_id uuid,
    evidence_id uuid,
    title varchar(240) NOT NULL,
    description text NOT NULL,
    affected_component varchar(240),
    risk_level varchar(24) NOT NULL,
    status varchar(40) NOT NULL,
    metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
    created_by uuid NOT NULL,
    created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    version bigint NOT NULL DEFAULT 1,
    PRIMARY KEY (tenant_id, id),
    CONSTRAINT fk_case_finding_case FOREIGN KEY (tenant_id, case_id)
        REFERENCES case_mgmt.vulnerability_cases (tenant_id, id) ON UPDATE RESTRICT ON DELETE CASCADE,
    CONSTRAINT fk_case_finding_project FOREIGN KEY (tenant_id, project_id)
        REFERENCES iam.projects (tenant_id, id) ON UPDATE RESTRICT ON DELETE RESTRICT,
    CONSTRAINT fk_case_finding_execution FOREIGN KEY (tenant_id, validation_execution_id)
        REFERENCES validation.executions (tenant_id, id) ON UPDATE RESTRICT ON DELETE RESTRICT,
    CONSTRAINT fk_case_finding_evidence FOREIGN KEY (tenant_id, evidence_id)
        REFERENCES validation.execution_evidence (tenant_id, id) ON UPDATE RESTRICT ON DELETE RESTRICT,
    CONSTRAINT fk_case_finding_creator FOREIGN KEY (tenant_id, created_by)
        REFERENCES iam.users (tenant_id, id) ON UPDATE RESTRICT ON DELETE RESTRICT,
    CONSTRAINT ck_case_finding_risk CHECK (risk_level IN ('informational','low','medium','high','critical')),
    CONSTRAINT ck_case_finding_status CHECK (status IN ('CANDIDATE','VALIDATED','FALSE_POSITIVE','REMEDIATED','INCONCLUSIVE')),
    CONSTRAINT ck_case_finding_metadata CHECK (jsonb_typeof(metadata) = 'object'),
    CONSTRAINT ck_case_finding_version CHECK (version > 0),
    CONSTRAINT ck_case_finding_timestamps CHECK (updated_at >= created_at)
);

CREATE INDEX idx_case_mgmt_findings_case
    ON case_mgmt.case_findings (tenant_id, case_id, created_at DESC);

CREATE TABLE case_mgmt.remediation_proposals (
    id uuid NOT NULL,
    case_id uuid NOT NULL,
    tenant_id uuid NOT NULL,
    project_id uuid NOT NULL,
    source varchar(40) NOT NULL,
    title varchar(240) NOT NULL,
    description text NOT NULL,
    risk_level varchar(24) NOT NULL,
    knowledge_refs jsonb NOT NULL DEFAULT '[]'::jsonb,
    model_invocation_id uuid,
    provenance jsonb NOT NULL DEFAULT '{}'::jsonb,
    status varchar(40) NOT NULL,
    proposed_by uuid NOT NULL,
    created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    version bigint NOT NULL DEFAULT 1,
    PRIMARY KEY (tenant_id, id),
    CONSTRAINT fk_remediation_proposal_case FOREIGN KEY (tenant_id, case_id)
        REFERENCES case_mgmt.vulnerability_cases (tenant_id, id) ON UPDATE RESTRICT ON DELETE CASCADE,
    CONSTRAINT fk_remediation_proposal_project FOREIGN KEY (tenant_id, project_id)
        REFERENCES iam.projects (tenant_id, id) ON UPDATE RESTRICT ON DELETE RESTRICT,
    CONSTRAINT fk_remediation_proposal_user FOREIGN KEY (tenant_id, proposed_by)
        REFERENCES iam.users (tenant_id, id) ON UPDATE RESTRICT ON DELETE RESTRICT,
    CONSTRAINT ck_remediation_proposal_source CHECK (source IN ('AI_GENERATED','KNOWLEDGE_BASE','VENDOR_ADVISORY','MANUAL')),
    CONSTRAINT ck_remediation_proposal_risk CHECK (risk_level IN ('low','medium','high')),
    CONSTRAINT ck_remediation_proposal_status CHECK (status IN ('PROPOSED','APPROVED','REJECTED','CHANGES_REQUESTED')),
    CONSTRAINT ck_remediation_proposal_knowledge_refs CHECK (jsonb_typeof(knowledge_refs) = 'array'),
    CONSTRAINT ck_remediation_proposal_provenance CHECK (jsonb_typeof(provenance) = 'object'),
    CONSTRAINT ck_remediation_proposal_version CHECK (version > 0),
    CONSTRAINT ck_remediation_proposal_timestamps CHECK (updated_at >= created_at)
);

CREATE INDEX idx_case_mgmt_proposals_case
    ON case_mgmt.remediation_proposals (tenant_id, case_id, created_at DESC);

CREATE TABLE case_mgmt.remediation_decisions (
    id uuid NOT NULL,
    proposal_id uuid NOT NULL,
    case_id uuid NOT NULL,
    tenant_id uuid NOT NULL,
    project_id uuid NOT NULL,
    decision varchar(40) NOT NULL,
    reason text NOT NULL,
    automated boolean NOT NULL DEFAULT false,
    decided_by uuid NOT NULL,
    decided_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    version bigint NOT NULL DEFAULT 1,
    PRIMARY KEY (tenant_id, id),
    CONSTRAINT fk_remediation_decision_proposal FOREIGN KEY (tenant_id, proposal_id)
        REFERENCES case_mgmt.remediation_proposals (tenant_id, id) ON UPDATE RESTRICT ON DELETE CASCADE,
    CONSTRAINT fk_remediation_decision_case FOREIGN KEY (tenant_id, case_id)
        REFERENCES case_mgmt.vulnerability_cases (tenant_id, id) ON UPDATE RESTRICT ON DELETE CASCADE,
    CONSTRAINT fk_remediation_decision_project FOREIGN KEY (tenant_id, project_id)
        REFERENCES iam.projects (tenant_id, id) ON UPDATE RESTRICT ON DELETE RESTRICT,
    CONSTRAINT fk_remediation_decision_user FOREIGN KEY (tenant_id, decided_by)
        REFERENCES iam.users (tenant_id, id) ON UPDATE RESTRICT ON DELETE RESTRICT,
    CONSTRAINT ck_remediation_decision_value CHECK (decision IN ('APPROVED','REJECTED','CHANGES_REQUESTED')),
    CONSTRAINT ck_remediation_decision_version CHECK (version > 0),
    CONSTRAINT ck_remediation_decision_timestamps CHECK (updated_at >= created_at)
);

CREATE INDEX idx_case_mgmt_decisions_proposal
    ON case_mgmt.remediation_decisions (tenant_id, proposal_id, decided_at DESC);

CREATE TABLE case_mgmt.remediation_implementations (
    id uuid NOT NULL,
    decision_id uuid NOT NULL,
    proposal_id uuid NOT NULL,
    case_id uuid NOT NULL,
    tenant_id uuid NOT NULL,
    project_id uuid NOT NULL,
    implementation_ref varchar(500) NOT NULL,
    description text NOT NULL,
    implemented_by uuid NOT NULL,
    implemented_at timestamptz NOT NULL,
    verification_notes text,
    created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    version bigint NOT NULL DEFAULT 1,
    PRIMARY KEY (tenant_id, id),
    CONSTRAINT fk_remediation_impl_decision FOREIGN KEY (tenant_id, decision_id)
        REFERENCES case_mgmt.remediation_decisions (tenant_id, id) ON UPDATE RESTRICT ON DELETE CASCADE,
    CONSTRAINT fk_remediation_impl_proposal FOREIGN KEY (tenant_id, proposal_id)
        REFERENCES case_mgmt.remediation_proposals (tenant_id, id) ON UPDATE RESTRICT ON DELETE CASCADE,
    CONSTRAINT fk_remediation_impl_case FOREIGN KEY (tenant_id, case_id)
        REFERENCES case_mgmt.vulnerability_cases (tenant_id, id) ON UPDATE RESTRICT ON DELETE CASCADE,
    CONSTRAINT fk_remediation_impl_project FOREIGN KEY (tenant_id, project_id)
        REFERENCES iam.projects (tenant_id, id) ON UPDATE RESTRICT ON DELETE RESTRICT,
    CONSTRAINT fk_remediation_impl_user FOREIGN KEY (tenant_id, implemented_by)
        REFERENCES iam.users (tenant_id, id) ON UPDATE RESTRICT ON DELETE RESTRICT,
    CONSTRAINT ck_remediation_impl_version CHECK (version > 0),
    CONSTRAINT ck_remediation_impl_timestamps CHECK (updated_at >= created_at)
);

CREATE INDEX idx_case_mgmt_implementations_case
    ON case_mgmt.remediation_implementations (tenant_id, case_id, created_at DESC);

CREATE TABLE case_mgmt.retest_requests (
    id uuid NOT NULL,
    case_id uuid NOT NULL,
    finding_id uuid NOT NULL,
    tenant_id uuid NOT NULL,
    project_id uuid NOT NULL,
    original_execution_id uuid NOT NULL,
    remediation_implementation_id uuid NOT NULL,
    retest_execution_id uuid NOT NULL,
    status varchar(40) NOT NULL,
    template_id varchar(120) NOT NULL,
    template_version varchar(40) NOT NULL,
    template_version_changed boolean NOT NULL DEFAULT false,
    requested_by uuid NOT NULL,
    requested_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    version bigint NOT NULL DEFAULT 1,
    PRIMARY KEY (tenant_id, id),
    CONSTRAINT uq_case_mgmt_retest UNIQUE (
        tenant_id, case_id, finding_id, remediation_implementation_id, original_execution_id
    ),
    CONSTRAINT fk_retest_case FOREIGN KEY (tenant_id, case_id)
        REFERENCES case_mgmt.vulnerability_cases (tenant_id, id) ON UPDATE RESTRICT ON DELETE CASCADE,
    CONSTRAINT fk_retest_finding FOREIGN KEY (tenant_id, finding_id)
        REFERENCES case_mgmt.case_findings (tenant_id, id) ON UPDATE RESTRICT ON DELETE CASCADE,
    CONSTRAINT fk_retest_implementation FOREIGN KEY (tenant_id, remediation_implementation_id)
        REFERENCES case_mgmt.remediation_implementations (tenant_id, id) ON UPDATE RESTRICT ON DELETE RESTRICT,
    CONSTRAINT fk_retest_original_execution FOREIGN KEY (tenant_id, original_execution_id)
        REFERENCES validation.executions (tenant_id, id) ON UPDATE RESTRICT ON DELETE RESTRICT,
    CONSTRAINT fk_retest_execution FOREIGN KEY (tenant_id, retest_execution_id)
        REFERENCES validation.executions (tenant_id, id) ON UPDATE RESTRICT ON DELETE RESTRICT,
    CONSTRAINT fk_retest_project FOREIGN KEY (tenant_id, project_id)
        REFERENCES iam.projects (tenant_id, id) ON UPDATE RESTRICT ON DELETE RESTRICT,
    CONSTRAINT fk_retest_user FOREIGN KEY (tenant_id, requested_by)
        REFERENCES iam.users (tenant_id, id) ON UPDATE RESTRICT ON DELETE RESTRICT,
    CONSTRAINT ck_retest_status CHECK (status IN ('REQUESTED','QUEUED','RUNNING','COMPLETED','CANCELLED','INCONCLUSIVE')),
    CONSTRAINT ck_retest_version CHECK (version > 0),
    CONSTRAINT ck_retest_timestamps CHECK (updated_at >= created_at)
);

CREATE INDEX idx_case_mgmt_retests_case
    ON case_mgmt.retest_requests (tenant_id, case_id, created_at DESC);

CREATE TABLE case_mgmt.validation_comparisons (
    id uuid NOT NULL,
    retest_id uuid NOT NULL,
    case_id uuid NOT NULL,
    finding_id uuid NOT NULL,
    tenant_id uuid NOT NULL,
    project_id uuid NOT NULL,
    original_execution_id uuid NOT NULL,
    retest_execution_id uuid NOT NULL,
    result varchar(40) NOT NULL,
    initial_status varchar(40) NOT NULL,
    retest_status varchar(40) NOT NULL,
    success_condition_diff jsonb NOT NULL DEFAULT '{}'::jsonb,
    key_response_diff jsonb NOT NULL DEFAULT '{}'::jsonb,
    component_version_diff jsonb NOT NULL DEFAULT '{}'::jsonb,
    evidence_sha256 jsonb NOT NULL DEFAULT '{}'::jsonb,
    risk_level_change varchar(40),
    residual_risk text,
    recommendation text,
    reviewed_by uuid,
    reviewed_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    version bigint NOT NULL DEFAULT 1,
    PRIMARY KEY (tenant_id, id),
    CONSTRAINT uq_case_mgmt_comparison_retest UNIQUE (tenant_id, retest_id),
    CONSTRAINT fk_comparison_retest FOREIGN KEY (tenant_id, retest_id)
        REFERENCES case_mgmt.retest_requests (tenant_id, id) ON UPDATE RESTRICT ON DELETE CASCADE,
    CONSTRAINT fk_comparison_case FOREIGN KEY (tenant_id, case_id)
        REFERENCES case_mgmt.vulnerability_cases (tenant_id, id) ON UPDATE RESTRICT ON DELETE CASCADE,
    CONSTRAINT fk_comparison_finding FOREIGN KEY (tenant_id, finding_id)
        REFERENCES case_mgmt.case_findings (tenant_id, id) ON UPDATE RESTRICT ON DELETE CASCADE,
    CONSTRAINT fk_comparison_original_execution FOREIGN KEY (tenant_id, original_execution_id)
        REFERENCES validation.executions (tenant_id, id) ON UPDATE RESTRICT ON DELETE RESTRICT,
    CONSTRAINT fk_comparison_retest_execution FOREIGN KEY (tenant_id, retest_execution_id)
        REFERENCES validation.executions (tenant_id, id) ON UPDATE RESTRICT ON DELETE RESTRICT,
    CONSTRAINT fk_comparison_project FOREIGN KEY (tenant_id, project_id)
        REFERENCES iam.projects (tenant_id, id) ON UPDATE RESTRICT ON DELETE RESTRICT,
    CONSTRAINT fk_comparison_reviewer FOREIGN KEY (tenant_id, reviewed_by)
        REFERENCES iam.users (tenant_id, id) ON UPDATE RESTRICT ON DELETE RESTRICT,
    CONSTRAINT ck_comparison_result CHECK (
        result IN ('REMEDIATED','PARTIALLY_REMEDIATED','NOT_REMEDIATED','REGRESSION','INCONCLUSIVE')
    ),
    CONSTRAINT ck_comparison_success_diff CHECK (jsonb_typeof(success_condition_diff) = 'object'),
    CONSTRAINT ck_comparison_response_diff CHECK (jsonb_typeof(key_response_diff) = 'object'),
    CONSTRAINT ck_comparison_component_diff CHECK (jsonb_typeof(component_version_diff) = 'object'),
    CONSTRAINT ck_comparison_evidence_sha CHECK (jsonb_typeof(evidence_sha256) = 'object'),
    CONSTRAINT ck_comparison_version CHECK (version > 0),
    CONSTRAINT ck_comparison_timestamps CHECK (updated_at >= created_at)
);

CREATE INDEX idx_case_mgmt_comparisons_case
    ON case_mgmt.validation_comparisons (tenant_id, case_id, created_at DESC);

CREATE TABLE case_mgmt.case_dispositions (
    id uuid NOT NULL,
    case_id uuid NOT NULL,
    tenant_id uuid NOT NULL,
    project_id uuid NOT NULL,
    disposition varchar(40) NOT NULL,
    reason text NOT NULL,
    residual_risk text,
    human_confirmed boolean NOT NULL DEFAULT true,
    decided_by uuid NOT NULL,
    decided_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    version bigint NOT NULL DEFAULT 1,
    PRIMARY KEY (tenant_id, id),
    CONSTRAINT fk_disposition_case FOREIGN KEY (tenant_id, case_id)
        REFERENCES case_mgmt.vulnerability_cases (tenant_id, id) ON UPDATE RESTRICT ON DELETE CASCADE,
    CONSTRAINT fk_disposition_project FOREIGN KEY (tenant_id, project_id)
        REFERENCES iam.projects (tenant_id, id) ON UPDATE RESTRICT ON DELETE RESTRICT,
    CONSTRAINT fk_disposition_user FOREIGN KEY (tenant_id, decided_by)
        REFERENCES iam.users (tenant_id, id) ON UPDATE RESTRICT ON DELETE RESTRICT,
    CONSTRAINT ck_disposition_value CHECK (disposition IN ('REMEDIATED','ACCEPTED_RISK','FALSE_POSITIVE','INCONCLUSIVE')),
    CONSTRAINT ck_disposition_human CHECK (human_confirmed IS TRUE),
    CONSTRAINT ck_disposition_version CHECK (version > 0),
    CONSTRAINT ck_disposition_timestamps CHECK (updated_at >= created_at)
);

CREATE INDEX idx_case_mgmt_dispositions_case
    ON case_mgmt.case_dispositions (tenant_id, case_id, decided_at DESC);

CREATE TABLE case_mgmt.case_reports (
    id uuid NOT NULL,
    case_id uuid NOT NULL,
    tenant_id uuid NOT NULL,
    project_id uuid NOT NULL,
    title varchar(240) NOT NULL,
    report jsonb NOT NULL,
    generated_by uuid NOT NULL,
    generated_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    version bigint NOT NULL DEFAULT 1,
    PRIMARY KEY (tenant_id, id),
    CONSTRAINT fk_report_case FOREIGN KEY (tenant_id, case_id)
        REFERENCES case_mgmt.vulnerability_cases (tenant_id, id) ON UPDATE RESTRICT ON DELETE CASCADE,
    CONSTRAINT fk_report_project FOREIGN KEY (tenant_id, project_id)
        REFERENCES iam.projects (tenant_id, id) ON UPDATE RESTRICT ON DELETE RESTRICT,
    CONSTRAINT fk_report_user FOREIGN KEY (tenant_id, generated_by)
        REFERENCES iam.users (tenant_id, id) ON UPDATE RESTRICT ON DELETE RESTRICT,
    CONSTRAINT ck_report_json CHECK (jsonb_typeof(report) = 'object'),
    CONSTRAINT ck_report_version CHECK (version > 0),
    CONSTRAINT ck_report_timestamps CHECK (updated_at >= created_at)
);

CREATE INDEX idx_case_mgmt_reports_case
    ON case_mgmt.case_reports (tenant_id, case_id, generated_at DESC);

GRANT USAGE ON SCHEMA case_mgmt TO vulnlab_app;
GRANT SELECT, INSERT, UPDATE ON ALL TABLES IN SCHEMA case_mgmt TO vulnlab_app;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA case_mgmt TO vulnlab_app;

COMMIT;
