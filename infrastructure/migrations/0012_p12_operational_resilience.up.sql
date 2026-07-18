BEGIN;

CREATE SCHEMA IF NOT EXISTS resilience;

CREATE TABLE resilience.capacity_quotas (
    id uuid NOT NULL,
    tenant_id uuid NOT NULL,
    quota_type varchar(80) NOT NULL,
    subject_id varchar(160) NOT NULL,
    max_concurrency integer NOT NULL,
    weight integer NOT NULL DEFAULT 1,
    priority integer NOT NULL DEFAULT 100,
    metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
    created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    version bigint NOT NULL DEFAULT 1,
    PRIMARY KEY (tenant_id, id),
    CONSTRAINT uq_resilience_capacity_quota UNIQUE (tenant_id, quota_type, subject_id),
    CONSTRAINT fk_resilience_quota_tenant FOREIGN KEY (tenant_id)
        REFERENCES iam.tenants (id) ON UPDATE RESTRICT ON DELETE RESTRICT,
    CONSTRAINT ck_resilience_quota_type CHECK (
        quota_type IN (
            'tenant_concurrency','project_concurrency','global_concurrency',
            'model_concurrency','sandbox_capacity','queue_backlog','api_rate_limit'
        )
    ),
    CONSTRAINT ck_resilience_quota_positive CHECK (
        max_concurrency > 0 AND weight > 0 AND priority >= 0
    ),
    CONSTRAINT ck_resilience_quota_metadata CHECK (jsonb_typeof(metadata) = 'object'),
    CONSTRAINT ck_resilience_quota_version CHECK (version > 0),
    CONSTRAINT ck_resilience_quota_timestamps CHECK (updated_at >= created_at)
);

CREATE TABLE resilience.service_instances (
    id uuid NOT NULL,
    tenant_id uuid NOT NULL,
    kind varchar(40) NOT NULL,
    status varchar(40) NOT NULL,
    metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
    last_heartbeat_at timestamptz NOT NULL,
    created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    version bigint NOT NULL DEFAULT 1,
    PRIMARY KEY (tenant_id, id),
    CONSTRAINT fk_resilience_instance_tenant FOREIGN KEY (tenant_id)
        REFERENCES iam.tenants (id) ON UPDATE RESTRICT ON DELETE RESTRICT,
    CONSTRAINT ck_resilience_instance_kind CHECK (
        kind IN ('control_plane','validation_worker','api_gateway','scheduler')
    ),
    CONSTRAINT ck_resilience_instance_status CHECK (
        status IN ('starting','ready','draining','terminated')
    ),
    CONSTRAINT ck_resilience_instance_metadata CHECK (jsonb_typeof(metadata) = 'object'),
    CONSTRAINT ck_resilience_instance_version CHECK (version > 0),
    CONSTRAINT ck_resilience_instance_timestamps CHECK (
        updated_at >= created_at AND last_heartbeat_at >= created_at
    )
);

CREATE TABLE resilience.worker_heartbeats (
    id uuid NOT NULL,
    tenant_id uuid NOT NULL,
    worker_id varchar(160) NOT NULL,
    active_executions integer NOT NULL DEFAULT 0,
    sandbox_capacity integer NOT NULL DEFAULT 0,
    metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
    last_heartbeat_at timestamptz NOT NULL,
    created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    version bigint NOT NULL DEFAULT 1,
    PRIMARY KEY (tenant_id, id),
    CONSTRAINT uq_resilience_worker UNIQUE (tenant_id, worker_id),
    CONSTRAINT fk_resilience_worker_tenant FOREIGN KEY (tenant_id)
        REFERENCES iam.tenants (id) ON UPDATE RESTRICT ON DELETE RESTRICT,
    CONSTRAINT ck_resilience_worker_capacity CHECK (
        active_executions >= 0 AND sandbox_capacity >= 0
    ),
    CONSTRAINT ck_resilience_worker_metadata CHECK (jsonb_typeof(metadata) = 'object'),
    CONSTRAINT ck_resilience_worker_version CHECK (version > 0),
    CONSTRAINT ck_resilience_worker_timestamps CHECK (
        updated_at >= created_at AND last_heartbeat_at >= created_at
    )
);

CREATE TABLE resilience.evidence_consistency_reports (
    id uuid NOT NULL,
    tenant_id uuid NOT NULL,
    status varchar(40) NOT NULL,
    summary jsonb NOT NULL DEFAULT '{}'::jsonb,
    findings jsonb NOT NULL DEFAULT '[]'::jsonb,
    repair_action varchar(80) NOT NULL DEFAULT 'none',
    created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    version bigint NOT NULL DEFAULT 1,
    PRIMARY KEY (tenant_id, id),
    CONSTRAINT fk_resilience_evidence_report_tenant FOREIGN KEY (tenant_id)
        REFERENCES iam.tenants (id) ON UPDATE RESTRICT ON DELETE RESTRICT,
    CONSTRAINT ck_resilience_evidence_report_status CHECK (status IN ('healthy','inconsistent')),
    CONSTRAINT ck_resilience_evidence_report_summary CHECK (jsonb_typeof(summary) = 'object'),
    CONSTRAINT ck_resilience_evidence_report_findings CHECK (jsonb_typeof(findings) = 'array'),
    CONSTRAINT ck_resilience_evidence_report_version CHECK (version > 0),
    CONSTRAINT ck_resilience_evidence_report_timestamps CHECK (updated_at >= created_at)
);

CREATE TABLE resilience.backup_restore_drills (
    id uuid NOT NULL,
    tenant_id uuid NOT NULL,
    drill_type varchar(40) NOT NULL,
    status varchar(40) NOT NULL,
    rpo_seconds integer,
    rto_seconds integer,
    manifest jsonb NOT NULL DEFAULT '{}'::jsonb,
    validation jsonb NOT NULL DEFAULT '{}'::jsonb,
    created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    version bigint NOT NULL DEFAULT 1,
    PRIMARY KEY (tenant_id, id),
    CONSTRAINT fk_resilience_drill_tenant FOREIGN KEY (tenant_id)
        REFERENCES iam.tenants (id) ON UPDATE RESTRICT ON DELETE RESTRICT,
    CONSTRAINT ck_resilience_drill_type CHECK (drill_type IN ('backup','restore','full_dr')),
    CONSTRAINT ck_resilience_drill_status CHECK (
        status IN ('planned','running','succeeded','failed','aborted')
    ),
    CONSTRAINT ck_resilience_drill_measurement CHECK (
        (rpo_seconds IS NULL OR rpo_seconds >= 0) AND (rto_seconds IS NULL OR rto_seconds >= 0)
    ),
    CONSTRAINT ck_resilience_drill_manifest CHECK (jsonb_typeof(manifest) = 'object'),
    CONSTRAINT ck_resilience_drill_validation CHECK (jsonb_typeof(validation) = 'object'),
    CONSTRAINT ck_resilience_drill_version CHECK (version > 0),
    CONSTRAINT ck_resilience_drill_timestamps CHECK (updated_at >= created_at)
);

CREATE TABLE resilience.failure_injection_events (
    id uuid NOT NULL,
    tenant_id uuid NOT NULL,
    failure_type varchar(80) NOT NULL,
    target varchar(200) NOT NULL,
    status varchar(40) NOT NULL,
    isolated_environment boolean NOT NULL DEFAULT true,
    metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
    created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    version bigint NOT NULL DEFAULT 1,
    PRIMARY KEY (tenant_id, id),
    CONSTRAINT fk_resilience_failure_event_tenant FOREIGN KEY (tenant_id)
        REFERENCES iam.tenants (id) ON UPDATE RESTRICT ON DELETE RESTRICT,
    CONSTRAINT ck_resilience_failure_event_status CHECK (
        status IN ('planned','running','succeeded','failed','blocked')
    ),
    CONSTRAINT ck_resilience_failure_event_metadata CHECK (jsonb_typeof(metadata) = 'object'),
    CONSTRAINT ck_resilience_failure_event_version CHECK (version > 0),
    CONSTRAINT ck_resilience_failure_event_timestamps CHECK (updated_at >= created_at)
);

CREATE INDEX idx_resilience_capacity_quota_subject
    ON resilience.capacity_quotas (tenant_id, quota_type, subject_id);

CREATE INDEX idx_resilience_instance_kind
    ON resilience.service_instances (tenant_id, kind, status, updated_at DESC);

CREATE INDEX idx_resilience_worker_heartbeat
    ON resilience.worker_heartbeats (tenant_id, last_heartbeat_at DESC);

CREATE INDEX idx_resilience_evidence_report
    ON resilience.evidence_consistency_reports (tenant_id, created_at DESC);

CREATE INDEX idx_resilience_drill_status
    ON resilience.backup_restore_drills (tenant_id, status, created_at DESC);

CREATE INDEX idx_resilience_failure_event_status
    ON resilience.failure_injection_events (tenant_id, status, created_at DESC);

ALTER TABLE resilience.capacity_quotas ENABLE ROW LEVEL SECURITY;
ALTER TABLE resilience.capacity_quotas FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation_capacity_quotas ON resilience.capacity_quotas
    USING (tenant_id = current_setting('vulnlab.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('vulnlab.tenant_id', true)::uuid);

ALTER TABLE resilience.service_instances ENABLE ROW LEVEL SECURITY;
ALTER TABLE resilience.service_instances FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation_service_instances ON resilience.service_instances
    USING (tenant_id = current_setting('vulnlab.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('vulnlab.tenant_id', true)::uuid);

ALTER TABLE resilience.worker_heartbeats ENABLE ROW LEVEL SECURITY;
ALTER TABLE resilience.worker_heartbeats FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation_worker_heartbeats ON resilience.worker_heartbeats
    USING (tenant_id = current_setting('vulnlab.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('vulnlab.tenant_id', true)::uuid);

ALTER TABLE resilience.evidence_consistency_reports ENABLE ROW LEVEL SECURITY;
ALTER TABLE resilience.evidence_consistency_reports FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation_evidence_consistency_reports ON resilience.evidence_consistency_reports
    USING (tenant_id = current_setting('vulnlab.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('vulnlab.tenant_id', true)::uuid);

ALTER TABLE resilience.backup_restore_drills ENABLE ROW LEVEL SECURITY;
ALTER TABLE resilience.backup_restore_drills FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation_backup_restore_drills ON resilience.backup_restore_drills
    USING (tenant_id = current_setting('vulnlab.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('vulnlab.tenant_id', true)::uuid);

ALTER TABLE resilience.failure_injection_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE resilience.failure_injection_events FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation_failure_injection_events ON resilience.failure_injection_events
    USING (tenant_id = current_setting('vulnlab.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('vulnlab.tenant_id', true)::uuid);

GRANT USAGE ON SCHEMA resilience TO vulnlab_app;
GRANT SELECT, INSERT, UPDATE ON ALL TABLES IN SCHEMA resilience TO vulnlab_app;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA resilience TO vulnlab_app;

COMMIT;
