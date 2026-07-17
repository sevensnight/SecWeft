BEGIN;

CREATE SCHEMA IF NOT EXISTS validation;

CREATE TABLE validation.executions (
    id uuid NOT NULL,
    tenant_id uuid NOT NULL,
    project_id uuid,
    task_id uuid NOT NULL,
    plan_id uuid NOT NULL,
    template_id varchar(120) NOT NULL,
    template_version varchar(40) NOT NULL,
    status varchar(40) NOT NULL,
    trace_id varchar(80) NOT NULL,
    sandbox_id varchar(120) NOT NULL,
    approval_id varchar(240) NOT NULL,
    policy_decision_id uuid NOT NULL,
    idempotency_key varchar(240),
    queue_message_id uuid,
    result jsonb NOT NULL DEFAULT '{}'::jsonb,
    error text,
    review_decision varchar(20),
    review_reason text,
    reviewed_by uuid,
    reviewed_at timestamptz,
    retry_of uuid,
    created_by uuid NOT NULL,
    started_at timestamptz,
    finished_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    version bigint NOT NULL DEFAULT 1,
    PRIMARY KEY (tenant_id, id),
    CONSTRAINT fk_validation_execution_tenant FOREIGN KEY (tenant_id)
        REFERENCES iam.tenants (id) ON UPDATE RESTRICT ON DELETE RESTRICT,
    CONSTRAINT fk_validation_execution_creator FOREIGN KEY (tenant_id, created_by)
        REFERENCES iam.users (tenant_id, id) ON UPDATE RESTRICT ON DELETE RESTRICT,
    CONSTRAINT fk_validation_execution_reviewer FOREIGN KEY (tenant_id, reviewed_by)
        REFERENCES iam.users (tenant_id, id) ON UPDATE RESTRICT ON DELETE RESTRICT,
    CONSTRAINT fk_validation_execution_retry FOREIGN KEY (tenant_id, retry_of)
        REFERENCES validation.executions (tenant_id, id) ON UPDATE RESTRICT ON DELETE RESTRICT,
    CONSTRAINT ck_validation_execution_status CHECK (
        status IN (
            'QUEUED','PROVISIONING','RUNNING','COLLECTING_EVIDENCE','VERIFYING',
            'SUCCEEDED','FAILED','CANCELLED','EXPIRED','POLICY_REJECTED',
            'APPROVAL_REVOKED','SCOPE_INVALID','SANDBOX_FAILED','RESOURCE_EXCEEDED',
            'EXECUTION_TIMEOUT','EVIDENCE_INCOMPLETE'
        )
    ),
    CONSTRAINT ck_validation_execution_review CHECK (review_decision IS NULL OR review_decision IN ('accepted','rejected')),
    CONSTRAINT ck_validation_execution_result CHECK (jsonb_typeof(result) = 'object'),
    CONSTRAINT ck_validation_execution_version CHECK (version > 0),
    CONSTRAINT ck_validation_execution_timestamps CHECK (
        updated_at >= created_at
        AND (started_at IS NULL OR started_at >= created_at)
        AND (finished_at IS NULL OR started_at IS NULL OR finished_at >= started_at)
    )
);

CREATE INDEX idx_validation_execution_task
    ON validation.executions (tenant_id, task_id, created_at DESC);

CREATE INDEX idx_validation_execution_plan
    ON validation.executions (tenant_id, plan_id, created_at DESC);

CREATE TABLE validation.execution_events (
    id bigserial NOT NULL,
    tenant_id uuid NOT NULL,
    execution_id uuid NOT NULL,
    event_type varchar(160) NOT NULL,
    status varchar(40) NOT NULL,
    payload jsonb NOT NULL DEFAULT '{}'::jsonb,
    created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    version bigint NOT NULL DEFAULT 1,
    PRIMARY KEY (tenant_id, id),
    CONSTRAINT fk_validation_event_execution FOREIGN KEY (tenant_id, execution_id)
        REFERENCES validation.executions (tenant_id, id) ON UPDATE RESTRICT ON DELETE CASCADE,
    CONSTRAINT ck_validation_event_payload CHECK (jsonb_typeof(payload) = 'object'),
    CONSTRAINT ck_validation_event_version CHECK (version > 0),
    CONSTRAINT ck_validation_event_timestamps CHECK (updated_at >= created_at)
);

CREATE INDEX idx_validation_event_execution
    ON validation.execution_events (tenant_id, execution_id, id);

CREATE TABLE validation.execution_evidence (
    id uuid NOT NULL,
    tenant_id uuid NOT NULL,
    execution_id uuid NOT NULL,
    task_id uuid NOT NULL,
    evidence_item_id uuid,
    title varchar(240) NOT NULL,
    artifact_ref text NOT NULL,
    content_sha256 char(64) NOT NULL,
    metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
    created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    version bigint NOT NULL DEFAULT 1,
    PRIMARY KEY (tenant_id, id),
    CONSTRAINT fk_validation_evidence_execution FOREIGN KEY (tenant_id, execution_id)
        REFERENCES validation.executions (tenant_id, id) ON UPDATE RESTRICT ON DELETE CASCADE,
    CONSTRAINT ck_validation_evidence_hash CHECK (content_sha256 ~ '^[a-f0-9]{64}$'),
    CONSTRAINT ck_validation_evidence_metadata CHECK (jsonb_typeof(metadata) = 'object'),
    CONSTRAINT ck_validation_evidence_version CHECK (version > 0),
    CONSTRAINT ck_validation_evidence_timestamps CHECK (updated_at >= created_at)
);

CREATE INDEX idx_validation_evidence_execution
    ON validation.execution_evidence (tenant_id, execution_id, created_at DESC);

CREATE TABLE validation.queue_messages (
    id uuid NOT NULL,
    tenant_id uuid NOT NULL,
    execution_id uuid NOT NULL,
    message_id uuid NOT NULL,
    subject varchar(200) NOT NULL,
    status varchar(24) NOT NULL,
    attempt integer NOT NULL DEFAULT 0,
    max_attempts integer NOT NULL DEFAULT 3,
    available_at timestamptz NOT NULL,
    locked_by varchar(160),
    lock_token uuid,
    locked_until timestamptz,
    last_error text,
    payload jsonb NOT NULL DEFAULT '{}'::jsonb,
    created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    version bigint NOT NULL DEFAULT 1,
    PRIMARY KEY (tenant_id, id),
    CONSTRAINT uq_validation_queue_message UNIQUE (tenant_id, message_id),
    CONSTRAINT fk_validation_queue_execution FOREIGN KEY (tenant_id, execution_id)
        REFERENCES validation.executions (tenant_id, id) ON UPDATE RESTRICT ON DELETE CASCADE,
    CONSTRAINT ck_validation_queue_status CHECK (status IN ('ready','leased','done','cancelled','dead')),
    CONSTRAINT ck_validation_queue_attempts CHECK (attempt >= 0 AND max_attempts BETWEEN 1 AND 20),
    CONSTRAINT ck_validation_queue_payload CHECK (jsonb_typeof(payload) = 'object'),
    CONSTRAINT ck_validation_queue_version CHECK (version > 0),
    CONSTRAINT ck_validation_queue_timestamps CHECK (
        updated_at >= created_at AND (locked_until IS NULL OR locked_until >= available_at)
    )
);

CREATE INDEX idx_validation_queue_ready
    ON validation.queue_messages (tenant_id, status, available_at, id)
    WHERE status IN ('ready', 'leased');

COMMIT;
