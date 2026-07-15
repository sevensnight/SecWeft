BEGIN;

SET LOCAL lock_timeout = '10s';
SET LOCAL statement_timeout = '60s';

CREATE SCHEMA IF NOT EXISTS iam;
CREATE SCHEMA IF NOT EXISTS control;
CREATE SCHEMA IF NOT EXISTS audit;

CREATE TABLE iam.tenants (
    id uuid NOT NULL,
    slug varchar(63) NOT NULL,
    display_name varchar(200) NOT NULL,
    status varchar(24) NOT NULL DEFAULT 'ACTIVE',
    created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    version bigint NOT NULL DEFAULT 1,
    CONSTRAINT pk_tenants PRIMARY KEY (id),
    CONSTRAINT uq_tenants_slug UNIQUE (slug),
    CONSTRAINT ck_tenants_slug CHECK (slug ~ '^[a-z0-9][a-z0-9-]{1,61}[a-z0-9]$'),
    CONSTRAINT ck_tenants_status CHECK (status IN ('ACTIVE', 'SUSPENDED', 'DISABLED')),
    CONSTRAINT ck_tenants_version CHECK (version > 0),
    CONSTRAINT ck_tenants_timestamps CHECK (updated_at >= created_at)
);

CREATE TABLE iam.projects (
    id uuid NOT NULL,
    tenant_id uuid NOT NULL,
    slug varchar(63) NOT NULL,
    display_name varchar(200) NOT NULL,
    status varchar(24) NOT NULL DEFAULT 'ACTIVE',
    created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    version bigint NOT NULL DEFAULT 1,
    CONSTRAINT pk_projects PRIMARY KEY (id),
    CONSTRAINT uq_projects_tenant_slug UNIQUE (tenant_id, slug),
    CONSTRAINT uq_projects_tenant_id UNIQUE (tenant_id, id),
    CONSTRAINT fk_projects_tenant FOREIGN KEY (tenant_id)
        REFERENCES iam.tenants (id) ON UPDATE RESTRICT ON DELETE RESTRICT,
    CONSTRAINT ck_projects_slug CHECK (slug ~ '^[a-z0-9][a-z0-9-]{1,61}[a-z0-9]$'),
    CONSTRAINT ck_projects_status CHECK (status IN ('ACTIVE', 'ARCHIVED', 'DISABLED')),
    CONSTRAINT ck_projects_version CHECK (version > 0),
    CONSTRAINT ck_projects_timestamps CHECK (updated_at >= created_at)
);

CREATE TABLE iam.users (
    id uuid NOT NULL,
    tenant_id uuid NOT NULL,
    subject varchar(255) NOT NULL,
    username varchar(128) NOT NULL,
    email varchar(320),
    active boolean NOT NULL DEFAULT true,
    created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    version bigint NOT NULL DEFAULT 1,
    CONSTRAINT pk_users PRIMARY KEY (id),
    CONSTRAINT uq_users_tenant_subject UNIQUE (tenant_id, subject),
    CONSTRAINT uq_users_tenant_username UNIQUE (tenant_id, username),
    CONSTRAINT uq_users_tenant_id UNIQUE (tenant_id, id),
    CONSTRAINT fk_users_tenant FOREIGN KEY (tenant_id)
        REFERENCES iam.tenants (id) ON UPDATE RESTRICT ON DELETE RESTRICT,
    CONSTRAINT ck_users_version CHECK (version > 0),
    CONSTRAINT ck_users_timestamps CHECK (updated_at >= created_at)
);

CREATE TABLE iam.roles (
    id uuid NOT NULL,
    tenant_id uuid NOT NULL,
    code varchar(80) NOT NULL,
    display_name varchar(160) NOT NULL,
    description text NOT NULL DEFAULT '',
    scope_type varchar(24) NOT NULL,
    system_managed boolean NOT NULL DEFAULT false,
    created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    version bigint NOT NULL DEFAULT 1,
    CONSTRAINT pk_roles PRIMARY KEY (id),
    CONSTRAINT uq_roles_tenant_code UNIQUE (tenant_id, code),
    CONSTRAINT uq_roles_tenant_id UNIQUE (tenant_id, id),
    CONSTRAINT fk_roles_tenant FOREIGN KEY (tenant_id)
        REFERENCES iam.tenants (id) ON UPDATE RESTRICT ON DELETE RESTRICT,
    CONSTRAINT ck_roles_code CHECK (code ~ '^[a-z][a-z0-9_.:-]{2,79}$'),
    CONSTRAINT ck_roles_scope CHECK (scope_type IN ('TENANT', 'PROJECT')),
    CONSTRAINT ck_roles_version CHECK (version > 0),
    CONSTRAINT ck_roles_timestamps CHECK (updated_at >= created_at)
);

CREATE TABLE iam.permissions (
    id uuid NOT NULL,
    tenant_id uuid NOT NULL,
    code varchar(120) NOT NULL,
    description text NOT NULL DEFAULT '',
    resource_type varchar(80) NOT NULL,
    action varchar(80) NOT NULL,
    created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    version bigint NOT NULL DEFAULT 1,
    CONSTRAINT pk_permissions PRIMARY KEY (id),
    CONSTRAINT uq_permissions_tenant_code UNIQUE (tenant_id, code),
    CONSTRAINT uq_permissions_tenant_id UNIQUE (tenant_id, id),
    CONSTRAINT fk_permissions_tenant FOREIGN KEY (tenant_id)
        REFERENCES iam.tenants (id) ON UPDATE RESTRICT ON DELETE RESTRICT,
    CONSTRAINT ck_permissions_code CHECK (code ~ '^[a-z][a-z0-9_.:-]{2,119}$'),
    CONSTRAINT ck_permissions_version CHECK (version > 0),
    CONSTRAINT ck_permissions_timestamps CHECK (updated_at >= created_at)
);

CREATE TABLE iam.role_permissions (
    tenant_id uuid NOT NULL,
    role_id uuid NOT NULL,
    permission_id uuid NOT NULL,
    created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    version bigint NOT NULL DEFAULT 1,
    CONSTRAINT pk_role_permissions PRIMARY KEY (tenant_id, role_id, permission_id),
    CONSTRAINT fk_role_permissions_role FOREIGN KEY (tenant_id, role_id)
        REFERENCES iam.roles (tenant_id, id) ON UPDATE RESTRICT ON DELETE CASCADE,
    CONSTRAINT fk_role_permissions_permission FOREIGN KEY (tenant_id, permission_id)
        REFERENCES iam.permissions (tenant_id, id) ON UPDATE RESTRICT ON DELETE CASCADE,
    CONSTRAINT ck_role_permissions_version CHECK (version > 0),
    CONSTRAINT ck_role_permissions_timestamps CHECK (updated_at >= created_at)
);

CREATE TABLE iam.user_roles (
    id uuid NOT NULL,
    tenant_id uuid NOT NULL,
    project_id uuid,
    user_id uuid NOT NULL,
    role_id uuid NOT NULL,
    granted_by uuid NOT NULL,
    expires_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    version bigint NOT NULL DEFAULT 1,
    CONSTRAINT pk_user_roles PRIMARY KEY (id),
    CONSTRAINT uq_user_roles_tenant_id UNIQUE (tenant_id, id),
    CONSTRAINT fk_user_roles_project FOREIGN KEY (tenant_id, project_id)
        REFERENCES iam.projects (tenant_id, id) ON UPDATE RESTRICT ON DELETE RESTRICT,
    CONSTRAINT fk_user_roles_user FOREIGN KEY (tenant_id, user_id)
        REFERENCES iam.users (tenant_id, id) ON UPDATE RESTRICT ON DELETE CASCADE,
    CONSTRAINT fk_user_roles_role FOREIGN KEY (tenant_id, role_id)
        REFERENCES iam.roles (tenant_id, id) ON UPDATE RESTRICT ON DELETE CASCADE,
    CONSTRAINT fk_user_roles_grantor FOREIGN KEY (tenant_id, granted_by)
        REFERENCES iam.users (tenant_id, id) ON UPDATE RESTRICT ON DELETE RESTRICT,
    CONSTRAINT ck_user_roles_version CHECK (version > 0),
    CONSTRAINT ck_user_roles_expiry CHECK (expires_at IS NULL OR expires_at > created_at),
    CONSTRAINT ck_user_roles_timestamps CHECK (updated_at >= created_at)
);

CREATE UNIQUE INDEX uq_user_roles_tenant_scope
    ON iam.user_roles (tenant_id, user_id, role_id)
    WHERE project_id IS NULL;
CREATE UNIQUE INDEX uq_user_roles_project_scope
    ON iam.user_roles (tenant_id, project_id, user_id, role_id)
    WHERE project_id IS NOT NULL;
CREATE INDEX idx_users_tenant_active ON iam.users (tenant_id, active, username);
CREATE INDEX idx_user_roles_user ON iam.user_roles (tenant_id, user_id, project_id);

CREATE TABLE control.tasks (
    id uuid NOT NULL,
    tenant_id uuid NOT NULL,
    project_id uuid NOT NULL,
    title varchar(240) NOT NULL,
    description text NOT NULL DEFAULT '',
    task_type varchar(80) NOT NULL,
    priority smallint NOT NULL DEFAULT 50,
    status varchar(32) NOT NULL DEFAULT 'DRAFT',
    approval_status varchar(32) NOT NULL DEFAULT 'NOT_REQUIRED',
    current_stage varchar(80),
    requested_by uuid NOT NULL,
    assigned_to uuid,
    input jsonb NOT NULL DEFAULT '{}'::jsonb,
    output_summary jsonb,
    error_code varchar(120),
    error_message text,
    deadline_at timestamptz,
    started_at timestamptz,
    finished_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    version bigint NOT NULL DEFAULT 1,
    CONSTRAINT pk_tasks PRIMARY KEY (id),
    CONSTRAINT uq_tasks_tenant_id UNIQUE (tenant_id, id),
    CONSTRAINT uq_tasks_tenant_project_id UNIQUE (tenant_id, project_id, id),
    CONSTRAINT fk_tasks_project FOREIGN KEY (tenant_id, project_id)
        REFERENCES iam.projects (tenant_id, id) ON UPDATE RESTRICT ON DELETE RESTRICT,
    CONSTRAINT fk_tasks_requester FOREIGN KEY (tenant_id, requested_by)
        REFERENCES iam.users (tenant_id, id) ON UPDATE RESTRICT ON DELETE RESTRICT,
    CONSTRAINT fk_tasks_assignee FOREIGN KEY (tenant_id, assigned_to)
        REFERENCES iam.users (tenant_id, id) ON UPDATE RESTRICT ON DELETE RESTRICT,
    CONSTRAINT ck_tasks_priority CHECK (priority BETWEEN 0 AND 100),
    CONSTRAINT ck_tasks_status CHECK (status IN (
        'DRAFT', 'PENDING_APPROVAL', 'APPROVED', 'QUEUED', 'RUNNING',
        'PAUSING', 'PAUSED', 'CANCELLING', 'CANCELLED', 'SUCCEEDED',
        'FAILED', 'TIMED_OUT', 'COMPENSATING', 'COMPENSATED', 'ARCHIVED'
    )),
    CONSTRAINT ck_tasks_approval CHECK (approval_status IN (
        'NOT_REQUIRED', 'PENDING', 'APPROVED', 'REJECTED', 'REVOKED'
    )),
    CONSTRAINT ck_tasks_input_object CHECK (jsonb_typeof(input) = 'object'),
    CONSTRAINT ck_tasks_output_object CHECK (output_summary IS NULL OR jsonb_typeof(output_summary) = 'object'),
    CONSTRAINT ck_tasks_version CHECK (version > 0),
    CONSTRAINT ck_tasks_timestamps CHECK (
        updated_at >= created_at
        AND (started_at IS NULL OR started_at >= created_at)
        AND (finished_at IS NULL OR started_at IS NOT NULL)
        AND (finished_at IS NULL OR finished_at >= started_at)
    )
);

CREATE TABLE control.task_stages (
    id uuid NOT NULL,
    tenant_id uuid NOT NULL,
    project_id uuid NOT NULL,
    task_id uuid NOT NULL,
    stage_code varchar(80) NOT NULL,
    sequence_no integer NOT NULL,
    status varchar(24) NOT NULL DEFAULT 'PENDING',
    attempt integer NOT NULL DEFAULT 0,
    max_attempts integer NOT NULL DEFAULT 1,
    checkpoint jsonb,
    error_code varchar(120),
    started_at timestamptz,
    finished_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    version bigint NOT NULL DEFAULT 1,
    CONSTRAINT pk_task_stages PRIMARY KEY (id),
    CONSTRAINT uq_task_stages_tenant_id UNIQUE (tenant_id, id),
    CONSTRAINT uq_task_stages_sequence UNIQUE (tenant_id, task_id, sequence_no),
    CONSTRAINT uq_task_stages_code UNIQUE (tenant_id, task_id, stage_code),
    CONSTRAINT fk_task_stages_task FOREIGN KEY (tenant_id, project_id, task_id)
        REFERENCES control.tasks (tenant_id, project_id, id) ON UPDATE RESTRICT ON DELETE CASCADE,
    CONSTRAINT ck_task_stages_sequence CHECK (sequence_no >= 0),
    CONSTRAINT ck_task_stages_attempt CHECK (attempt >= 0 AND max_attempts > 0 AND attempt <= max_attempts),
    CONSTRAINT ck_task_stages_status CHECK (status IN (
        'PENDING', 'READY', 'RUNNING', 'PAUSED', 'SUCCEEDED', 'FAILED',
        'SKIPPED', 'CANCELLED', 'TIMED_OUT', 'COMPENSATED'
    )),
    CONSTRAINT ck_task_stages_checkpoint CHECK (checkpoint IS NULL OR jsonb_typeof(checkpoint) = 'object'),
    CONSTRAINT ck_task_stages_version CHECK (version > 0),
    CONSTRAINT ck_task_stages_timestamps CHECK (
        updated_at >= created_at
        AND (started_at IS NULL OR started_at >= created_at)
        AND (finished_at IS NULL OR started_at IS NOT NULL)
        AND (finished_at IS NULL OR finished_at >= started_at)
    )
);

CREATE TABLE control.task_events (
    id bigint GENERATED ALWAYS AS IDENTITY,
    event_id uuid NOT NULL,
    tenant_id uuid NOT NULL,
    project_id uuid NOT NULL,
    task_id uuid NOT NULL,
    sequence_no bigint NOT NULL,
    event_type varchar(160) NOT NULL,
    trace_id varchar(64) NOT NULL,
    actor_user_id uuid,
    payload jsonb NOT NULL DEFAULT '{}'::jsonb,
    occurred_at timestamptz NOT NULL,
    created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    version bigint NOT NULL DEFAULT 1,
    CONSTRAINT pk_task_events PRIMARY KEY (id),
    CONSTRAINT uq_task_events_event UNIQUE (tenant_id, event_id),
    CONSTRAINT uq_task_events_sequence UNIQUE (tenant_id, task_id, sequence_no),
    CONSTRAINT fk_task_events_task FOREIGN KEY (tenant_id, project_id, task_id)
        REFERENCES control.tasks (tenant_id, project_id, id) ON UPDATE RESTRICT ON DELETE CASCADE,
    CONSTRAINT fk_task_events_actor FOREIGN KEY (tenant_id, actor_user_id)
        REFERENCES iam.users (tenant_id, id) ON UPDATE RESTRICT ON DELETE RESTRICT,
    CONSTRAINT ck_task_events_sequence CHECK (sequence_no > 0),
    CONSTRAINT ck_task_events_trace CHECK (length(trace_id) BETWEEN 16 AND 64),
    CONSTRAINT ck_task_events_payload CHECK (jsonb_typeof(payload) = 'object'),
    CONSTRAINT ck_task_events_version CHECK (version > 0),
    CONSTRAINT ck_task_events_timestamps CHECK (updated_at >= created_at)
);

CREATE TABLE control.outbox_events (
    id bigint GENERATED ALWAYS AS IDENTITY,
    event_id uuid NOT NULL,
    tenant_id uuid NOT NULL,
    project_id uuid,
    aggregate_type varchar(100) NOT NULL,
    aggregate_id uuid NOT NULL,
    event_type varchar(160) NOT NULL,
    event_version integer NOT NULL DEFAULT 1,
    partition_key varchar(200) NOT NULL,
    payload jsonb NOT NULL,
    headers jsonb NOT NULL DEFAULT '{}'::jsonb,
    occurred_at timestamptz NOT NULL,
    published_at timestamptz,
    publish_attempts integer NOT NULL DEFAULT 0,
    last_error text,
    created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    version bigint NOT NULL DEFAULT 1,
    CONSTRAINT pk_outbox_events PRIMARY KEY (id),
    CONSTRAINT uq_outbox_events_event UNIQUE (tenant_id, event_id),
    CONSTRAINT fk_outbox_events_tenant FOREIGN KEY (tenant_id)
        REFERENCES iam.tenants (id) ON UPDATE RESTRICT ON DELETE RESTRICT,
    CONSTRAINT fk_outbox_events_project FOREIGN KEY (tenant_id, project_id)
        REFERENCES iam.projects (tenant_id, id) ON UPDATE RESTRICT ON DELETE RESTRICT,
    CONSTRAINT ck_outbox_event_version CHECK (event_version > 0),
    CONSTRAINT ck_outbox_attempts CHECK (publish_attempts >= 0),
    CONSTRAINT ck_outbox_payload CHECK (jsonb_typeof(payload) = 'object'),
    CONSTRAINT ck_outbox_headers CHECK (jsonb_typeof(headers) = 'object'),
    CONSTRAINT ck_outbox_version CHECK (version > 0),
    CONSTRAINT ck_outbox_timestamps CHECK (
        updated_at >= created_at AND (published_at IS NULL OR published_at >= occurred_at)
    )
);

CREATE TABLE control.inbox_messages (
    id bigint GENERATED ALWAYS AS IDENTITY,
    tenant_id uuid NOT NULL,
    consumer_name varchar(160) NOT NULL,
    message_id uuid NOT NULL,
    message_type varchar(160) NOT NULL,
    payload_sha256 char(64) NOT NULL,
    status varchar(24) NOT NULL DEFAULT 'RECEIVED',
    received_at timestamptz NOT NULL,
    processed_at timestamptz,
    error_code varchar(120),
    created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    version bigint NOT NULL DEFAULT 1,
    CONSTRAINT pk_inbox_messages PRIMARY KEY (id),
    CONSTRAINT uq_inbox_consumer_message UNIQUE (tenant_id, consumer_name, message_id),
    CONSTRAINT fk_inbox_messages_tenant FOREIGN KEY (tenant_id)
        REFERENCES iam.tenants (id) ON UPDATE RESTRICT ON DELETE RESTRICT,
    CONSTRAINT ck_inbox_payload_hash CHECK (payload_sha256 ~ '^[a-f0-9]{64}$'),
    CONSTRAINT ck_inbox_status CHECK (status IN ('RECEIVED', 'PROCESSING', 'PROCESSED', 'FAILED')),
    CONSTRAINT ck_inbox_version CHECK (version > 0),
    CONSTRAINT ck_inbox_timestamps CHECK (
        updated_at >= created_at AND (processed_at IS NULL OR processed_at >= received_at)
    )
);

CREATE TABLE control.idempotency_records (
    id uuid NOT NULL,
    tenant_id uuid NOT NULL,
    project_id uuid,
    operation varchar(160) NOT NULL,
    idempotency_key varchar(200) NOT NULL,
    request_sha256 char(64) NOT NULL,
    status varchar(24) NOT NULL DEFAULT 'PROCESSING',
    response_status integer,
    response_body jsonb,
    resource_type varchar(100),
    resource_id uuid,
    locked_until timestamptz,
    expires_at timestamptz NOT NULL,
    created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    version bigint NOT NULL DEFAULT 1,
    CONSTRAINT pk_idempotency_records PRIMARY KEY (id),
    CONSTRAINT uq_idempotency_tenant_id UNIQUE (tenant_id, id),
    CONSTRAINT fk_idempotency_tenant FOREIGN KEY (tenant_id)
        REFERENCES iam.tenants (id) ON UPDATE RESTRICT ON DELETE RESTRICT,
    CONSTRAINT fk_idempotency_project FOREIGN KEY (tenant_id, project_id)
        REFERENCES iam.projects (tenant_id, id) ON UPDATE RESTRICT ON DELETE RESTRICT,
    CONSTRAINT ck_idempotency_request_hash CHECK (request_sha256 ~ '^[a-f0-9]{64}$'),
    CONSTRAINT ck_idempotency_status CHECK (status IN ('PROCESSING', 'COMPLETED', 'FAILED')),
    CONSTRAINT ck_idempotency_response_status CHECK (
        response_status IS NULL OR response_status BETWEEN 100 AND 599
    ),
    CONSTRAINT ck_idempotency_response_body CHECK (
        response_body IS NULL OR jsonb_typeof(response_body) IN ('object', 'array')
    ),
    CONSTRAINT ck_idempotency_expiry CHECK (expires_at > created_at),
    CONSTRAINT ck_idempotency_version CHECK (version > 0),
    CONSTRAINT ck_idempotency_timestamps CHECK (updated_at >= created_at)
);

CREATE UNIQUE INDEX uq_idempotency_tenant_scope
    ON control.idempotency_records (tenant_id, operation, idempotency_key)
    WHERE project_id IS NULL;
CREATE UNIQUE INDEX uq_idempotency_project_scope
    ON control.idempotency_records (tenant_id, project_id, operation, idempotency_key)
    WHERE project_id IS NOT NULL;
CREATE INDEX idx_tasks_project_status
    ON control.tasks (tenant_id, project_id, status, priority DESC, created_at DESC);
CREATE INDEX idx_tasks_requester
    ON control.tasks (tenant_id, requested_by, created_at DESC);
CREATE INDEX idx_task_stages_ready
    ON control.task_stages (tenant_id, status, updated_at)
    WHERE status IN ('PENDING', 'READY', 'RUNNING');
CREATE INDEX idx_task_events_stream
    ON control.task_events (tenant_id, task_id, sequence_no);
CREATE INDEX idx_outbox_unpublished
    ON control.outbox_events (occurred_at, id)
    WHERE published_at IS NULL;
CREATE INDEX idx_inbox_status
    ON control.inbox_messages (tenant_id, consumer_name, status, received_at);
CREATE INDEX idx_idempotency_expiry
    ON control.idempotency_records (expires_at);

CREATE TABLE audit.events (
    id bigint GENERATED ALWAYS AS IDENTITY,
    event_id uuid NOT NULL,
    tenant_id uuid NOT NULL,
    project_id uuid,
    actor_type varchar(24) NOT NULL,
    actor_user_id uuid,
    action varchar(160) NOT NULL,
    resource_type varchar(100) NOT NULL,
    resource_id varchar(200) NOT NULL,
    outcome varchar(24) NOT NULL,
    risk_level varchar(8) NOT NULL,
    trace_id varchar(64) NOT NULL,
    request_id varchar(64) NOT NULL,
    task_id uuid,
    agent_id uuid,
    sandbox_id uuid,
    duration_ms bigint,
    details jsonb NOT NULL DEFAULT '{}'::jsonb,
    previous_hash bytea NOT NULL,
    entry_hash bytea NOT NULL,
    occurred_at timestamptz NOT NULL,
    created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    version bigint NOT NULL DEFAULT 1,
    CONSTRAINT pk_audit_events PRIMARY KEY (id),
    CONSTRAINT uq_audit_events_event UNIQUE (tenant_id, event_id),
    CONSTRAINT uq_audit_events_hash UNIQUE (tenant_id, entry_hash),
    CONSTRAINT uq_audit_events_tenant_id UNIQUE (tenant_id, id),
    CONSTRAINT fk_audit_events_tenant FOREIGN KEY (tenant_id)
        REFERENCES iam.tenants (id) ON UPDATE RESTRICT ON DELETE RESTRICT,
    CONSTRAINT fk_audit_events_project FOREIGN KEY (tenant_id, project_id)
        REFERENCES iam.projects (tenant_id, id) ON UPDATE RESTRICT ON DELETE RESTRICT,
    CONSTRAINT fk_audit_events_actor FOREIGN KEY (tenant_id, actor_user_id)
        REFERENCES iam.users (tenant_id, id) ON UPDATE RESTRICT ON DELETE RESTRICT,
    CONSTRAINT fk_audit_events_task FOREIGN KEY (tenant_id, task_id)
        REFERENCES control.tasks (tenant_id, id) ON UPDATE RESTRICT ON DELETE RESTRICT,
    CONSTRAINT ck_audit_actor_type CHECK (actor_type IN ('USER', 'SERVICE', 'AGENT', 'SYSTEM')),
    CONSTRAINT ck_audit_outcome CHECK (outcome IN ('SUCCEEDED', 'FAILED', 'DENIED', 'CANCELLED')),
    CONSTRAINT ck_audit_risk CHECK (risk_level IN ('R0', 'R1', 'R2', 'R3', 'R4')),
    CONSTRAINT ck_audit_trace CHECK (length(trace_id) BETWEEN 16 AND 64),
    CONSTRAINT ck_audit_request CHECK (length(request_id) BETWEEN 16 AND 64),
    CONSTRAINT ck_audit_duration CHECK (duration_ms IS NULL OR duration_ms >= 0),
    CONSTRAINT ck_audit_details CHECK (jsonb_typeof(details) = 'object'),
    CONSTRAINT ck_audit_previous_hash CHECK (octet_length(previous_hash) = 32),
    CONSTRAINT ck_audit_entry_hash CHECK (octet_length(entry_hash) = 32),
    CONSTRAINT ck_audit_version CHECK (version = 1),
    CONSTRAINT ck_audit_timestamps CHECK (updated_at = created_at)
);

CREATE TABLE audit.chain_heads (
    tenant_id uuid NOT NULL,
    last_event_id bigint NOT NULL,
    last_hash bytea NOT NULL,
    event_count bigint NOT NULL,
    created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    version bigint NOT NULL DEFAULT 1,
    CONSTRAINT pk_audit_chain_heads PRIMARY KEY (tenant_id),
    CONSTRAINT fk_audit_chain_heads_tenant FOREIGN KEY (tenant_id)
        REFERENCES iam.tenants (id) ON UPDATE RESTRICT ON DELETE RESTRICT,
    CONSTRAINT fk_audit_chain_heads_event FOREIGN KEY (tenant_id, last_event_id)
        REFERENCES audit.events (tenant_id, id) ON UPDATE RESTRICT ON DELETE RESTRICT,
    CONSTRAINT ck_audit_chain_hash CHECK (octet_length(last_hash) = 32),
    CONSTRAINT ck_audit_chain_count CHECK (event_count > 0),
    CONSTRAINT ck_audit_chain_version CHECK (version > 0),
    CONSTRAINT ck_audit_chain_timestamps CHECK (updated_at >= created_at)
);

CREATE INDEX idx_audit_events_occurred
    ON audit.events (tenant_id, occurred_at DESC, id DESC);
CREATE INDEX idx_audit_events_trace
    ON audit.events (tenant_id, trace_id, occurred_at DESC);
CREATE INDEX idx_audit_events_request
    ON audit.events (tenant_id, request_id, occurred_at DESC);
CREATE INDEX idx_audit_events_task
    ON audit.events (tenant_id, task_id, occurred_at DESC)
    WHERE task_id IS NOT NULL;
CREATE INDEX idx_audit_events_actor
    ON audit.events (tenant_id, actor_user_id, occurred_at DESC)
    WHERE actor_user_id IS NOT NULL;

CREATE FUNCTION audit.reject_event_mutation()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'audit.events is append-only'
        USING ERRCODE = '55000';
END;
$$;

CREATE TRIGGER trg_audit_events_append_only
BEFORE UPDATE OR DELETE ON audit.events
FOR EACH ROW EXECUTE FUNCTION audit.reject_event_mutation();

COMMIT;
