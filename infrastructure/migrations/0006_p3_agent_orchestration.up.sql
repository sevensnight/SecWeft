BEGIN;

CREATE SCHEMA IF NOT EXISTS agent;

CREATE TABLE agent.skill_definitions (
    id uuid NOT NULL,
    tenant_id uuid NOT NULL,
    name varchar(120) NOT NULL,
    version_label varchar(80) NOT NULL,
    description text NOT NULL,
    input_schema jsonb NOT NULL DEFAULT '{}'::jsonb,
    output_schema jsonb NOT NULL DEFAULT '{}'::jsonb,
    required_permissions text[] NOT NULL DEFAULT ARRAY[]::text[],
    risk_level varchar(20) NOT NULL,
    resource_limits jsonb NOT NULL DEFAULT '{}'::jsonb,
    timeout_seconds integer NOT NULL DEFAULT 30,
    execution_type varchar(40) NOT NULL,
    approval_required boolean NOT NULL DEFAULT false,
    enabled boolean NOT NULL DEFAULT true,
    builtin boolean NOT NULL DEFAULT false,
    created_by uuid NOT NULL,
    updated_by uuid NOT NULL,
    created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    version bigint NOT NULL DEFAULT 1,
    PRIMARY KEY (tenant_id, id),
    CONSTRAINT fk_agent_skill_tenant FOREIGN KEY (tenant_id)
        REFERENCES iam.tenants (id) ON UPDATE RESTRICT ON DELETE RESTRICT,
    CONSTRAINT fk_agent_skill_creator FOREIGN KEY (tenant_id, created_by)
        REFERENCES iam.users (tenant_id, id) ON UPDATE RESTRICT ON DELETE RESTRICT,
    CONSTRAINT fk_agent_skill_updater FOREIGN KEY (tenant_id, updated_by)
        REFERENCES iam.users (tenant_id, id) ON UPDATE RESTRICT ON DELETE RESTRICT,
    CONSTRAINT ck_agent_skill_name CHECK (name ~ '^[a-z][a-z0-9_.-]{2,119}$'),
    CONSTRAINT ck_agent_skill_risk CHECK (risk_level IN ('low', 'medium', 'high')),
    CONSTRAINT ck_agent_skill_execution CHECK (execution_type IN ('internal', 'webhook', 'sandbox_deferred')),
    CONSTRAINT ck_agent_skill_timeout CHECK (timeout_seconds BETWEEN 1 AND 3600),
    CONSTRAINT ck_agent_skill_json CHECK (
        jsonb_typeof(input_schema) = 'object'
        AND jsonb_typeof(output_schema) = 'object'
        AND jsonb_typeof(resource_limits) = 'object'
    ),
    CONSTRAINT ck_agent_skill_version CHECK (version > 0),
    CONSTRAINT ck_agent_skill_timestamps CHECK (updated_at >= created_at)
);

CREATE UNIQUE INDEX uq_agent_skill_name_version
    ON agent.skill_definitions (tenant_id, name, version_label);

CREATE TABLE agent.agent_definitions (
    id uuid NOT NULL,
    tenant_id uuid NOT NULL,
    name varchar(120) NOT NULL,
    version_label varchar(80) NOT NULL,
    description text NOT NULL,
    responsibilities jsonb NOT NULL DEFAULT '[]'::jsonb,
    input_schema jsonb NOT NULL DEFAULT '{}'::jsonb,
    output_schema jsonb NOT NULL DEFAULT '{}'::jsonb,
    allowed_tools text[] NOT NULL DEFAULT ARRAY[]::text[],
    data_scope varchar(20) NOT NULL,
    token_budget integer NOT NULL DEFAULT 0,
    timeout_seconds integer NOT NULL DEFAULT 60,
    risk_level varchar(20) NOT NULL,
    retry_policy jsonb NOT NULL DEFAULT '{}'::jsonb,
    enabled boolean NOT NULL DEFAULT true,
    builtin boolean NOT NULL DEFAULT false,
    created_by uuid NOT NULL,
    updated_by uuid NOT NULL,
    created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    version bigint NOT NULL DEFAULT 1,
    PRIMARY KEY (tenant_id, id),
    CONSTRAINT fk_agent_definition_tenant FOREIGN KEY (tenant_id)
        REFERENCES iam.tenants (id) ON UPDATE RESTRICT ON DELETE RESTRICT,
    CONSTRAINT fk_agent_definition_creator FOREIGN KEY (tenant_id, created_by)
        REFERENCES iam.users (tenant_id, id) ON UPDATE RESTRICT ON DELETE RESTRICT,
    CONSTRAINT fk_agent_definition_updater FOREIGN KEY (tenant_id, updated_by)
        REFERENCES iam.users (tenant_id, id) ON UPDATE RESTRICT ON DELETE RESTRICT,
    CONSTRAINT ck_agent_definition_name CHECK (name ~ '^[a-z][a-z0-9_.-]{2,119}$'),
    CONSTRAINT ck_agent_definition_scope CHECK (data_scope IN ('task', 'project', 'tenant')),
    CONSTRAINT ck_agent_definition_risk CHECK (risk_level IN ('low', 'medium', 'high')),
    CONSTRAINT ck_agent_definition_budget CHECK (token_budget >= 0),
    CONSTRAINT ck_agent_definition_timeout CHECK (timeout_seconds BETWEEN 1 AND 3600),
    CONSTRAINT ck_agent_definition_json CHECK (
        jsonb_typeof(responsibilities) = 'array'
        AND jsonb_typeof(input_schema) = 'object'
        AND jsonb_typeof(output_schema) = 'object'
        AND jsonb_typeof(retry_policy) = 'object'
    ),
    CONSTRAINT ck_agent_definition_version CHECK (version > 0),
    CONSTRAINT ck_agent_definition_timestamps CHECK (updated_at >= created_at)
);

CREATE UNIQUE INDEX uq_agent_definition_name_version
    ON agent.agent_definitions (tenant_id, name, version_label);

CREATE TABLE agent.workflow_definitions (
    id uuid NOT NULL,
    tenant_id uuid NOT NULL,
    name varchar(160) NOT NULL,
    version_label varchar(80) NOT NULL,
    description text NOT NULL,
    enabled boolean NOT NULL DEFAULT true,
    builtin boolean NOT NULL DEFAULT false,
    created_by uuid NOT NULL,
    updated_by uuid NOT NULL,
    created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    version bigint NOT NULL DEFAULT 1,
    PRIMARY KEY (tenant_id, id),
    CONSTRAINT fk_agent_workflow_tenant FOREIGN KEY (tenant_id)
        REFERENCES iam.tenants (id) ON UPDATE RESTRICT ON DELETE RESTRICT,
    CONSTRAINT fk_agent_workflow_creator FOREIGN KEY (tenant_id, created_by)
        REFERENCES iam.users (tenant_id, id) ON UPDATE RESTRICT ON DELETE RESTRICT,
    CONSTRAINT fk_agent_workflow_updater FOREIGN KEY (tenant_id, updated_by)
        REFERENCES iam.users (tenant_id, id) ON UPDATE RESTRICT ON DELETE RESTRICT,
    CONSTRAINT ck_agent_workflow_name CHECK (name ~ '^[a-z][a-z0-9_.-]{2,159}$'),
    CONSTRAINT ck_agent_workflow_version CHECK (version > 0),
    CONSTRAINT ck_agent_workflow_timestamps CHECK (updated_at >= created_at)
);

CREATE UNIQUE INDEX uq_agent_workflow_name_version
    ON agent.workflow_definitions (tenant_id, name, version_label);

CREATE TABLE agent.workflow_stages (
    id uuid NOT NULL,
    tenant_id uuid NOT NULL,
    workflow_id uuid NOT NULL,
    stage_code varchar(120) NOT NULL,
    display_name varchar(160) NOT NULL,
    sequence_no integer NOT NULL,
    agent_id uuid NOT NULL,
    skill_id uuid NOT NULL,
    depends_on text[] NOT NULL DEFAULT ARRAY[]::text[],
    max_attempts integer NOT NULL DEFAULT 1,
    created_by uuid NOT NULL,
    updated_by uuid NOT NULL,
    created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    version bigint NOT NULL DEFAULT 1,
    PRIMARY KEY (tenant_id, id),
    CONSTRAINT fk_agent_workflow_stage_workflow FOREIGN KEY (tenant_id, workflow_id)
        REFERENCES agent.workflow_definitions (tenant_id, id) ON UPDATE RESTRICT ON DELETE RESTRICT,
    CONSTRAINT fk_agent_workflow_stage_agent FOREIGN KEY (tenant_id, agent_id)
        REFERENCES agent.agent_definitions (tenant_id, id) ON UPDATE RESTRICT ON DELETE RESTRICT,
    CONSTRAINT fk_agent_workflow_stage_skill FOREIGN KEY (tenant_id, skill_id)
        REFERENCES agent.skill_definitions (tenant_id, id) ON UPDATE RESTRICT ON DELETE RESTRICT,
    CONSTRAINT fk_agent_workflow_stage_creator FOREIGN KEY (tenant_id, created_by)
        REFERENCES iam.users (tenant_id, id) ON UPDATE RESTRICT ON DELETE RESTRICT,
    CONSTRAINT fk_agent_workflow_stage_updater FOREIGN KEY (tenant_id, updated_by)
        REFERENCES iam.users (tenant_id, id) ON UPDATE RESTRICT ON DELETE RESTRICT,
    CONSTRAINT uq_agent_workflow_stage_code UNIQUE (tenant_id, workflow_id, stage_code),
    CONSTRAINT uq_agent_workflow_stage_sequence UNIQUE (tenant_id, workflow_id, sequence_no),
    CONSTRAINT ck_agent_workflow_stage_code CHECK (stage_code ~ '^[a-z][a-z0-9_.-]{0,119}$'),
    CONSTRAINT ck_agent_workflow_stage_sequence CHECK (sequence_no >= 0),
    CONSTRAINT ck_agent_workflow_stage_attempts CHECK (max_attempts BETWEEN 1 AND 10),
    CONSTRAINT ck_agent_workflow_stage_version CHECK (version > 0),
    CONSTRAINT ck_agent_workflow_stage_timestamps CHECK (updated_at >= created_at)
);

CREATE TABLE agent.task_executions (
    id uuid NOT NULL,
    tenant_id uuid NOT NULL,
    project_id uuid NOT NULL,
    task_id uuid NOT NULL,
    workflow_id uuid,
    worker_id varchar(160) NOT NULL,
    lease_token uuid NOT NULL,
    fencing_token bigint NOT NULL,
    status varchar(24) NOT NULL,
    started_at timestamptz NOT NULL,
    heartbeat_at timestamptz NOT NULL,
    finished_at timestamptz,
    error_code varchar(120),
    error_message text,
    created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    version bigint NOT NULL DEFAULT 1,
    PRIMARY KEY (tenant_id, id),
    CONSTRAINT fk_agent_task_execution_task FOREIGN KEY (tenant_id, project_id, task_id)
        REFERENCES control.tasks (tenant_id, project_id, id) ON UPDATE RESTRICT ON DELETE RESTRICT,
    CONSTRAINT fk_agent_task_execution_workflow FOREIGN KEY (tenant_id, workflow_id)
        REFERENCES agent.workflow_definitions (tenant_id, id) ON UPDATE RESTRICT ON DELETE RESTRICT,
    CONSTRAINT ck_agent_task_execution_status CHECK (
        status IN ('leased', 'running', 'paused', 'succeeded', 'failed', 'cancelled', 'timed_out')
    ),
    CONSTRAINT ck_agent_task_execution_fencing CHECK (fencing_token > 0),
    CONSTRAINT ck_agent_task_execution_version CHECK (version > 0),
    CONSTRAINT ck_agent_task_execution_timestamps CHECK (
        updated_at >= created_at
        AND heartbeat_at >= started_at
        AND (finished_at IS NULL OR finished_at >= started_at)
    )
);

CREATE INDEX idx_agent_task_execution_task
    ON agent.task_executions (tenant_id, project_id, task_id, created_at DESC);

CREATE TABLE agent.queue_messages (
    id uuid NOT NULL,
    tenant_id uuid NOT NULL,
    project_id uuid NOT NULL,
    task_id uuid NOT NULL,
    message_id uuid NOT NULL,
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
    CONSTRAINT uq_agent_queue_message UNIQUE (tenant_id, message_id),
    CONSTRAINT fk_agent_queue_task FOREIGN KEY (tenant_id, project_id, task_id)
        REFERENCES control.tasks (tenant_id, project_id, id) ON UPDATE RESTRICT ON DELETE RESTRICT,
    CONSTRAINT ck_agent_queue_status CHECK (status IN ('ready', 'leased', 'done', 'cancelled', 'dead')),
    CONSTRAINT ck_agent_queue_attempts CHECK (attempt >= 0 AND max_attempts BETWEEN 1 AND 20),
    CONSTRAINT ck_agent_queue_payload CHECK (jsonb_typeof(payload) = 'object'),
    CONSTRAINT ck_agent_queue_version CHECK (version > 0),
    CONSTRAINT ck_agent_queue_timestamps CHECK (
        updated_at >= created_at AND (locked_until IS NULL OR locked_until >= available_at)
    )
);

CREATE INDEX idx_agent_queue_ready
    ON agent.queue_messages (tenant_id, status, available_at, id)
    WHERE status IN ('ready', 'leased');

CREATE TABLE agent.dead_letters (
    id uuid NOT NULL,
    tenant_id uuid NOT NULL,
    project_id uuid,
    task_id uuid,
    queue_message_id uuid,
    reason text NOT NULL,
    payload jsonb NOT NULL DEFAULT '{}'::jsonb,
    created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    version bigint NOT NULL DEFAULT 1,
    PRIMARY KEY (tenant_id, id),
    CONSTRAINT fk_agent_dead_letter_task FOREIGN KEY (tenant_id, project_id, task_id)
        REFERENCES control.tasks (tenant_id, project_id, id) ON UPDATE RESTRICT ON DELETE RESTRICT,
    CONSTRAINT fk_agent_dead_letter_queue FOREIGN KEY (tenant_id, queue_message_id)
        REFERENCES agent.queue_messages (tenant_id, id) ON UPDATE RESTRICT ON DELETE RESTRICT,
    CONSTRAINT ck_agent_dead_letter_payload CHECK (jsonb_typeof(payload) = 'object'),
    CONSTRAINT ck_agent_dead_letter_version CHECK (version > 0),
    CONSTRAINT ck_agent_dead_letter_timestamps CHECK (updated_at >= created_at)
);

CREATE INDEX idx_agent_dead_letters_task
    ON agent.dead_letters (tenant_id, project_id, task_id, created_at DESC)
    WHERE task_id IS NOT NULL;

DO $rls$
DECLARE
    target text;
BEGIN
    FOREACH target IN ARRAY ARRAY[
        'agent.skill_definitions',
        'agent.agent_definitions',
        'agent.workflow_definitions',
        'agent.workflow_stages',
        'agent.task_executions',
        'agent.queue_messages',
        'agent.dead_letters'
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

GRANT USAGE ON SCHEMA agent TO vulnlab_app;
GRANT SELECT, INSERT, UPDATE ON ALL TABLES IN SCHEMA agent TO vulnlab_app;
ALTER DEFAULT PRIVILEGES IN SCHEMA agent
    GRANT SELECT, INSERT, UPDATE ON TABLES TO vulnlab_app;

COMMIT;
