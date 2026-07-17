BEGIN;

CREATE SCHEMA IF NOT EXISTS model;

CREATE TABLE model.credentials (
    id uuid NOT NULL,
    tenant_id uuid NOT NULL,
    display_name varchar(120) NOT NULL,
    kind varchar(40) NOT NULL,
    secret_ciphertext bytea NOT NULL,
    secret_sha256 char(64) NOT NULL,
    status varchar(20) NOT NULL DEFAULT 'ACTIVE',
    created_by uuid NOT NULL,
    rotated_by uuid NOT NULL,
    created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    rotated_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    version bigint NOT NULL DEFAULT 1,
    PRIMARY KEY (tenant_id, id),
    CONSTRAINT fk_model_credentials_tenant FOREIGN KEY (tenant_id)
        REFERENCES iam.tenants (id) ON UPDATE RESTRICT ON DELETE RESTRICT,
    CONSTRAINT fk_model_credentials_creator FOREIGN KEY (tenant_id, created_by)
        REFERENCES iam.users (tenant_id, id) ON UPDATE RESTRICT ON DELETE RESTRICT,
    CONSTRAINT fk_model_credentials_rotator FOREIGN KEY (tenant_id, rotated_by)
        REFERENCES iam.users (tenant_id, id) ON UPDATE RESTRICT ON DELETE RESTRICT,
    CONSTRAINT ck_model_credentials_kind CHECK (kind IN ('api_key', 'oauth_token', 'custom_header')),
    CONSTRAINT ck_model_credentials_status CHECK (status IN ('ACTIVE', 'REVOKED')),
    CONSTRAINT ck_model_credentials_secret_sha CHECK (secret_sha256 ~ '^[0-9a-f]{64}$'),
    CONSTRAINT ck_model_credentials_version CHECK (version > 0),
    CONSTRAINT ck_model_credentials_timestamps CHECK (updated_at >= created_at AND rotated_at >= created_at)
);

CREATE UNIQUE INDEX uq_model_credentials_display_active
    ON model.credentials (tenant_id, lower(display_name))
    WHERE status = 'ACTIVE';

CREATE TABLE model.providers (
    id uuid NOT NULL,
    tenant_id uuid NOT NULL,
    name varchar(80) NOT NULL,
    kind varchar(40) NOT NULL,
    base_url varchar(2048),
    credential_id uuid,
    enabled boolean NOT NULL DEFAULT true,
    priority integer NOT NULL DEFAULT 100,
    rate_limit_per_minute integer NOT NULL DEFAULT 60,
    token_quota_per_minute integer NOT NULL DEFAULT 100000,
    timeout_seconds numeric(8,3) NOT NULL DEFAULT 30,
    circuit_failure_threshold integer NOT NULL DEFAULT 3,
    circuit_cooldown_seconds integer NOT NULL DEFAULT 30,
    config jsonb NOT NULL DEFAULT '{}'::jsonb,
    created_by uuid NOT NULL,
    updated_by uuid NOT NULL,
    created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    version bigint NOT NULL DEFAULT 1,
    PRIMARY KEY (tenant_id, id),
    CONSTRAINT fk_model_providers_tenant FOREIGN KEY (tenant_id)
        REFERENCES iam.tenants (id) ON UPDATE RESTRICT ON DELETE RESTRICT,
    CONSTRAINT fk_model_providers_credential FOREIGN KEY (tenant_id, credential_id)
        REFERENCES model.credentials (tenant_id, id) ON UPDATE RESTRICT ON DELETE RESTRICT,
    CONSTRAINT fk_model_providers_creator FOREIGN KEY (tenant_id, created_by)
        REFERENCES iam.users (tenant_id, id) ON UPDATE RESTRICT ON DELETE RESTRICT,
    CONSTRAINT fk_model_providers_updater FOREIGN KEY (tenant_id, updated_by)
        REFERENCES iam.users (tenant_id, id) ON UPDATE RESTRICT ON DELETE RESTRICT,
    CONSTRAINT ck_model_providers_name CHECK (name ~ '^[A-Za-z0-9][A-Za-z0-9_. -]{0,78}[A-Za-z0-9]$'),
    CONSTRAINT ck_model_providers_kind CHECK (kind IN ('mock', 'openai_compatible', 'ollama')),
    CONSTRAINT ck_model_providers_endpoint CHECK (
        (kind = 'mock' AND base_url IS NULL)
        OR (kind <> 'mock' AND base_url ~ '^https?://')
    ),
    CONSTRAINT ck_model_providers_priority CHECK (priority BETWEEN 0 AND 10000),
    CONSTRAINT ck_model_providers_rate CHECK (rate_limit_per_minute BETWEEN 1 AND 10000),
    CONSTRAINT ck_model_providers_token_quota CHECK (token_quota_per_minute BETWEEN 128 AND 10000000),
    CONSTRAINT ck_model_providers_timeout CHECK (timeout_seconds BETWEEN 1 AND 300),
    CONSTRAINT ck_model_providers_circuit CHECK (
        circuit_failure_threshold BETWEEN 1 AND 20
        AND circuit_cooldown_seconds BETWEEN 1 AND 3600
    ),
    CONSTRAINT ck_model_providers_version CHECK (version > 0),
    CONSTRAINT ck_model_providers_timestamps CHECK (updated_at >= created_at)
);

CREATE UNIQUE INDEX uq_model_providers_name
    ON model.providers (tenant_id, lower(name));
CREATE INDEX idx_model_providers_route
    ON model.providers (tenant_id, enabled, priority, id);

CREATE TABLE model.instances (
    id uuid NOT NULL,
    tenant_id uuid NOT NULL,
    provider_id uuid NOT NULL,
    model_key varchar(160) NOT NULL,
    display_name varchar(160) NOT NULL,
    version_label varchar(80) NOT NULL DEFAULT 'default',
    capabilities text[] NOT NULL DEFAULT ARRAY[]::text[],
    context_window_tokens integer NOT NULL DEFAULT 8192,
    max_output_tokens integer NOT NULL DEFAULT 4096,
    input_cost_per_1k numeric(14,8) NOT NULL DEFAULT 0,
    output_cost_per_1k numeric(14,8) NOT NULL DEFAULT 0,
    enabled boolean NOT NULL DEFAULT true,
    health_status varchar(20) NOT NULL DEFAULT 'UNKNOWN',
    created_by uuid NOT NULL,
    updated_by uuid NOT NULL,
    created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    version bigint NOT NULL DEFAULT 1,
    PRIMARY KEY (tenant_id, id),
    CONSTRAINT fk_model_instances_provider FOREIGN KEY (tenant_id, provider_id)
        REFERENCES model.providers (tenant_id, id) ON UPDATE RESTRICT ON DELETE RESTRICT,
    CONSTRAINT fk_model_instances_creator FOREIGN KEY (tenant_id, created_by)
        REFERENCES iam.users (tenant_id, id) ON UPDATE RESTRICT ON DELETE RESTRICT,
    CONSTRAINT fk_model_instances_updater FOREIGN KEY (tenant_id, updated_by)
        REFERENCES iam.users (tenant_id, id) ON UPDATE RESTRICT ON DELETE RESTRICT,
    CONSTRAINT ck_model_instances_model_key CHECK (model_key ~ '^[A-Za-z0-9][A-Za-z0-9_.:/@+-]{0,159}$'),
    CONSTRAINT ck_model_instances_context CHECK (context_window_tokens BETWEEN 128 AND 4000000),
    CONSTRAINT ck_model_instances_output CHECK (max_output_tokens BETWEEN 16 AND 1000000),
    CONSTRAINT ck_model_instances_cost CHECK (input_cost_per_1k >= 0 AND output_cost_per_1k >= 0),
    CONSTRAINT ck_model_instances_health CHECK (health_status IN ('UNKNOWN', 'READY', 'DEGRADED', 'DOWN')),
    CONSTRAINT ck_model_instances_version CHECK (version > 0),
    CONSTRAINT ck_model_instances_timestamps CHECK (updated_at >= created_at)
);

CREATE UNIQUE INDEX uq_model_instances_key
    ON model.instances (tenant_id, provider_id, model_key, version_label);
CREATE INDEX idx_model_instances_enabled
    ON model.instances (tenant_id, enabled, provider_id);

CREATE TABLE model.invocations (
    id uuid NOT NULL,
    tenant_id uuid NOT NULL,
    project_id uuid,
    provider_id uuid,
    model_instance_id uuid,
    actor_user_id uuid,
    purpose varchar(40) NOT NULL,
    request_sha256 char(64) NOT NULL,
    response_sha256 char(64),
    status varchar(20) NOT NULL,
    prompt_tokens integer NOT NULL DEFAULT 0,
    completion_tokens integer NOT NULL DEFAULT 0,
    total_tokens integer NOT NULL DEFAULT 0,
    cost_usd numeric(18,8) NOT NULL DEFAULT 0,
    failover_count integer NOT NULL DEFAULT 0,
    structured_output boolean NOT NULL DEFAULT false,
    tool_count integer NOT NULL DEFAULT 0,
    latency_ms integer NOT NULL DEFAULT 0,
    error_code varchar(80),
    trace_id char(32),
    request_id uuid,
    occurred_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    version bigint NOT NULL DEFAULT 1,
    PRIMARY KEY (tenant_id, id),
    CONSTRAINT fk_model_invocations_tenant FOREIGN KEY (tenant_id)
        REFERENCES iam.tenants (id) ON UPDATE RESTRICT ON DELETE RESTRICT,
    CONSTRAINT fk_model_invocations_project FOREIGN KEY (tenant_id, project_id)
        REFERENCES iam.projects (tenant_id, id) ON UPDATE RESTRICT ON DELETE RESTRICT,
    CONSTRAINT fk_model_invocations_provider FOREIGN KEY (tenant_id, provider_id)
        REFERENCES model.providers (tenant_id, id) ON UPDATE RESTRICT ON DELETE RESTRICT,
    CONSTRAINT fk_model_invocations_instance FOREIGN KEY (tenant_id, model_instance_id)
        REFERENCES model.instances (tenant_id, id) ON UPDATE RESTRICT ON DELETE RESTRICT,
    CONSTRAINT fk_model_invocations_actor FOREIGN KEY (tenant_id, actor_user_id)
        REFERENCES iam.users (tenant_id, id) ON UPDATE RESTRICT ON DELETE RESTRICT,
    CONSTRAINT ck_model_invocations_status CHECK (status IN ('SUCCEEDED', 'FAILED', 'RATE_LIMITED', 'CIRCUIT_OPEN')),
    CONSTRAINT ck_model_invocations_hash CHECK (
        request_sha256 ~ '^[0-9a-f]{64}$'
        AND (response_sha256 IS NULL OR response_sha256 ~ '^[0-9a-f]{64}$')
    ),
    CONSTRAINT ck_model_invocations_tokens CHECK (
        prompt_tokens >= 0
        AND completion_tokens >= 0
        AND total_tokens = prompt_tokens + completion_tokens
    ),
    CONSTRAINT ck_model_invocations_cost CHECK (cost_usd >= 0),
    CONSTRAINT ck_model_invocations_counts CHECK (
        failover_count >= 0 AND tool_count >= 0 AND latency_ms >= 0
    ),
    CONSTRAINT ck_model_invocations_version CHECK (version > 0),
    CONSTRAINT ck_model_invocations_timestamps CHECK (updated_at >= created_at)
);

CREATE INDEX idx_model_invocations_project_time
    ON model.invocations (tenant_id, project_id, occurred_at DESC, id DESC);
CREATE INDEX idx_model_invocations_actor_time
    ON model.invocations (tenant_id, actor_user_id, occurred_at DESC, id DESC);
CREATE INDEX idx_model_invocations_provider_time
    ON model.invocations (tenant_id, provider_id, occurred_at DESC, id DESC);

DO $rls$
DECLARE
    target text;
BEGIN
    FOREACH target IN ARRAY ARRAY[
        'model.credentials',
        'model.providers',
        'model.instances',
        'model.invocations'
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

GRANT USAGE ON SCHEMA model TO vulnlab_app;
GRANT SELECT, INSERT, UPDATE ON ALL TABLES IN SCHEMA model TO vulnlab_app;
ALTER DEFAULT PRIVILEGES IN SCHEMA model
    GRANT SELECT, INSERT, UPDATE ON TABLES TO vulnlab_app;

COMMIT;
