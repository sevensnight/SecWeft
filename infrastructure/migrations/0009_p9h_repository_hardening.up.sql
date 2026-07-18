BEGIN;

CREATE SCHEMA IF NOT EXISTS compat;

CREATE TABLE compat.repository_adapter_metadata (
    tenant_id uuid NOT NULL DEFAULT '00000000-0000-0000-0000-000000000000',
    id integer NOT NULL CHECK (id = 1),
    adapter_name text NOT NULL,
    adapter_version text NOT NULL,
    schema_name text NOT NULL,
    installed_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    version integer NOT NULL DEFAULT 1,
    PRIMARY KEY (tenant_id, id),
    CONSTRAINT ck_repository_adapter_metadata_version CHECK (version > 0)
);

CREATE TABLE control.repository_adapter_contracts (
    tenant_id uuid NOT NULL DEFAULT '00000000-0000-0000-0000-000000000000',
    domain text NOT NULL,
    repository_protocol text NOT NULL,
    sqlite_adapter text NOT NULL,
    postgres_adapter text NOT NULL,
    required_behaviors jsonb NOT NULL,
    created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    version integer NOT NULL DEFAULT 1,
    PRIMARY KEY (tenant_id, domain),
    CONSTRAINT ck_repository_contract_behaviors CHECK (
        jsonb_typeof(required_behaviors) = 'array'
    ),
    CONSTRAINT ck_repository_contract_version CHECK (version > 0)
);

INSERT INTO control.repository_adapter_contracts(
    domain, repository_protocol, sqlite_adapter, postgres_adapter, required_behaviors
) VALUES
    (
        'tenant_user_rbac',
        'ControlPlaneRepository',
        'SQLiteControlPlaneRepository',
        'PostgresControlPlaneRepository',
        '["foreign_keys","unique_constraints","tenant_or_owner_isolation","audit_atomicity"]'::jsonb
    ),
    (
        'model_provider_quota_cost',
        'ControlPlaneRepository',
        'SQLiteControlPlaneRepository',
        'PostgresControlPlaneRepository',
        '["unique_constraints","pagination_sorting","cost_precision","audit_atomicity"]'::jsonb
    ),
    (
        'task_stage_agent_skill',
        'ControlPlaneRepository',
        'SQLiteControlPlaneRepository',
        'PostgresControlPlaneRepository',
        '["foreign_keys","lease_cas","optimistic_locking","pagination_sorting"]'::jsonb
    ),
    (
        'knowledge_context',
        'ControlPlaneRepository',
        'SQLiteControlPlaneRepository',
        'PostgresControlPlaneRepository',
        '["foreign_keys","json_metadata","classification_filters","pagination_sorting"]'::jsonb
    ),
    (
        'policy_approval_asset_scope',
        'ControlPlaneRepository',
        'SQLiteControlPlaneRepository',
        'PostgresControlPlaneRepository',
        '["scope_hash_binding","approval_revocation_race","policy_decision_audit","foreign_keys"]'::jsonb
    ),
    (
        'validation_plan_execution',
        'ControlPlaneRepository',
        'SQLiteControlPlaneRepository',
        'PostgresControlPlaneRepository',
        '["idempotency_key_concurrency","execution_lease_cas","cancellation_race","worker_recovery"]'::jsonb
    ),
    (
        'execution_event_evidence_review',
        'ControlPlaneRepository',
        'SQLiteControlPlaneRepository',
        'PostgresControlPlaneRepository',
        '["foreign_keys","evidence_hash_metadata","review_atomicity","pagination_sorting"]'::jsonb
    ),
    (
        'audit_report',
        'ControlPlaneRepository',
        'SQLiteControlPlaneRepository',
        'PostgresControlPlaneRepository',
        '["append_only_chain","transaction_atomicity","tamper_detection","timezone_aware_timestamps"]'::jsonb
    )
ON CONFLICT(tenant_id, domain) DO UPDATE
SET repository_protocol = excluded.repository_protocol,
    sqlite_adapter = excluded.sqlite_adapter,
    postgres_adapter = excluded.postgres_adapter,
    required_behaviors = excluded.required_behaviors,
    updated_at = CURRENT_TIMESTAMP,
    version = control.repository_adapter_contracts.version + 1;

COMMIT;
