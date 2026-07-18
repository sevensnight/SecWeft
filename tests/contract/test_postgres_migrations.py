from __future__ import annotations

from tools.contracts.check_migrations import MIGRATIONS, check, migration_pairs, validate_pair


def test_p0_postgres_migrations_are_reversible_and_tenant_safe() -> None:
    result = check()
    assert result["valid"], result["errors"]
    assert result["pairs"] == [
        "0001_p0_enterprise_baseline",
        "0002_p1_identity_tenancy_rbac",
        "0003_p1_role_scope_enforcement",
        "0004_p1_application_least_privilege",
        "0005_p2_model_gateway",
        "0006_p3_agent_orchestration",
        "0007_p9_validation_execution_plane",
        "0008_p9r_validation_runtime_outbox",
    ]


def test_p0_migration_contains_no_execution_or_vulnerability_payloads() -> None:
    pairs = migration_pairs()
    sql = "\n".join(path.read_text(encoding="utf-8").lower() for pair in pairs for path in pair)
    assert "docker socket" not in sql
    assert "host network" not in sql
    assert "exploit payload" not in sql
    assert "credential theft" not in sql
    assert "todo" not in sql
    assert MIGRATIONS.is_dir()


def test_p2_model_gateway_migration_keeps_secrets_and_payloads_out_of_read_models() -> None:
    up = MIGRATIONS / "0005_p2_model_gateway.up.sql"
    sql = up.read_text(encoding="utf-8").lower()

    assert "create schema if not exists model" in sql
    assert "model.credentials" in sql
    assert "secret_ciphertext bytea not null" in sql
    assert "secret_plaintext" not in sql
    assert "api_key text" not in sql
    assert "api_key varchar" not in sql
    assert "prompt_text" not in sql
    assert "response_text" not in sql
    assert "request_sha256" in sql
    assert "response_sha256" in sql
    assert "alter table %s force row level security" in sql
    assert "grant select, insert, update on all tables in schema model to vulnlab_app" in sql
    assert "grant select, insert, update, delete on all tables in schema model" not in sql


def test_p3_agent_orchestration_migration_has_leases_dlq_and_rls() -> None:
    up = MIGRATIONS / "0006_p3_agent_orchestration.up.sql"
    sql = up.read_text(encoding="utf-8").lower()

    assert "create schema if not exists agent" in sql
    assert "agent.agent_definitions" in sql
    assert "agent.skill_definitions" in sql
    assert "agent.workflow_definitions" in sql
    assert "agent.workflow_stages" in sql
    assert "agent.task_executions" in sql
    assert "agent.queue_messages" in sql
    assert "agent.dead_letters" in sql
    assert "lease_token uuid not null" in sql
    assert "fencing_token bigint not null" in sql
    assert "locked_until timestamptz" in sql
    assert "references control.tasks (tenant_id, project_id, id)" in sql
    assert "alter table %s force row level security" in sql
    assert "grant select, insert, update on all tables in schema agent to vulnlab_app" in sql
    assert "grant select, insert, update, delete on all tables in schema agent" not in sql
    assert "exploit payload" not in sql


def test_p9_validation_execution_migration_has_queue_evidence_and_statuses() -> None:
    up = MIGRATIONS / "0007_p9_validation_execution_plane.up.sql"
    sql = up.read_text(encoding="utf-8").lower()

    assert "create schema if not exists validation" in sql
    assert "validation.executions" in sql
    assert "validation.execution_events" in sql
    assert "validation.execution_evidence" in sql
    assert "validation.queue_messages" in sql
    assert "approval_revoked" in sql
    assert "policy_rejected" in sql
    assert "execution_timeout" in sql
    assert "content_sha256 char(64) not null" in sql
    assert "idx_validation_queue_ready" in sql
    assert "host network" not in sql
    assert "docker socket" not in sql
    assert "exploit payload" not in sql


def test_p9r_runtime_outbox_migration_has_publish_and_lease_fields() -> None:
    up = MIGRATIONS / "0008_p9r_validation_runtime_outbox.up.sql"
    sql = up.read_text(encoding="utf-8").lower()

    assert "validation.executions" in sql
    assert "lease_owner varchar(160)" in sql
    assert "lease_token uuid" in sql
    assert "lease_expires_at timestamptz" in sql
    assert "worker_attempt integer not null default 0" in sql
    assert "validation.queue_messages" in sql
    assert "schema_version integer not null default 1" in sql
    assert "publish_attempt integer not null default 0" in sql
    assert "published_at timestamptz" in sql
    assert "last_publish_error text" in sql
    assert "idx_validation_queue_outbox_unpublished" in sql
    assert "idx_validation_execution_lease" in sql
    assert "host network" not in sql
    assert "docker socket" not in sql
    assert "exploit payload" not in sql


def test_migration_checker_rejects_tenant_unsafe_foreign_key(tmp_path) -> None:
    up, down = migration_pairs()[0]
    unsafe_up = tmp_path / up.name
    copied_down = tmp_path / down.name
    unsafe_up.write_text(
        up.read_text(encoding="utf-8").replace(
            "REFERENCES control.tasks (tenant_id, id)",
            "REFERENCES control.tasks (id)",
            1,
        ),
        encoding="utf-8",
    )
    copied_down.write_text(down.read_text(encoding="utf-8"), encoding="utf-8")

    errors = validate_pair(unsafe_up, copied_down)
    assert any("foreign keys must include tenant_id" in error for error in errors)


def test_migration_checker_rejects_non_reversed_rollback(tmp_path) -> None:
    up, down = migration_pairs()[0]
    copied_up = tmp_path / up.name
    unordered_down = tmp_path / down.name
    copied_up.write_text(up.read_text(encoding="utf-8"), encoding="utf-8")
    unordered_down.write_text(
        down.read_text(encoding="utf-8").replace(
            "DROP TABLE IF EXISTS audit.chain_heads;\nDROP TABLE IF EXISTS audit.events;",
            "DROP TABLE IF EXISTS audit.events;\nDROP TABLE IF EXISTS audit.chain_heads;",
        ),
        encoding="utf-8",
    )

    errors = validate_pair(copied_up, unordered_down)
    assert "down migration must drop tables in exact reverse dependency order" in errors
