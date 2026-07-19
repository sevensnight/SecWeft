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
        "0009_p9h_repository_hardening",
        "0010_p10_case_lifecycle",
        "0011_p11_evaluation_governance",
        "0012_p12_operational_resilience",
        "0013_p13_release_governance",
        "0014_p14_enterprise_acceptance_delivery",
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


def test_p9h_repository_hardening_migration_declares_adapter_contracts() -> None:
    up = MIGRATIONS / "0009_p9h_repository_hardening.up.sql"
    sql = up.read_text(encoding="utf-8").lower()

    assert "compat.repository_adapter_metadata" in sql
    assert "control.repository_adapter_contracts" in sql
    assert "controlplanerepository" in sql
    assert "sqlitecontrolplanerepository" in sql
    assert "postgrescontrolplanerepository" in sql
    assert "validation_plan_execution" in sql
    assert "idempotency_key_concurrency" in sql
    assert "timezone_aware_timestamps" in sql
    assert "required_behaviors jsonb not null" in sql
    assert "host network" not in sql
    assert "docker socket" not in sql
    assert "exploit payload" not in sql


def test_p10_case_lifecycle_migration_has_remediation_retest_and_comparison() -> None:
    up = MIGRATIONS / "0010_p10_case_lifecycle.up.sql"
    sql = up.read_text(encoding="utf-8").lower()

    assert "create schema if not exists case_mgmt" in sql
    assert "case_mgmt.vulnerability_cases" in sql
    assert "case_mgmt.case_findings" in sql
    assert "case_mgmt.remediation_proposals" in sql
    assert "case_mgmt.remediation_decisions" in sql
    assert "case_mgmt.remediation_implementations" in sql
    assert "case_mgmt.retest_requests" in sql
    assert "case_mgmt.validation_comparisons" in sql
    assert "case_mgmt.case_dispositions" in sql
    assert "case_mgmt.case_reports" in sql
    assert "ai_generated" in sql
    assert "validation.retest" not in sql
    assert "remediated" in sql
    assert "inconclusive" in sql
    assert "references validation.executions (tenant_id, id)" in sql
    assert "references case_mgmt.vulnerability_cases (tenant_id, id)" in sql
    assert "grant select, insert, update on all tables in schema case_mgmt to vulnlab_app" in sql
    assert "grant select, insert, update, delete on all tables in schema case_mgmt" not in sql
    assert "host network" not in sql
    assert "docker socket" not in sql
    assert "exploit payload" not in sql


def test_p11_evaluation_governance_migration_has_versioned_metrics_and_gates() -> None:
    up = MIGRATIONS / "0011_p11_evaluation_governance.up.sql"
    sql = up.read_text(encoding="utf-8").lower()

    assert "create schema if not exists evaluation" in sql
    assert "evaluation.evaluation_suites" in sql
    assert "evaluation.evaluation_datasets" in sql
    assert "evaluation.evaluation_cases" in sql
    assert "evaluation.metric_definitions" in sql
    assert "evaluation.evaluation_runs" in sql
    assert "evaluation.evaluation_run_variants" in sql
    assert "evaluation.configuration_snapshots" in sql
    assert "evaluation.evaluation_results" in sql
    assert "evaluation.metric_results" in sql
    assert "evaluation.regression_comparisons" in sql
    assert "evaluation.evaluation_reviews" in sql
    assert "evaluation.promotion_decisions" in sql
    assert "ground_truth_hash char(64) not null" in sql
    assert "config_hash char(64) not null" in sql
    assert "snapshot_hash char(64) not null" in sql
    assert "ck_eval_cases_judge" in sql
    assert "restricted_llm_judge" in sql
    assert "references evaluation.evaluation_datasets (tenant_id, id)" in sql
    assert "references evaluation.evaluation_runs (tenant_id, id)" in sql
    assert "references evaluation.evaluation_run_variants (tenant_id, id)" in sql
    assert "grant select, insert, update on all tables in schema evaluation to vulnlab_app" in sql
    assert "grant select, insert, update, delete on all tables in schema evaluation" not in sql
    assert "host network" not in sql
    assert "docker socket" not in sql
    assert "exploit payload" not in sql


def test_p12_operational_resilience_migration_has_ha_scaling_and_dr_state() -> None:
    up = MIGRATIONS / "0012_p12_operational_resilience.up.sql"
    sql = up.read_text(encoding="utf-8").lower()

    assert "create schema if not exists resilience" in sql
    assert "resilience.capacity_quotas" in sql
    assert "tenant_concurrency" in sql
    assert "project_concurrency" in sql
    assert "global_concurrency" in sql
    assert "sandbox_capacity" in sql
    assert "queue_backlog" in sql
    assert "resilience.service_instances" in sql
    assert "control_plane" in sql
    assert "validation_worker" in sql
    assert "resilience.worker_heartbeats" in sql
    assert "active_executions integer not null default 0" in sql
    assert "resilience.evidence_consistency_reports" in sql
    assert "missing_object" not in sql
    assert "resilience.backup_restore_drills" in sql
    assert "rpo_seconds integer" in sql
    assert "rto_seconds integer" in sql
    assert "resilience.failure_injection_events" in sql
    assert "isolated_environment boolean not null default true" in sql
    assert "force row level security" in sql
    assert "grant select, insert, update on all tables in schema resilience to vulnlab_app" in sql
    assert "grant select, insert, update, delete on all tables in schema resilience" not in sql
    assert "host network" not in sql
    assert "docker socket" not in sql
    assert "exploit payload" not in sql


def test_p13_release_governance_migration_has_supply_chain_and_release_state() -> None:
    up = MIGRATIONS / "0013_p13_release_governance.up.sql"
    sql = up.read_text(encoding="utf-8").lower()

    assert "create schema if not exists release" in sql
    assert "release.artifacts" in sql
    assert "release.candidates" in sql
    assert "release.gate_results" in sql
    assert "release.approvals" in sql
    assert "release.exceptions" in sql
    assert "release.environment_promotions" in sql
    assert "release.deployment_records" in sql
    assert "release.rollback_records" in sql
    assert "release.drift_detection_results" in sql
    assert "release.compliance_evidence_packages" in sql
    assert "sbom" in sql
    assert "provenance" in sql
    assert "signature" in sql
    assert "artifact_digest varchar(256) not null" in sql
    assert "image_digest varchar(256) not null" in sql
    assert "source_commit varchar(80) not null" in sql
    assert "version bigint not null default 1" in sql
    assert "force row level security" in sql
    assert "grant select, insert, update on all tables in schema release to vulnlab_app" in sql
    assert "grant select, insert, update, delete on all tables in schema release" not in sql
    assert "host network" not in sql
    assert "docker socket" not in sql
    assert "exploit payload" not in sql


def test_p14_enterprise_acceptance_migration_has_delivery_governance_and_rls() -> None:
    up = MIGRATIONS / "0014_p14_enterprise_acceptance_delivery.up.sql"
    sql = up.read_text(encoding="utf-8").lower()

    assert "create schema if not exists delivery" in sql
    assert "delivery.acceptance_runs" in sql
    assert "delivery.delivery_packages" in sql
    assert "delivery.data_exports" in sql
    assert "delivery.deletion_requests" in sql
    assert "delivery.legal_holds" in sql
    assert "delivery.compliance_evidence_packages" in sql
    assert "delivery.secret_rotation_records" in sql
    assert "runtime_not_claimed boolean not null default true" in sql
    assert "production_ready boolean not null default false" in sql
    assert "jsonb not null default '{}'::jsonb" in sql
    assert "ck_delivery_delete_no_self_approval" in sql
    assert "secret_count integer not null default 0" in sql
    assert "force row level security" in sql
    assert "grant select, insert, update on all tables in schema delivery to vulnlab_app" in sql
    assert "grant select, insert, update, delete on all tables in schema delivery" not in sql
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
