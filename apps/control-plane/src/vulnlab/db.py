from __future__ import annotations

import hashlib
import json
import sqlite3
import threading
from collections.abc import Iterator, Sequence
from contextlib import closing, contextmanager
from pathlib import Path
from typing import Any

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    username TEXT NOT NULL UNIQUE,
    key_hash TEXT NOT NULL UNIQUE,
    role TEXT NOT NULL CHECK(role IN ('viewer','analyst','operator','admin')),
    active INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS providers (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    kind TEXT NOT NULL CHECK(kind IN ('mock','openai_compatible','ollama')),
    base_url TEXT,
    model TEXT NOT NULL,
    encrypted_api_key TEXT,
    enabled INTEGER NOT NULL DEFAULT 1,
    priority INTEGER NOT NULL DEFAULT 100,
    rate_limit_per_minute INTEGER NOT NULL DEFAULT 60,
    token_quota_per_minute INTEGER NOT NULL DEFAULT 100000,
    timeout_seconds REAL NOT NULL DEFAULT 30,
    input_cost_per_1k REAL NOT NULL DEFAULT 0,
    output_cost_per_1k REAL NOT NULL DEFAULT 0,
    capabilities_json TEXT NOT NULL DEFAULT '[]',
    config_json TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS model_invocations (
    id TEXT PRIMARY KEY,
    actor_id TEXT NOT NULL REFERENCES users(id),
    provider_id TEXT,
    provider_name TEXT NOT NULL,
    model TEXT NOT NULL,
    purpose TEXT NOT NULL,
    request_hash TEXT NOT NULL,
    status TEXT NOT NULL CHECK(status IN ('succeeded','failed')),
    prompt_tokens INTEGER NOT NULL DEFAULT 0,
    completion_tokens INTEGER NOT NULL DEFAULT 0,
    total_tokens INTEGER NOT NULL DEFAULT 0,
    cost_usd REAL NOT NULL DEFAULT 0,
    failover_count INTEGER NOT NULL DEFAULT 0,
    structured_output INTEGER NOT NULL DEFAULT 0,
    tool_count INTEGER NOT NULL DEFAULT 0,
    latency_ms INTEGER NOT NULL DEFAULT 0,
    error TEXT,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS scopes (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    target_pattern TEXT NOT NULL,
    protocols_json TEXT NOT NULL,
    ports_json TEXT NOT NULL,
    expires_at TEXT,
    approved INTEGER NOT NULL DEFAULT 0,
    approved_by TEXT REFERENCES users(id),
    approved_at TEXT,
    approval_reason TEXT,
    resolved_ips_json TEXT NOT NULL DEFAULT '[]',
    scope_hash TEXT NOT NULL,
    created_by TEXT NOT NULL REFERENCES users(id),
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS target_profiles (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    target TEXT NOT NULL,
    proxy_url TEXT,
    proxy_scope_id TEXT REFERENCES scopes(id),
    intent TEXT NOT NULL,
    indicators_json TEXT NOT NULL DEFAULT '[]',
    scope_id TEXT NOT NULL REFERENCES scopes(id),
    created_by TEXT NOT NULL REFERENCES users(id),
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS skills (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    version TEXT NOT NULL DEFAULT '1.0',
    description TEXT NOT NULL,
    risk_level TEXT NOT NULL CHECK(risk_level IN ('low','medium','high')),
    required_role TEXT NOT NULL,
    input_schema_json TEXT NOT NULL,
    output_schema_json TEXT NOT NULL DEFAULT '{"type":"object"}',
    permissions_json TEXT NOT NULL DEFAULT '[]',
    resource_limits_json TEXT NOT NULL DEFAULT '{}',
    timeout_seconds REAL NOT NULL DEFAULT 30,
    execution_type TEXT NOT NULL DEFAULT 'internal',
    tool_dependencies_json TEXT NOT NULL DEFAULT '[]',
    approval_required INTEGER NOT NULL DEFAULT 0,
    enabled INTEGER NOT NULL DEFAULT 1,
    builtin INTEGER NOT NULL DEFAULT 0,
    invocation_count INTEGER NOT NULL DEFAULT 0,
    success_count INTEGER NOT NULL DEFAULT 0,
    failure_count INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS agents (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    version TEXT NOT NULL DEFAULT '1.0',
    description TEXT NOT NULL,
    responsibilities_json TEXT NOT NULL DEFAULT '[]',
    input_schema_json TEXT NOT NULL DEFAULT '{"type":"object"}',
    output_schema_json TEXT NOT NULL DEFAULT '{"type":"object"}',
    allowed_tools_json TEXT NOT NULL DEFAULT '[]',
    data_scope TEXT NOT NULL DEFAULT 'task',
    token_budget INTEGER NOT NULL DEFAULT 0,
    timeout_seconds REAL NOT NULL DEFAULT 60,
    risk_level TEXT NOT NULL CHECK(risk_level IN ('low','medium','high')),
    retry_policy_json TEXT NOT NULL DEFAULT '{}',
    enabled INTEGER NOT NULL DEFAULT 1,
    builtin INTEGER NOT NULL DEFAULT 0,
    created_by TEXT REFERENCES users(id),
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    UNIQUE(name, version)
);

CREATE TABLE IF NOT EXISTS workflows (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    version TEXT NOT NULL DEFAULT '1.0',
    description TEXT NOT NULL,
    stages_json TEXT NOT NULL,
    enabled INTEGER NOT NULL DEFAULT 1,
    builtin INTEGER NOT NULL DEFAULT 0,
    created_by TEXT REFERENCES users(id),
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    UNIQUE(name, version)
);

CREATE TABLE IF NOT EXISTS tasks (
    id TEXT PRIMARY KEY,
    title TEXT NOT NULL,
    target TEXT NOT NULL,
    intent TEXT NOT NULL,
    indicators_json TEXT NOT NULL DEFAULT '[]',
    scope_id TEXT NOT NULL REFERENCES scopes(id),
    status TEXT NOT NULL,
    approval_status TEXT NOT NULL,
    approved_by TEXT REFERENCES users(id),
    approved_at TEXT,
    approval_reason TEXT,
    scope_hash TEXT NOT NULL,
    created_by TEXT NOT NULL REFERENCES users(id),
    assigned_skills_json TEXT NOT NULL DEFAULT '[]',
    workflow_name TEXT NOT NULL DEFAULT 'p3.synthetic.defensive',
    workflow_version TEXT NOT NULL DEFAULT '1.0',
    plan_json TEXT,
    result_json TEXT,
    error TEXT,
    current_stage TEXT,
    pause_requested INTEGER NOT NULL DEFAULT 0,
    cancel_requested INTEGER NOT NULL DEFAULT 0,
    retry_count INTEGER NOT NULL DEFAULT 0,
    max_retries INTEGER NOT NULL DEFAULT 2,
    lease_owner TEXT,
    lease_token TEXT,
    lease_expires_at TEXT,
    fencing_token INTEGER NOT NULL DEFAULT 0,
    deadline_at TEXT,
    started_at TEXT,
    finished_at TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS task_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    task_id TEXT NOT NULL REFERENCES tasks(id) ON DELETE CASCADE,
    event_type TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS task_stages (
    id TEXT PRIMARY KEY,
    task_id TEXT NOT NULL REFERENCES tasks(id) ON DELETE CASCADE,
    stage_code TEXT NOT NULL,
    display_name TEXT NOT NULL,
    sequence_no INTEGER NOT NULL,
    agent_name TEXT NOT NULL,
    agent_version TEXT NOT NULL DEFAULT '1.0',
    skill_name TEXT NOT NULL,
    skill_version TEXT NOT NULL DEFAULT '1.0',
    depends_on_json TEXT NOT NULL DEFAULT '[]',
    status TEXT NOT NULL CHECK(status IN ('pending','ready','running','paused','succeeded','failed','skipped','cancelled','timed_out')),
    attempt INTEGER NOT NULL DEFAULT 0,
    max_attempts INTEGER NOT NULL DEFAULT 1,
    lease_owner TEXT,
    lease_token TEXT,
    lease_expires_at TEXT,
    checkpoint_json TEXT,
    output_json TEXT,
    error TEXT,
    started_at TEXT,
    finished_at TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    UNIQUE(task_id, stage_code),
    UNIQUE(task_id, sequence_no)
);

CREATE TABLE IF NOT EXISTS task_executions (
    id TEXT PRIMARY KEY,
    task_id TEXT NOT NULL REFERENCES tasks(id) ON DELETE CASCADE,
    worker_id TEXT NOT NULL,
    lease_token TEXT NOT NULL,
    fencing_token INTEGER NOT NULL,
    status TEXT NOT NULL CHECK(status IN ('leased','running','paused','succeeded','failed','cancelled','timed_out')),
    started_at TEXT NOT NULL,
    heartbeat_at TEXT NOT NULL,
    finished_at TEXT,
    error TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS task_queue_messages (
    id TEXT PRIMARY KEY,
    task_id TEXT NOT NULL REFERENCES tasks(id) ON DELETE CASCADE,
    message_id TEXT NOT NULL UNIQUE,
    status TEXT NOT NULL CHECK(status IN ('ready','leased','done','cancelled','dead')),
    attempt INTEGER NOT NULL DEFAULT 0,
    max_attempts INTEGER NOT NULL DEFAULT 3,
    available_at TEXT NOT NULL,
    locked_by TEXT,
    lock_token TEXT,
    locked_until TEXT,
    last_error TEXT,
    payload_json TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS task_dead_letters (
    id TEXT PRIMARY KEY,
    task_id TEXT REFERENCES tasks(id) ON DELETE SET NULL,
    queue_message_id TEXT,
    reason TEXT NOT NULL,
    payload_json TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS task_idempotency_records (
    id TEXT PRIMARY KEY,
    principal_id TEXT NOT NULL REFERENCES users(id),
    operation TEXT NOT NULL,
    idempotency_key TEXT NOT NULL,
    request_hash TEXT NOT NULL,
    response_json TEXT,
    resource_type TEXT,
    resource_id TEXT,
    status TEXT NOT NULL CHECK(status IN ('processing','completed','failed')),
    expires_at TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    UNIQUE(principal_id, operation, idempotency_key)
);

CREATE TABLE IF NOT EXISTS memory_messages (
    id TEXT PRIMARY KEY,
    task_id TEXT NOT NULL REFERENCES tasks(id) ON DELETE CASCADE,
    owner_id TEXT NOT NULL REFERENCES users(id),
    role TEXT NOT NULL,
    content TEXT NOT NULL,
    content_hash TEXT NOT NULL,
    visibility TEXT NOT NULL CHECK(visibility IN ('private','task')),
    sequence_no INTEGER NOT NULL DEFAULT 0,
    token_estimate INTEGER NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS checkpoints (
    id TEXT PRIMARY KEY,
    task_id TEXT NOT NULL REFERENCES tasks(id) ON DELETE CASCADE,
    summary TEXT NOT NULL,
    state_json TEXT NOT NULL,
    summary_hash TEXT NOT NULL,
    state_hash TEXT NOT NULL,
    message_count INTEGER NOT NULL,
    evidence_count INTEGER NOT NULL DEFAULT 0,
    restore_policy_hash TEXT NOT NULL DEFAULT '',
    created_by TEXT NOT NULL REFERENCES users(id),
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS rag_documents (
    id TEXT PRIMARY KEY,
    tenant_key TEXT NOT NULL DEFAULT 'compat',
    project_key TEXT,
    title TEXT NOT NULL,
    content TEXT NOT NULL,
    source TEXT NOT NULL,
    classification TEXT NOT NULL CHECK(classification IN ('public','internal','restricted')),
    version TEXT NOT NULL,
    tags_json TEXT NOT NULL,
    metadata_json TEXT NOT NULL DEFAULT '{}',
    content_hash TEXT NOT NULL,
    created_by TEXT NOT NULL REFERENCES users(id),
    created_at TEXT NOT NULL,
    UNIQUE(tenant_key, project_key, source, version, content_hash)
);

CREATE TABLE IF NOT EXISTS rag_chunks (
    id TEXT PRIMARY KEY,
    document_id TEXT NOT NULL REFERENCES rag_documents(id) ON DELETE CASCADE,
    chunk_index INTEGER NOT NULL,
    content TEXT NOT NULL,
    token_estimate INTEGER NOT NULL,
    chunk_hash TEXT NOT NULL,
    created_at TEXT NOT NULL,
    UNIQUE(document_id, chunk_index),
    UNIQUE(document_id, chunk_hash)
);

CREATE TABLE IF NOT EXISTS evidence_items (
    id TEXT PRIMARY KEY,
    task_id TEXT NOT NULL REFERENCES tasks(id) ON DELETE CASCADE,
    title TEXT NOT NULL,
    source_type TEXT NOT NULL CHECK(source_type IN ('manual','rag_chunk','checkpoint','task_output')),
    source_ref TEXT NOT NULL,
    content TEXT NOT NULL,
    content_hash TEXT NOT NULL,
    classification TEXT NOT NULL CHECK(classification IN ('public','internal','restricted')),
    trust TEXT NOT NULL CHECK(trust IN ('untrusted_evidence_only','operator_attested','system_observed')),
    metadata_json TEXT NOT NULL DEFAULT '{}',
    created_by TEXT NOT NULL REFERENCES users(id),
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS policy_decisions (
    id TEXT PRIMARY KEY,
    actor_id TEXT NOT NULL REFERENCES users(id),
    action TEXT NOT NULL,
    resource_type TEXT NOT NULL,
    resource_id TEXT NOT NULL,
    decision TEXT NOT NULL CHECK(decision IN ('allow','deny','requires_approval')),
    reason TEXT NOT NULL,
    details_json TEXT NOT NULL DEFAULT '{}',
    policy_hash TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS validation_plans (
    id TEXT PRIMARY KEY,
    task_id TEXT NOT NULL REFERENCES tasks(id) ON DELETE CASCADE,
    status TEXT NOT NULL CHECK(status IN ('draft','submitted','approved','rejected','revoked')),
    plan_json TEXT NOT NULL,
    plan_hash TEXT NOT NULL,
    policy_decision_ids_json TEXT NOT NULL DEFAULT '[]',
    created_by TEXT NOT NULL REFERENCES users(id),
    submitted_at TEXT,
    reviewed_by TEXT REFERENCES users(id),
    reviewed_at TEXT,
    review_reason TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS validation_executions (
    id TEXT PRIMARY KEY,
    plan_id TEXT NOT NULL REFERENCES validation_plans(id) ON DELETE CASCADE,
    task_id TEXT NOT NULL REFERENCES tasks(id) ON DELETE CASCADE,
    tenant_id TEXT NOT NULL,
    template_id TEXT NOT NULL,
    template_version TEXT NOT NULL,
    status TEXT NOT NULL CHECK(status IN (
        'QUEUED','PROVISIONING','RUNNING','COLLECTING_EVIDENCE','VERIFYING',
        'SUCCEEDED','FAILED','CANCELLED','EXPIRED','POLICY_REJECTED',
        'APPROVAL_REVOKED','SCOPE_INVALID','SANDBOX_FAILED','RESOURCE_EXCEEDED',
        'EXECUTION_TIMEOUT','EVIDENCE_INCOMPLETE'
    )),
    trace_id TEXT NOT NULL,
    sandbox_id TEXT NOT NULL,
    approval_id TEXT NOT NULL,
    policy_decision_id TEXT NOT NULL REFERENCES policy_decisions(id),
    idempotency_key TEXT,
    queue_message_id TEXT,
    result_json TEXT NOT NULL DEFAULT '{}',
    error TEXT,
    review_decision TEXT CHECK(review_decision IN ('accepted','rejected')),
    review_reason TEXT,
    reviewed_by TEXT REFERENCES users(id),
    reviewed_at TEXT,
    retry_of TEXT REFERENCES validation_executions(id),
    created_by TEXT NOT NULL REFERENCES users(id),
    lease_owner TEXT,
    lease_token TEXT,
    lease_expires_at TEXT,
    worker_attempt INTEGER NOT NULL DEFAULT 0,
    started_at TEXT,
    finished_at TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS validation_execution_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    execution_id TEXT NOT NULL REFERENCES validation_executions(id) ON DELETE CASCADE,
    event_type TEXT NOT NULL,
    status TEXT NOT NULL,
    payload_json TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS validation_execution_evidence (
    id TEXT PRIMARY KEY,
    execution_id TEXT NOT NULL REFERENCES validation_executions(id) ON DELETE CASCADE,
    task_id TEXT NOT NULL REFERENCES tasks(id) ON DELETE CASCADE,
    evidence_item_id TEXT REFERENCES evidence_items(id),
    title TEXT NOT NULL,
    artifact_ref TEXT NOT NULL,
    content_sha256 TEXT NOT NULL,
    metadata_json TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS validation_queue_messages (
    id TEXT PRIMARY KEY,
    execution_id TEXT NOT NULL REFERENCES validation_executions(id) ON DELETE CASCADE,
    message_id TEXT NOT NULL UNIQUE,
    subject TEXT NOT NULL,
    schema_version INTEGER NOT NULL DEFAULT 1,
    status TEXT NOT NULL CHECK(status IN ('ready','leased','done','cancelled','dead')),
    attempt INTEGER NOT NULL DEFAULT 0,
    max_attempts INTEGER NOT NULL DEFAULT 3,
    publish_attempt INTEGER NOT NULL DEFAULT 0,
    published_at TEXT,
    last_publish_error TEXT,
    available_at TEXT NOT NULL,
    locked_by TEXT,
    lock_token TEXT,
    locked_until TEXT,
    last_error TEXT,
    payload_json TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS vulnerability_cases (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    project_id TEXT NOT NULL,
    title TEXT NOT NULL,
    summary TEXT NOT NULL,
    severity TEXT NOT NULL CHECK(severity IN ('informational','low','medium','high','critical')),
    status TEXT NOT NULL CHECK(status IN (
        'DRAFT','TRIAGE','VALIDATION_PENDING','VALIDATED',
        'REMEDIATION_PLANNED','REMEDIATION_IN_PROGRESS',
        'RETEST_PENDING','REMEDIATED','ACCEPTED_RISK',
        'FALSE_POSITIVE','INCONCLUSIVE','CLOSED'
    )),
    source TEXT NOT NULL DEFAULT 'MANUAL',
    external_ref TEXT,
    metadata_json TEXT NOT NULL DEFAULT '{}',
    created_by TEXT NOT NULL REFERENCES users(id),
    updated_by TEXT NOT NULL REFERENCES users(id),
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    version INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE IF NOT EXISTS case_findings (
    id TEXT PRIMARY KEY,
    case_id TEXT NOT NULL REFERENCES vulnerability_cases(id) ON DELETE CASCADE,
    tenant_id TEXT NOT NULL,
    project_id TEXT NOT NULL,
    validation_execution_id TEXT REFERENCES validation_executions(id),
    evidence_id TEXT REFERENCES validation_execution_evidence(id),
    title TEXT NOT NULL,
    description TEXT NOT NULL,
    affected_component TEXT,
    risk_level TEXT NOT NULL CHECK(risk_level IN ('informational','low','medium','high','critical')),
    status TEXT NOT NULL CHECK(status IN ('CANDIDATE','VALIDATED','FALSE_POSITIVE','REMEDIATED','INCONCLUSIVE')),
    metadata_json TEXT NOT NULL DEFAULT '{}',
    created_by TEXT NOT NULL REFERENCES users(id),
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    version INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE IF NOT EXISTS remediation_proposals (
    id TEXT PRIMARY KEY,
    case_id TEXT NOT NULL REFERENCES vulnerability_cases(id) ON DELETE CASCADE,
    tenant_id TEXT NOT NULL,
    project_id TEXT NOT NULL,
    source TEXT NOT NULL CHECK(source IN ('AI_GENERATED','KNOWLEDGE_BASE','VENDOR_ADVISORY','MANUAL')),
    title TEXT NOT NULL,
    description TEXT NOT NULL,
    risk_level TEXT NOT NULL CHECK(risk_level IN ('low','medium','high')),
    knowledge_refs_json TEXT NOT NULL DEFAULT '[]',
    model_invocation_id TEXT REFERENCES model_invocations(id),
    provenance_json TEXT NOT NULL DEFAULT '{}',
    status TEXT NOT NULL CHECK(status IN ('PROPOSED','APPROVED','REJECTED','CHANGES_REQUESTED')),
    proposed_by TEXT NOT NULL REFERENCES users(id),
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    version INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE IF NOT EXISTS remediation_decisions (
    id TEXT PRIMARY KEY,
    proposal_id TEXT NOT NULL REFERENCES remediation_proposals(id) ON DELETE CASCADE,
    case_id TEXT NOT NULL REFERENCES vulnerability_cases(id) ON DELETE CASCADE,
    tenant_id TEXT NOT NULL,
    project_id TEXT NOT NULL,
    decision TEXT NOT NULL CHECK(decision IN ('APPROVED','REJECTED','CHANGES_REQUESTED')),
    reason TEXT NOT NULL,
    automated INTEGER NOT NULL DEFAULT 0,
    decided_by TEXT NOT NULL REFERENCES users(id),
    decided_at TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    version INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE IF NOT EXISTS remediation_implementations (
    id TEXT PRIMARY KEY,
    decision_id TEXT NOT NULL REFERENCES remediation_decisions(id) ON DELETE CASCADE,
    proposal_id TEXT NOT NULL REFERENCES remediation_proposals(id) ON DELETE CASCADE,
    case_id TEXT NOT NULL REFERENCES vulnerability_cases(id) ON DELETE CASCADE,
    tenant_id TEXT NOT NULL,
    project_id TEXT NOT NULL,
    implementation_ref TEXT NOT NULL,
    description TEXT NOT NULL,
    implemented_by TEXT NOT NULL REFERENCES users(id),
    implemented_at TEXT NOT NULL,
    verification_notes TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    version INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE IF NOT EXISTS retest_requests (
    id TEXT PRIMARY KEY,
    case_id TEXT NOT NULL REFERENCES vulnerability_cases(id) ON DELETE CASCADE,
    finding_id TEXT NOT NULL REFERENCES case_findings(id) ON DELETE CASCADE,
    tenant_id TEXT NOT NULL,
    project_id TEXT NOT NULL,
    original_execution_id TEXT NOT NULL REFERENCES validation_executions(id),
    remediation_implementation_id TEXT NOT NULL REFERENCES remediation_implementations(id),
    retest_execution_id TEXT NOT NULL REFERENCES validation_executions(id),
    status TEXT NOT NULL CHECK(status IN ('REQUESTED','QUEUED','RUNNING','COMPLETED','CANCELLED','INCONCLUSIVE')),
    template_id TEXT NOT NULL,
    template_version TEXT NOT NULL,
    template_version_changed INTEGER NOT NULL DEFAULT 0,
    requested_by TEXT NOT NULL REFERENCES users(id),
    requested_at TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    version INTEGER NOT NULL DEFAULT 1,
    UNIQUE(tenant_id, case_id, finding_id, remediation_implementation_id, original_execution_id)
);

CREATE TABLE IF NOT EXISTS validation_comparisons (
    id TEXT PRIMARY KEY,
    retest_id TEXT NOT NULL REFERENCES retest_requests(id) ON DELETE CASCADE,
    case_id TEXT NOT NULL REFERENCES vulnerability_cases(id) ON DELETE CASCADE,
    finding_id TEXT NOT NULL REFERENCES case_findings(id) ON DELETE CASCADE,
    tenant_id TEXT NOT NULL,
    project_id TEXT NOT NULL,
    original_execution_id TEXT NOT NULL REFERENCES validation_executions(id),
    retest_execution_id TEXT NOT NULL REFERENCES validation_executions(id),
    result TEXT NOT NULL CHECK(result IN (
        'REMEDIATED','PARTIALLY_REMEDIATED','NOT_REMEDIATED','REGRESSION','INCONCLUSIVE'
    )),
    initial_status TEXT NOT NULL,
    retest_status TEXT NOT NULL,
    success_condition_diff_json TEXT NOT NULL DEFAULT '{}',
    key_response_diff_json TEXT NOT NULL DEFAULT '{}',
    component_version_diff_json TEXT NOT NULL DEFAULT '{}',
    evidence_sha256_json TEXT NOT NULL DEFAULT '{}',
    risk_level_change TEXT,
    residual_risk TEXT,
    recommendation TEXT,
    reviewed_by TEXT REFERENCES users(id),
    reviewed_at TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    version INTEGER NOT NULL DEFAULT 1,
    UNIQUE(tenant_id, retest_id)
);

CREATE TABLE IF NOT EXISTS case_dispositions (
    id TEXT PRIMARY KEY,
    case_id TEXT NOT NULL REFERENCES vulnerability_cases(id) ON DELETE CASCADE,
    tenant_id TEXT NOT NULL,
    project_id TEXT NOT NULL,
    disposition TEXT NOT NULL CHECK(disposition IN ('REMEDIATED','ACCEPTED_RISK','FALSE_POSITIVE','INCONCLUSIVE')),
    reason TEXT NOT NULL,
    residual_risk TEXT,
    human_confirmed INTEGER NOT NULL DEFAULT 1,
    decided_by TEXT NOT NULL REFERENCES users(id),
    decided_at TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    version INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE IF NOT EXISTS case_reports (
    id TEXT PRIMARY KEY,
    case_id TEXT NOT NULL REFERENCES vulnerability_cases(id) ON DELETE CASCADE,
    tenant_id TEXT NOT NULL,
    project_id TEXT NOT NULL,
    title TEXT NOT NULL,
    report_json TEXT NOT NULL,
    generated_by TEXT NOT NULL REFERENCES users(id),
    generated_at TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    version INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE IF NOT EXISTS sandbox_runs (
    id TEXT PRIMARY KEY,
    task_id TEXT REFERENCES tasks(id),
    mode TEXT NOT NULL,
    argv_json TEXT NOT NULL,
    status TEXT NOT NULL,
    exit_code INTEGER,
    stdout TEXT NOT NULL DEFAULT '',
    stderr TEXT NOT NULL DEFAULT '',
    started_at TEXT NOT NULL,
    finished_at TEXT,
    created_by TEXT NOT NULL REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS audit_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    actor_id TEXT NOT NULL,
    action TEXT NOT NULL,
    resource_type TEXT NOT NULL,
    resource_id TEXT NOT NULL,
    outcome TEXT NOT NULL,
    details_json TEXT NOT NULL,
    prev_hash TEXT NOT NULL,
    entry_hash TEXT NOT NULL UNIQUE
);

CREATE TABLE IF NOT EXISTS audit_head (
    id INTEGER PRIMARY KEY CHECK(id=1),
    entry_count INTEGER NOT NULL,
    last_hash TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_tasks_created_by ON tasks(created_by);
CREATE INDEX IF NOT EXISTS idx_task_events_task ON task_events(task_id);
CREATE INDEX IF NOT EXISTS idx_task_stages_task ON task_stages(task_id, sequence_no);
CREATE INDEX IF NOT EXISTS idx_task_stages_lease ON task_stages(status, lease_expires_at);
CREATE INDEX IF NOT EXISTS idx_task_executions_task ON task_executions(task_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_task_queue_ready ON task_queue_messages(status, available_at);
CREATE INDEX IF NOT EXISTS idx_task_dead_letters_task ON task_dead_letters(task_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_agents_name ON agents(name, version);
CREATE INDEX IF NOT EXISTS idx_workflows_name ON workflows(name, version);
CREATE INDEX IF NOT EXISTS idx_memory_task ON memory_messages(task_id);
CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_logs(timestamp);
CREATE INDEX IF NOT EXISTS idx_rag_classification ON rag_documents(classification);
CREATE INDEX IF NOT EXISTS idx_rag_chunks_document ON rag_chunks(document_id, chunk_index);
CREATE INDEX IF NOT EXISTS idx_evidence_task ON evidence_items(task_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_policy_decisions_actor_time
    ON policy_decisions(actor_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_policy_decisions_resource
    ON policy_decisions(resource_type, resource_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_validation_plans_task
    ON validation_plans(task_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_validation_executions_task
    ON validation_executions(task_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_validation_executions_plan
    ON validation_executions(plan_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_validation_execution_events_execution
    ON validation_execution_events(execution_id, id);
CREATE INDEX IF NOT EXISTS idx_validation_execution_evidence_execution
    ON validation_execution_evidence(execution_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_validation_queue_ready
    ON validation_queue_messages(status, available_at);
CREATE INDEX IF NOT EXISTS idx_cases_tenant_project_status
    ON vulnerability_cases(tenant_id, project_id, status, updated_at DESC);
CREATE INDEX IF NOT EXISTS idx_case_findings_case
    ON case_findings(case_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_case_findings_execution
    ON case_findings(validation_execution_id);
CREATE INDEX IF NOT EXISTS idx_remediation_proposals_case
    ON remediation_proposals(case_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_remediation_decisions_proposal
    ON remediation_decisions(proposal_id, decided_at DESC);
CREATE INDEX IF NOT EXISTS idx_remediation_implementations_case
    ON remediation_implementations(case_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_retest_requests_case
    ON retest_requests(case_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_validation_comparisons_case
    ON validation_comparisons(case_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_case_dispositions_case
    ON case_dispositions(case_id, decided_at DESC);
CREATE INDEX IF NOT EXISTS idx_case_reports_case
    ON case_reports(case_id, generated_at DESC);
CREATE TABLE IF NOT EXISTS evaluation_suites (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    project_id TEXT NOT NULL,
    name TEXT NOT NULL,
    description TEXT NOT NULL,
    semantic_version TEXT NOT NULL,
    status TEXT NOT NULL CHECK(status IN ('DRAFT','ACTIVE','ARCHIVED')),
    metadata_json TEXT NOT NULL DEFAULT '{}',
    created_by TEXT NOT NULL REFERENCES users(id),
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    version INTEGER NOT NULL DEFAULT 1,
    UNIQUE(tenant_id, project_id, name, semantic_version)
);

CREATE TABLE IF NOT EXISTS evaluation_datasets (
    id TEXT PRIMARY KEY,
    suite_id TEXT NOT NULL REFERENCES evaluation_suites(id) ON DELETE CASCADE,
    tenant_id TEXT NOT NULL,
    project_id TEXT NOT NULL,
    name TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    semantic_version TEXT NOT NULL,
    ground_truth_version TEXT NOT NULL,
    published INTEGER NOT NULL DEFAULT 0,
    immutable INTEGER NOT NULL DEFAULT 0,
    dataset_hash TEXT NOT NULL,
    metadata_json TEXT NOT NULL DEFAULT '{}',
    created_by TEXT NOT NULL REFERENCES users(id),
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    version INTEGER NOT NULL DEFAULT 1,
    UNIQUE(tenant_id, project_id, suite_id, name, semantic_version)
);

CREATE TABLE IF NOT EXISTS evaluation_cases (
    id TEXT PRIMARY KEY,
    dataset_id TEXT NOT NULL REFERENCES evaluation_datasets(id) ON DELETE CASCADE,
    tenant_id TEXT NOT NULL,
    project_id TEXT NOT NULL,
    external_id TEXT NOT NULL,
    input_json TEXT NOT NULL DEFAULT '{}',
    expected_output TEXT,
    accepted_conclusions_json TEXT NOT NULL DEFAULT '[]',
    forbidden_conclusions_json TEXT NOT NULL DEFAULT '[]',
    expected_citations_json TEXT NOT NULL DEFAULT '[]',
    expected_template TEXT,
    expected_policy_result TEXT CHECK(expected_policy_result IN ('allow','deny','requires_approval')),
    required_evidence_fields_json TEXT NOT NULL DEFAULT '[]',
    allowed_tools_json TEXT NOT NULL DEFAULT '[]',
    forbidden_tools_json TEXT NOT NULL DEFAULT '[]',
    maximum_token_budget INTEGER NOT NULL,
    maximum_cost REAL NOT NULL,
    maximum_latency_ms INTEGER NOT NULL,
    scoring_method_json TEXT NOT NULL DEFAULT '[]',
    ground_truth_version TEXT NOT NULL,
    ground_truth_hash TEXT NOT NULL,
    metadata_json TEXT NOT NULL DEFAULT '{}',
    created_by TEXT NOT NULL REFERENCES users(id),
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    version INTEGER NOT NULL DEFAULT 1,
    UNIQUE(tenant_id, project_id, dataset_id, external_id)
);

CREATE TABLE IF NOT EXISTS metric_definitions (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    project_id TEXT NOT NULL,
    name TEXT NOT NULL,
    category TEXT NOT NULL CHECK(category IN ('quality','security','cost','latency','stability')),
    direction TEXT NOT NULL CHECK(direction IN ('higher_is_better','lower_is_better')),
    definition_json TEXT NOT NULL DEFAULT '{}',
    semantic_version TEXT NOT NULL,
    created_by TEXT NOT NULL REFERENCES users(id),
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    version INTEGER NOT NULL DEFAULT 1,
    UNIQUE(tenant_id, project_id, name, semantic_version)
);

CREATE TABLE IF NOT EXISTS evaluation_runs (
    id TEXT PRIMARY KEY,
    suite_id TEXT NOT NULL REFERENCES evaluation_suites(id) ON DELETE CASCADE,
    dataset_id TEXT NOT NULL REFERENCES evaluation_datasets(id) ON DELETE CASCADE,
    tenant_id TEXT NOT NULL,
    project_id TEXT NOT NULL,
    evaluation_type TEXT NOT NULL CHECK(evaluation_type IN (
        'deterministic_offline','real_model','controlled_e2e','human_blind_review'
    )),
    status TEXT NOT NULL CHECK(status IN (
        'DRAFT','EVALUATING','PASSED','FAILED','REVIEW_PENDING','APPROVED',
        'REJECTED','PROMOTED','ROLLED_BACK','CANCELLED'
    )),
    gate_status TEXT NOT NULL CHECK(gate_status IN ('PENDING','PASSED','FAILED','NOT_EVALUATED')),
    baseline_variant_id TEXT,
    candidate_variant_id TEXT,
    config_hash TEXT NOT NULL,
    gate_config_json TEXT NOT NULL DEFAULT '{}',
    metadata_json TEXT NOT NULL DEFAULT '{}',
    created_by TEXT NOT NULL REFERENCES users(id),
    started_at TEXT,
    finished_at TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    version INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE IF NOT EXISTS evaluation_run_variants (
    id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL REFERENCES evaluation_runs(id) ON DELETE CASCADE,
    tenant_id TEXT NOT NULL,
    project_id TEXT NOT NULL,
    name TEXT NOT NULL,
    role TEXT NOT NULL CHECK(role IN ('baseline','candidate')),
    configuration_snapshot_id TEXT NOT NULL,
    configuration_hash TEXT NOT NULL,
    status TEXT NOT NULL CHECK(status IN ('PENDING','RUNNING','SUCCEEDED','FAILED','CANCELLED')),
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    version INTEGER NOT NULL DEFAULT 1,
    UNIQUE(run_id, role, name)
);

CREATE TABLE IF NOT EXISTS configuration_snapshots (
    id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL REFERENCES evaluation_runs(id) ON DELETE CASCADE,
    variant_id TEXT NOT NULL,
    tenant_id TEXT NOT NULL,
    project_id TEXT NOT NULL,
    snapshot_json TEXT NOT NULL,
    snapshot_hash TEXT NOT NULL,
    created_at TEXT NOT NULL,
    UNIQUE(run_id, variant_id)
);

CREATE TABLE IF NOT EXISTS evaluation_results (
    id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL REFERENCES evaluation_runs(id) ON DELETE CASCADE,
    variant_id TEXT NOT NULL REFERENCES evaluation_run_variants(id) ON DELETE CASCADE,
    case_id TEXT NOT NULL REFERENCES evaluation_cases(id) ON DELETE CASCADE,
    tenant_id TEXT NOT NULL,
    project_id TEXT NOT NULL,
    status TEXT NOT NULL CHECK(status IN ('PASSED','FAILED','ERROR','GROUND_TRUTH_MISSING','INCONCLUSIVE')),
    output_json TEXT NOT NULL DEFAULT '{}',
    scores_json TEXT NOT NULL DEFAULT '{}',
    failure_reasons_json TEXT NOT NULL DEFAULT '[]',
    model_invocation_id TEXT REFERENCES model_invocations(id),
    judge_json TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    version INTEGER NOT NULL DEFAULT 1,
    UNIQUE(run_id, variant_id, case_id)
);

CREATE TABLE IF NOT EXISTS metric_results (
    id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL REFERENCES evaluation_runs(id) ON DELETE CASCADE,
    variant_id TEXT NOT NULL REFERENCES evaluation_run_variants(id) ON DELETE CASCADE,
    metric_definition_id TEXT NOT NULL REFERENCES metric_definitions(id),
    tenant_id TEXT NOT NULL,
    project_id TEXT NOT NULL,
    metric_name TEXT NOT NULL,
    category TEXT NOT NULL,
    value REAL NOT NULL,
    unit TEXT NOT NULL,
    threshold REAL,
    passed INTEGER,
    details_json TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    version INTEGER NOT NULL DEFAULT 1,
    UNIQUE(run_id, variant_id, metric_name)
);

CREATE TABLE IF NOT EXISTS regression_comparisons (
    id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL REFERENCES evaluation_runs(id) ON DELETE CASCADE,
    suite_id TEXT NOT NULL REFERENCES evaluation_suites(id) ON DELETE CASCADE,
    dataset_id TEXT NOT NULL REFERENCES evaluation_datasets(id) ON DELETE CASCADE,
    tenant_id TEXT NOT NULL,
    project_id TEXT NOT NULL,
    baseline_variant_id TEXT NOT NULL REFERENCES evaluation_run_variants(id),
    candidate_variant_id TEXT NOT NULL REFERENCES evaluation_run_variants(id),
    improved_metrics_json TEXT NOT NULL DEFAULT '[]',
    regressed_metrics_json TEXT NOT NULL DEFAULT '[]',
    new_failures_json TEXT NOT NULL DEFAULT '[]',
    resolved_failures_json TEXT NOT NULL DEFAULT '[]',
    cost_change REAL NOT NULL DEFAULT 0,
    latency_change REAL NOT NULL DEFAULT 0,
    security_gate_status TEXT NOT NULL CHECK(security_gate_status IN ('PASSED','FAILED')),
    gate_status TEXT NOT NULL CHECK(gate_status IN ('PASSED','FAILED')),
    failed_gates_json TEXT NOT NULL DEFAULT '[]',
    details_json TEXT NOT NULL DEFAULT '{}',
    created_by TEXT NOT NULL REFERENCES users(id),
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    version INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE IF NOT EXISTS evaluation_reviews (
    id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL REFERENCES evaluation_runs(id) ON DELETE CASCADE,
    tenant_id TEXT NOT NULL,
    project_id TEXT NOT NULL,
    decision TEXT NOT NULL CHECK(decision IN ('ACCEPTED','REJECTED','CHANGES_REQUESTED')),
    blind INTEGER NOT NULL DEFAULT 1,
    comments TEXT NOT NULL,
    annotations_json TEXT NOT NULL DEFAULT '{}',
    reviewed_by TEXT NOT NULL REFERENCES users(id),
    reviewed_at TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    version INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE IF NOT EXISTS promotion_decisions (
    id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL REFERENCES evaluation_runs(id) ON DELETE CASCADE,
    comparison_id TEXT REFERENCES regression_comparisons(id),
    tenant_id TEXT NOT NULL,
    project_id TEXT NOT NULL,
    decision TEXT NOT NULL CHECK(decision IN ('APPROVED','REJECTED','PROMOTED','ROLLED_BACK')),
    reason TEXT NOT NULL,
    target_environment TEXT NOT NULL,
    decided_by TEXT NOT NULL REFERENCES users(id),
    decided_at TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    version INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE IF NOT EXISTS operational_capacity_quotas (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    quota_type TEXT NOT NULL CHECK(quota_type IN (
        'tenant_concurrency','project_concurrency','global_concurrency',
        'model_concurrency','sandbox_capacity','queue_backlog','api_rate_limit'
    )),
    subject_id TEXT NOT NULL,
    max_concurrency INTEGER NOT NULL CHECK(max_concurrency > 0),
    weight INTEGER NOT NULL DEFAULT 1 CHECK(weight > 0),
    priority INTEGER NOT NULL DEFAULT 100 CHECK(priority >= 0),
    metadata_json TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    version INTEGER NOT NULL DEFAULT 1,
    UNIQUE(tenant_id, quota_type, subject_id)
);

CREATE TABLE IF NOT EXISTS operational_service_instances (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    kind TEXT NOT NULL CHECK(kind IN ('control_plane','validation_worker','api_gateway','scheduler')),
    status TEXT NOT NULL CHECK(status IN ('starting','ready','draining','terminated')),
    metadata_json TEXT NOT NULL DEFAULT '{}',
    last_heartbeat_at TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    version INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE IF NOT EXISTS operational_worker_heartbeats (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    worker_id TEXT NOT NULL UNIQUE,
    active_executions INTEGER NOT NULL DEFAULT 0 CHECK(active_executions >= 0),
    sandbox_capacity INTEGER NOT NULL DEFAULT 0 CHECK(sandbox_capacity >= 0),
    metadata_json TEXT NOT NULL DEFAULT '{}',
    last_heartbeat_at TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    version INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE IF NOT EXISTS operational_evidence_consistency_reports (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    status TEXT NOT NULL CHECK(status IN ('healthy','inconsistent')),
    summary_json TEXT NOT NULL DEFAULT '{}',
    findings_json TEXT NOT NULL DEFAULT '[]',
    repair_action TEXT NOT NULL DEFAULT 'none',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    version INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE IF NOT EXISTS operational_backup_restore_drills (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    drill_type TEXT NOT NULL CHECK(drill_type IN ('backup','restore','full_dr')),
    status TEXT NOT NULL CHECK(status IN ('planned','running','succeeded','failed','aborted')),
    rpo_seconds INTEGER CHECK(rpo_seconds IS NULL OR rpo_seconds >= 0),
    rto_seconds INTEGER CHECK(rto_seconds IS NULL OR rto_seconds >= 0),
    manifest_json TEXT NOT NULL DEFAULT '{}',
    validation_json TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    version INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE IF NOT EXISTS operational_failure_injection_events (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    failure_type TEXT NOT NULL,
    target TEXT NOT NULL,
    status TEXT NOT NULL CHECK(status IN ('planned','running','succeeded','failed','blocked')),
    isolated_environment INTEGER NOT NULL DEFAULT 1 CHECK(isolated_environment IN (0,1)),
    metadata_json TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    version INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE IF NOT EXISTS release_artifacts (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    project_id TEXT NOT NULL,
    name TEXT NOT NULL,
    artifact_type TEXT NOT NULL CHECK(artifact_type IN ('container','helm_chart','python_package','node_package','release_package')),
    digest TEXT NOT NULL,
    repository TEXT NOT NULL DEFAULT '',
    source_commit TEXT NOT NULL,
    metadata_json TEXT NOT NULL DEFAULT '{}',
    created_by TEXT NOT NULL REFERENCES users(id),
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    version INTEGER NOT NULL DEFAULT 1,
    UNIQUE(tenant_id, digest)
);

CREATE TABLE IF NOT EXISTS release_sbom_documents (
    id TEXT PRIMARY KEY,
    artifact_id TEXT NOT NULL REFERENCES release_artifacts(id) ON DELETE RESTRICT,
    format TEXT NOT NULL,
    generator TEXT NOT NULL,
    generated_at TEXT NOT NULL,
    artifact_digest TEXT NOT NULL,
    document_digest TEXT NOT NULL,
    component_count INTEGER NOT NULL DEFAULT 0,
    license_summary_json TEXT NOT NULL DEFAULT '{}',
    vulnerability_summary_json TEXT NOT NULL DEFAULT '{}',
    document_ref TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    version INTEGER NOT NULL DEFAULT 1,
    UNIQUE(artifact_id, document_digest)
);

CREATE TABLE IF NOT EXISTS release_provenance_statements (
    id TEXT PRIMARY KEY,
    artifact_id TEXT NOT NULL REFERENCES release_artifacts(id) ON DELETE RESTRICT,
    subject_digest TEXT NOT NULL,
    source_repository TEXT NOT NULL,
    source_commit TEXT NOT NULL,
    builder_workflow TEXT NOT NULL,
    statement_digest TEXT NOT NULL,
    predicate_type TEXT NOT NULL,
    verified INTEGER NOT NULL DEFAULT 0 CHECK(verified IN (0,1)),
    metadata_json TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    version INTEGER NOT NULL DEFAULT 1,
    UNIQUE(artifact_id, statement_digest)
);

CREATE TABLE IF NOT EXISTS release_signature_records (
    id TEXT PRIMARY KEY,
    artifact_id TEXT NOT NULL REFERENCES release_artifacts(id) ON DELETE RESTRICT,
    signature_digest TEXT NOT NULL,
    signature_identity TEXT NOT NULL,
    certificate_issuer TEXT NOT NULL,
    verified INTEGER NOT NULL DEFAULT 0 CHECK(verified IN (0,1)),
    verification_error TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    version INTEGER NOT NULL DEFAULT 1,
    UNIQUE(artifact_id, signature_digest)
);

CREATE TABLE IF NOT EXISTS release_security_scan_results (
    id TEXT PRIMARY KEY,
    artifact_id TEXT NOT NULL REFERENCES release_artifacts(id) ON DELETE RESTRICT,
    scanner TEXT NOT NULL,
    severity_summary_json TEXT NOT NULL DEFAULT '{}',
    critical_count INTEGER NOT NULL DEFAULT 0,
    high_count INTEGER NOT NULL DEFAULT 0,
    unresolved_critical INTEGER NOT NULL DEFAULT 0 CHECK(unresolved_critical IN (0,1)),
    scan_digest TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    version INTEGER NOT NULL DEFAULT 1,
    UNIQUE(artifact_id, scan_digest)
);

CREATE TABLE IF NOT EXISTS release_license_scan_results (
    id TEXT PRIMARY KEY,
    artifact_id TEXT NOT NULL REFERENCES release_artifacts(id) ON DELETE RESTRICT,
    scanner TEXT NOT NULL,
    license_summary_json TEXT NOT NULL DEFAULT '{}',
    prohibited_licenses_json TEXT NOT NULL DEFAULT '[]',
    passed INTEGER NOT NULL DEFAULT 0 CHECK(passed IN (0,1)),
    scan_digest TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    version INTEGER NOT NULL DEFAULT 1,
    UNIQUE(artifact_id, scan_digest)
);

CREATE TABLE IF NOT EXISTS release_candidates (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    project_id TEXT NOT NULL,
    name TEXT NOT NULL,
    artifact_id TEXT NOT NULL REFERENCES release_artifacts(id) ON DELETE RESTRICT,
    source_commit TEXT NOT NULL,
    image_digest TEXT NOT NULL,
    sbom_digest TEXT NOT NULL,
    provenance_digest TEXT NOT NULL,
    signature_digest TEXT NOT NULL,
    configuration_hash TEXT NOT NULL,
    migration_set_json TEXT NOT NULL DEFAULT '[]',
    helm_chart_digest TEXT NOT NULL,
    status TEXT NOT NULL CHECK(status IN ('created','frozen','evaluated','approved','promoting','deployed','blocked','rolled_back')),
    freeze_hash TEXT NOT NULL,
    metadata_json TEXT NOT NULL DEFAULT '{}',
    created_by TEXT NOT NULL REFERENCES users(id),
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    version INTEGER NOT NULL DEFAULT 1,
    UNIQUE(tenant_id, name),
    UNIQUE(tenant_id, freeze_hash)
);

CREATE TABLE IF NOT EXISTS release_gate_results (
    id TEXT PRIMARY KEY,
    candidate_id TEXT NOT NULL REFERENCES release_candidates(id) ON DELETE RESTRICT,
    gate_id TEXT NOT NULL,
    environment TEXT NOT NULL CHECK(environment IN ('development','integration','staging','production')),
    status TEXT NOT NULL CHECK(status IN ('passed','failed','warning')),
    reason TEXT NOT NULL,
    evidence_json TEXT NOT NULL DEFAULT '{}',
    evaluated_by TEXT NOT NULL REFERENCES users(id),
    policy_decision_id TEXT REFERENCES policy_decisions(id),
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    version INTEGER NOT NULL DEFAULT 1,
    UNIQUE(candidate_id, gate_id, environment)
);

CREATE TABLE IF NOT EXISTS release_approvals (
    id TEXT PRIMARY KEY,
    candidate_id TEXT NOT NULL REFERENCES release_candidates(id) ON DELETE RESTRICT,
    environment TEXT NOT NULL CHECK(environment IN ('development','integration','staging','production')),
    decision TEXT NOT NULL CHECK(decision IN ('approved','rejected')),
    reason TEXT NOT NULL DEFAULT '',
    approved_by TEXT NOT NULL REFERENCES users(id),
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    version INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE IF NOT EXISTS release_exceptions (
    id TEXT PRIMARY KEY,
    candidate_id TEXT NOT NULL REFERENCES release_candidates(id) ON DELETE RESTRICT,
    gate_id TEXT NOT NULL,
    reason TEXT NOT NULL,
    risk TEXT NOT NULL CHECK(risk IN ('low','medium','high','critical')),
    scope TEXT NOT NULL,
    requested_by TEXT NOT NULL REFERENCES users(id),
    approved_by TEXT REFERENCES users(id),
    expires_at TEXT NOT NULL,
    compensating_controls_json TEXT NOT NULL DEFAULT '[]',
    status TEXT NOT NULL CHECK(status IN ('requested','approved','expired','rejected')),
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    version INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE IF NOT EXISTS release_environment_promotions (
    id TEXT PRIMARY KEY,
    candidate_id TEXT NOT NULL REFERENCES release_candidates(id) ON DELETE RESTRICT,
    environment TEXT NOT NULL CHECK(environment IN ('development','integration','staging','production')),
    status TEXT NOT NULL CHECK(status IN ('requested','deployed','blocked','failed')),
    promoted_by TEXT NOT NULL REFERENCES users(id),
    policy_decision_id TEXT REFERENCES policy_decisions(id),
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    version INTEGER NOT NULL DEFAULT 1,
    UNIQUE(candidate_id, environment)
);

CREATE TABLE IF NOT EXISTS release_deployment_records (
    id TEXT PRIMARY KEY,
    promotion_id TEXT NOT NULL REFERENCES release_environment_promotions(id) ON DELETE RESTRICT,
    candidate_id TEXT NOT NULL REFERENCES release_candidates(id) ON DELETE RESTRICT,
    environment TEXT NOT NULL CHECK(environment IN ('development','integration','staging','production')),
    image_digest TEXT NOT NULL,
    canary_percentage INTEGER NOT NULL DEFAULT 100 CHECK(canary_percentage BETWEEN 0 AND 100),
    status TEXT NOT NULL CHECK(status IN ('deployed','failed','rollback_recommended','rolled_back')),
    health_json TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    version INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE IF NOT EXISTS release_rollback_records (
    id TEXT PRIMARY KEY,
    deployment_id TEXT NOT NULL REFERENCES release_deployment_records(id) ON DELETE RESTRICT,
    candidate_id TEXT NOT NULL REFERENCES release_candidates(id) ON DELETE RESTRICT,
    environment TEXT NOT NULL CHECK(environment IN ('development','integration','staging','production')),
    reason TEXT NOT NULL,
    requested_by TEXT NOT NULL REFERENCES users(id),
    approved_by TEXT REFERENCES users(id),
    status TEXT NOT NULL CHECK(status IN ('requested','approved','completed','rejected')),
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    version INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE IF NOT EXISTS release_configuration_snapshots (
    id TEXT PRIMARY KEY,
    candidate_id TEXT NOT NULL REFERENCES release_candidates(id) ON DELETE RESTRICT,
    environment TEXT NOT NULL CHECK(environment IN ('development','integration','staging','production')),
    approved_snapshot_json TEXT NOT NULL DEFAULT '{}',
    snapshot_hash TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    version INTEGER NOT NULL DEFAULT 1,
    UNIQUE(candidate_id, environment)
);

CREATE TABLE IF NOT EXISTS release_drift_detection_results (
    id TEXT PRIMARY KEY,
    deployment_id TEXT NOT NULL REFERENCES release_deployment_records(id) ON DELETE RESTRICT,
    status TEXT NOT NULL CHECK(status IN ('healthy','drift_detected','unknown')),
    drift_types_json TEXT NOT NULL DEFAULT '[]',
    expected_json TEXT NOT NULL DEFAULT '{}',
    actual_json TEXT NOT NULL DEFAULT '{}',
    reviewed_by TEXT REFERENCES users(id),
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    version INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE IF NOT EXISTS release_compliance_evidence_packages (
    id TEXT PRIMARY KEY,
    candidate_id TEXT NOT NULL REFERENCES release_candidates(id) ON DELETE RESTRICT,
    package_digest TEXT NOT NULL,
    contents_json TEXT NOT NULL DEFAULT '{}',
    generated_by TEXT NOT NULL REFERENCES users(id),
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    version INTEGER NOT NULL DEFAULT 1,
    UNIQUE(candidate_id, package_digest)
);

CREATE INDEX IF NOT EXISTS idx_evaluation_suites_tenant_project
    ON evaluation_suites(tenant_id, project_id, updated_at DESC);
CREATE INDEX IF NOT EXISTS idx_evaluation_datasets_suite
    ON evaluation_datasets(suite_id, semantic_version);
CREATE INDEX IF NOT EXISTS idx_evaluation_cases_dataset
    ON evaluation_cases(dataset_id, external_id);
CREATE INDEX IF NOT EXISTS idx_evaluation_runs_tenant_project
    ON evaluation_runs(tenant_id, project_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_evaluation_results_run
    ON evaluation_results(run_id, variant_id, status);
CREATE INDEX IF NOT EXISTS idx_metric_results_run
    ON metric_results(run_id, variant_id, metric_name);
CREATE INDEX IF NOT EXISTS idx_regression_comparisons_run
    ON regression_comparisons(run_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_evaluation_reviews_run
    ON evaluation_reviews(run_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_promotion_decisions_run
    ON promotion_decisions(run_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_operational_quota_subject
    ON operational_capacity_quotas(tenant_id, quota_type, subject_id);
CREATE INDEX IF NOT EXISTS idx_operational_instances_kind
    ON operational_service_instances(kind, status, updated_at DESC);
CREATE INDEX IF NOT EXISTS idx_operational_workers_heartbeat
    ON operational_worker_heartbeats(tenant_id, last_heartbeat_at DESC);
CREATE INDEX IF NOT EXISTS idx_operational_evidence_reports
    ON operational_evidence_consistency_reports(tenant_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_operational_drills
    ON operational_backup_restore_drills(tenant_id, status, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_operational_failure_events
    ON operational_failure_injection_events(tenant_id, status, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_release_artifacts_tenant_project
    ON release_artifacts(tenant_id, project_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_release_candidates_tenant_project
    ON release_candidates(tenant_id, project_id, updated_at DESC);
CREATE INDEX IF NOT EXISTS idx_release_candidates_artifact
    ON release_candidates(artifact_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_release_gate_results_candidate
    ON release_gate_results(candidate_id, environment, gate_id);
CREATE INDEX IF NOT EXISTS idx_release_exceptions_candidate
    ON release_exceptions(candidate_id, gate_id, status);
CREATE INDEX IF NOT EXISTS idx_release_promotions_candidate
    ON release_environment_promotions(candidate_id, environment);
CREATE INDEX IF NOT EXISTS idx_release_deployments_candidate
    ON release_deployment_records(candidate_id, environment, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_release_drift_deployment
    ON release_drift_detection_results(deployment_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_release_compliance_candidate
    ON release_compliance_evidence_packages(candidate_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_model_invocations_actor_time
    ON model_invocations(actor_id, created_at);
CREATE INDEX IF NOT EXISTS idx_model_invocations_provider_time
    ON model_invocations(provider_id, created_at);
"""


class Database:
    def __init__(self, path: str | Path):
        self.path = str(path)
        self._write_lock = threading.RLock()

    def connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=10, isolation_level=None)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute("PRAGMA busy_timeout=10000")
        return connection

    def initialize(self) -> None:
        with self._write_lock, closing(self.connect()) as connection:
            connection.execute("PRAGMA journal_mode=WAL")
            connection.executescript(SCHEMA)
            self._migrate(connection)

    @staticmethod
    def _columns(connection: sqlite3.Connection, table: str) -> set[str]:
        return {row["name"] for row in connection.execute(f"PRAGMA table_info({table})").fetchall()}

    @staticmethod
    def _scope_digest(row: sqlite3.Row) -> str:
        resolved = json.loads(row["resolved_ips_json"] or "[]")
        canonical = json.dumps(
            {
                "target_pattern": row["target_pattern"].strip().rstrip(".").lower(),
                "protocols": sorted(set(json.loads(row["protocols_json"]))),
                "ports": sorted(set(json.loads(row["ports_json"]))),
                "expires_at": row["expires_at"],
                "resolved_ips": sorted(set(resolved)),
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        return hashlib.sha256(canonical.encode()).hexdigest()

    def _migrate(self, connection: sqlite3.Connection) -> None:
        """Small in-place migrations keep persistent Docker volumes upgradeable."""
        connection.execute("BEGIN IMMEDIATE")
        try:
            scope_columns = self._columns(connection, "scopes")
            scope_hash_added = "scope_hash" not in scope_columns
            scope_additions = {
                "approved_by": "TEXT REFERENCES users(id)",
                "approved_at": "TEXT",
                "approval_reason": "TEXT",
                "resolved_ips_json": "TEXT NOT NULL DEFAULT '[]'",
                "scope_hash": "TEXT NOT NULL DEFAULT ''",
            }
            added_resolved_snapshot = False
            for name, definition in scope_additions.items():
                if name not in scope_columns:
                    connection.execute(f"ALTER TABLE scopes ADD COLUMN {name} {definition}")
                    added_resolved_snapshot |= name == "resolved_ips_json"

            task_columns = self._columns(connection, "tasks")
            task_hash_added = "scope_hash" not in task_columns
            task_additions = {
                "approved_by": "TEXT REFERENCES users(id)",
                "approved_at": "TEXT",
                "approval_reason": "TEXT",
                "scope_hash": "TEXT NOT NULL DEFAULT ''",
                "workflow_name": "TEXT NOT NULL DEFAULT 'p3.synthetic.defensive'",
                "workflow_version": "TEXT NOT NULL DEFAULT '1.0'",
                "current_stage": "TEXT",
                "pause_requested": "INTEGER NOT NULL DEFAULT 0",
                "cancel_requested": "INTEGER NOT NULL DEFAULT 0",
                "retry_count": "INTEGER NOT NULL DEFAULT 0",
                "max_retries": "INTEGER NOT NULL DEFAULT 2",
                "lease_owner": "TEXT",
                "lease_token": "TEXT",
                "lease_expires_at": "TEXT",
                "fencing_token": "INTEGER NOT NULL DEFAULT 0",
                "deadline_at": "TEXT",
                "started_at": "TEXT",
                "finished_at": "TEXT",
            }
            for name, definition in task_additions.items():
                if name not in task_columns:
                    connection.execute(f"ALTER TABLE tasks ADD COLUMN {name} {definition}")
            connection.execute(
                "CREATE INDEX IF NOT EXISTS idx_tasks_lease ON tasks(status, lease_expires_at)"
            )

            skill_columns = self._columns(connection, "skills")
            skill_additions = {
                "version": "TEXT NOT NULL DEFAULT '1.0'",
                "output_schema_json": 'TEXT NOT NULL DEFAULT \'{"type":"object"}\'',
                "permissions_json": "TEXT NOT NULL DEFAULT '[]'",
                "resource_limits_json": "TEXT NOT NULL DEFAULT '{}'",
                "timeout_seconds": "REAL NOT NULL DEFAULT 30",
                "execution_type": "TEXT NOT NULL DEFAULT 'internal'",
                "tool_dependencies_json": "TEXT NOT NULL DEFAULT '[]'",
                "approval_required": "INTEGER NOT NULL DEFAULT 0",
                "invocation_count": "INTEGER NOT NULL DEFAULT 0",
                "success_count": "INTEGER NOT NULL DEFAULT 0",
                "failure_count": "INTEGER NOT NULL DEFAULT 0",
                "updated_at": "TEXT NOT NULL DEFAULT ''",
            }
            for name, definition in skill_additions.items():
                if name not in skill_columns:
                    connection.execute(f"ALTER TABLE skills ADD COLUMN {name} {definition}")

            profile_columns = self._columns(connection, "target_profiles")
            if "proxy_scope_id" not in profile_columns:
                connection.execute(
                    "ALTER TABLE target_profiles ADD COLUMN proxy_scope_id TEXT REFERENCES scopes(id)"
                )

            provider_columns = self._columns(connection, "providers")
            provider_additions = {
                "token_quota_per_minute": "INTEGER NOT NULL DEFAULT 100000",
                "input_cost_per_1k": "REAL NOT NULL DEFAULT 0",
                "output_cost_per_1k": "REAL NOT NULL DEFAULT 0",
                "capabilities_json": "TEXT NOT NULL DEFAULT '[]'",
            }
            for name, definition in provider_additions.items():
                if name not in provider_columns:
                    connection.execute(f"ALTER TABLE providers ADD COLUMN {name} {definition}")

            memory_columns = self._columns(connection, "memory_messages")
            memory_additions = {
                "content_hash": "TEXT NOT NULL DEFAULT ''",
                "sequence_no": "INTEGER NOT NULL DEFAULT 0",
            }
            for name, definition in memory_additions.items():
                if name not in memory_columns:
                    connection.execute(
                        f"ALTER TABLE memory_messages ADD COLUMN {name} {definition}"
                    )
            memory_rows = connection.execute(
                "SELECT id, task_id, content FROM memory_messages ORDER BY task_id, created_at, id"
            ).fetchall()
            sequence_by_task: dict[str, int] = {}
            for row in memory_rows:
                task_id = str(row["task_id"])
                sequence_by_task[task_id] = sequence_by_task.get(task_id, 0) + 1
                content_hash = hashlib.sha256(str(row["content"]).encode()).hexdigest()
                connection.execute(
                    "UPDATE memory_messages SET content_hash=?, sequence_no=? WHERE id=?",
                    (content_hash, sequence_by_task[task_id], row["id"]),
                )

            checkpoint_columns = self._columns(connection, "checkpoints")
            checkpoint_additions = {
                "summary_hash": "TEXT NOT NULL DEFAULT ''",
                "state_hash": "TEXT NOT NULL DEFAULT ''",
                "evidence_count": "INTEGER NOT NULL DEFAULT 0",
                "restore_policy_hash": "TEXT NOT NULL DEFAULT ''",
            }
            for name, definition in checkpoint_additions.items():
                if name not in checkpoint_columns:
                    connection.execute(f"ALTER TABLE checkpoints ADD COLUMN {name} {definition}")
            checkpoint_rows = connection.execute(
                "SELECT id, summary, state_json FROM checkpoints"
            ).fetchall()
            for row in checkpoint_rows:
                summary_hash = hashlib.sha256(str(row["summary"]).encode()).hexdigest()
                state_hash = hashlib.sha256(str(row["state_json"]).encode()).hexdigest()
                restore_policy_hash = hashlib.sha256(
                    b"restored-context-never-restores-authority:v1"
                ).hexdigest()
                connection.execute(
                    """UPDATE checkpoints
                       SET summary_hash=?, state_hash=?, restore_policy_hash=?
                       WHERE id=?""",
                    (summary_hash, state_hash, restore_policy_hash, row["id"]),
                )

            rag_columns = self._columns(connection, "rag_documents")
            rag_additions = {
                "tenant_key": "TEXT NOT NULL DEFAULT 'compat'",
                "project_key": "TEXT",
                "metadata_json": "TEXT NOT NULL DEFAULT '{}'",
            }
            for name, definition in rag_additions.items():
                if name not in rag_columns:
                    connection.execute(f"ALTER TABLE rag_documents ADD COLUMN {name} {definition}")
            rag_rows = connection.execute(
                "SELECT id, content, created_at FROM rag_documents ORDER BY created_at, id"
            ).fetchall()
            for row in rag_rows:
                existing_chunk = connection.execute(
                    "SELECT id FROM rag_chunks WHERE document_id=? LIMIT 1", (row["id"],)
                ).fetchone()
                if existing_chunk is not None:
                    continue
                content = str(row["content"])
                connection.execute(
                    """INSERT INTO rag_chunks(
                       id, document_id, chunk_index, content, token_estimate, chunk_hash, created_at
                       ) VALUES(?,?,?,?,?,?,?)""",
                    (
                        hashlib.sha256(f"{row['id']}:0".encode()).hexdigest(),
                        row["id"],
                        0,
                        content,
                        max(1, len(content) // 4),
                        hashlib.sha256(content.encode()).hexdigest(),
                        row["created_at"],
                    ),
                )
            connection.execute(
                "CREATE INDEX IF NOT EXISTS idx_memory_task_sequence ON memory_messages(task_id, sequence_no)"
            )
            connection.execute(
                "CREATE INDEX IF NOT EXISTS idx_rag_chunks_document ON rag_chunks(document_id, chunk_index)"
            )
            connection.execute(
                "CREATE INDEX IF NOT EXISTS idx_evidence_task ON evidence_items(task_id, created_at DESC)"
            )
            connection.execute(
                """CREATE INDEX IF NOT EXISTS idx_policy_decisions_actor_time
                   ON policy_decisions(actor_id, created_at DESC)"""
            )
            connection.execute(
                """CREATE INDEX IF NOT EXISTS idx_policy_decisions_resource
                   ON policy_decisions(resource_type, resource_id, created_at DESC)"""
            )
            connection.execute(
                """CREATE INDEX IF NOT EXISTS idx_validation_plans_task
                   ON validation_plans(task_id, created_at DESC)"""
            )
            connection.execute(
                """CREATE TABLE IF NOT EXISTS validation_executions (
                    id TEXT PRIMARY KEY,
                    plan_id TEXT NOT NULL REFERENCES validation_plans(id) ON DELETE CASCADE,
                    task_id TEXT NOT NULL REFERENCES tasks(id) ON DELETE CASCADE,
                    tenant_id TEXT NOT NULL,
                    template_id TEXT NOT NULL,
                    template_version TEXT NOT NULL,
                    status TEXT NOT NULL CHECK(status IN (
                        'QUEUED','PROVISIONING','RUNNING','COLLECTING_EVIDENCE','VERIFYING',
                        'SUCCEEDED','FAILED','CANCELLED','EXPIRED','POLICY_REJECTED',
                        'APPROVAL_REVOKED','SCOPE_INVALID','SANDBOX_FAILED','RESOURCE_EXCEEDED',
                        'EXECUTION_TIMEOUT','EVIDENCE_INCOMPLETE'
                    )),
                    trace_id TEXT NOT NULL,
                    sandbox_id TEXT NOT NULL,
                    approval_id TEXT NOT NULL,
                    policy_decision_id TEXT NOT NULL REFERENCES policy_decisions(id),
                    idempotency_key TEXT,
                    queue_message_id TEXT,
                    result_json TEXT NOT NULL DEFAULT '{}',
                    error TEXT,
                    review_decision TEXT CHECK(review_decision IN ('accepted','rejected')),
                    review_reason TEXT,
                    reviewed_by TEXT REFERENCES users(id),
                    reviewed_at TEXT,
                    retry_of TEXT REFERENCES validation_executions(id),
                    created_by TEXT NOT NULL REFERENCES users(id),
                    lease_owner TEXT,
                    lease_token TEXT,
                    lease_expires_at TEXT,
                    worker_attempt INTEGER NOT NULL DEFAULT 0,
                    started_at TEXT,
                    finished_at TEXT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                )"""
            )
            connection.execute(
                """CREATE TABLE IF NOT EXISTS validation_execution_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    execution_id TEXT NOT NULL REFERENCES validation_executions(id) ON DELETE CASCADE,
                    event_type TEXT NOT NULL,
                    status TEXT NOT NULL,
                    payload_json TEXT NOT NULL DEFAULT '{}',
                    created_at TEXT NOT NULL
                )"""
            )
            connection.execute(
                """CREATE TABLE IF NOT EXISTS validation_execution_evidence (
                    id TEXT PRIMARY KEY,
                    execution_id TEXT NOT NULL REFERENCES validation_executions(id) ON DELETE CASCADE,
                    task_id TEXT NOT NULL REFERENCES tasks(id) ON DELETE CASCADE,
                    evidence_item_id TEXT REFERENCES evidence_items(id),
                    title TEXT NOT NULL,
                    artifact_ref TEXT NOT NULL,
                    content_sha256 TEXT NOT NULL,
                    metadata_json TEXT NOT NULL DEFAULT '{}',
                    created_at TEXT NOT NULL
                )"""
            )
            connection.execute(
                """CREATE TABLE IF NOT EXISTS validation_queue_messages (
                    id TEXT PRIMARY KEY,
                    execution_id TEXT NOT NULL REFERENCES validation_executions(id) ON DELETE CASCADE,
                    message_id TEXT NOT NULL UNIQUE,
                    subject TEXT NOT NULL,
                    schema_version INTEGER NOT NULL DEFAULT 1,
                    status TEXT NOT NULL CHECK(status IN ('ready','leased','done','cancelled','dead')),
                    attempt INTEGER NOT NULL DEFAULT 0,
                    max_attempts INTEGER NOT NULL DEFAULT 3,
                    publish_attempt INTEGER NOT NULL DEFAULT 0,
                    published_at TEXT,
                    last_publish_error TEXT,
                    available_at TEXT NOT NULL,
                    locked_by TEXT,
                    lock_token TEXT,
                    locked_until TEXT,
                    last_error TEXT,
                    payload_json TEXT NOT NULL DEFAULT '{}',
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                )"""
            )
            validation_execution_columns = self._columns(connection, "validation_executions")
            validation_execution_additions = {
                "lease_owner": "TEXT",
                "lease_token": "TEXT",
                "lease_expires_at": "TEXT",
                "worker_attempt": "INTEGER NOT NULL DEFAULT 0",
            }
            for name, definition in validation_execution_additions.items():
                if name not in validation_execution_columns:
                    connection.execute(
                        f"ALTER TABLE validation_executions ADD COLUMN {name} {definition}"
                    )
            validation_queue_columns = self._columns(connection, "validation_queue_messages")
            validation_queue_additions = {
                "schema_version": "INTEGER NOT NULL DEFAULT 1",
                "publish_attempt": "INTEGER NOT NULL DEFAULT 0",
                "published_at": "TEXT",
                "last_publish_error": "TEXT",
            }
            for name, definition in validation_queue_additions.items():
                if name not in validation_queue_columns:
                    connection.execute(
                        f"ALTER TABLE validation_queue_messages ADD COLUMN {name} {definition}"
                    )
            connection.execute(
                """CREATE INDEX IF NOT EXISTS idx_validation_executions_task
                   ON validation_executions(task_id, created_at DESC)"""
            )
            connection.execute(
                """CREATE INDEX IF NOT EXISTS idx_validation_executions_plan
                   ON validation_executions(plan_id, created_at DESC)"""
            )
            connection.execute(
                """CREATE INDEX IF NOT EXISTS idx_validation_execution_events_execution
                   ON validation_execution_events(execution_id, id)"""
            )
            connection.execute(
                """CREATE INDEX IF NOT EXISTS idx_validation_execution_evidence_execution
                   ON validation_execution_evidence(execution_id, created_at DESC)"""
            )
            connection.execute(
                """CREATE INDEX IF NOT EXISTS idx_validation_queue_ready
                   ON validation_queue_messages(status, available_at)"""
            )

            # Only backfill records that truly came from a legacy schema. Recomputing every
            # hash on startup would silently bless an offline modification to an approved scope.
            scope_rows = connection.execute("SELECT * FROM scopes").fetchall()
            for row in scope_rows:
                if scope_hash_added or added_resolved_snapshot or not row["scope_hash"]:
                    connection.execute(
                        "UPDATE scopes SET scope_hash=? WHERE id=?",
                        (self._scope_digest(row), row["id"]),
                    )
            if task_hash_added or added_resolved_snapshot:
                connection.execute(
                    """UPDATE tasks SET scope_hash=COALESCE(
                       (SELECT scope_hash FROM scopes WHERE scopes.id=tasks.scope_id), scope_hash)
                       WHERE scope_hash='' OR scope_hash IS NULL OR ?""",
                    (int(added_resolved_snapshot),),
                )
            if added_resolved_snapshot:
                # Old approvals were not bound to DNS results. Fail closed and require a fresh approval.
                connection.execute(
                    """UPDATE scopes SET approved=0,approved_by=NULL,approved_at=NULL,
                       approval_reason='reapproval required after DNS snapshot migration'"""
                )
                connection.execute(
                    """UPDATE tasks SET status='cancelled',approval_status='revoked',
                       error='scope reapproval required after migration'
                       WHERE status NOT IN ('succeeded','failed','cancelled')"""
                )

            head = connection.execute("SELECT id FROM audit_head WHERE id=1").fetchone()
            if head is None:
                count_row = connection.execute(
                    "SELECT COUNT(*) AS count FROM audit_logs"
                ).fetchone()
                last = connection.execute(
                    "SELECT entry_hash,timestamp FROM audit_logs ORDER BY id DESC LIMIT 1"
                ).fetchone()
                if last is not None:
                    connection.execute(
                        "INSERT INTO audit_head(id,entry_count,last_hash,updated_at) VALUES(1,?,?,?)",
                        (int(count_row["count"]), last["entry_hash"], last["timestamp"]),
                    )
            connection.execute("UPDATE skills SET updated_at=created_at WHERE updated_at=''")
            connection.execute("PRAGMA user_version=12")
            connection.commit()
        except Exception:
            connection.rollback()
            raise

    @contextmanager
    def transaction(self) -> Iterator[sqlite3.Connection]:
        with self._write_lock, closing(self.connect()) as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                yield connection
            except Exception:
                connection.rollback()
                raise
            else:
                connection.commit()

    def fetch_one(self, sql: str, params: Sequence[Any] = ()) -> sqlite3.Row | None:
        with closing(self.connect()) as connection:
            return connection.execute(sql, params).fetchone()

    def fetch_all(self, sql: str, params: Sequence[Any] = ()) -> list[sqlite3.Row]:
        with closing(self.connect()) as connection:
            return list(connection.execute(sql, params).fetchall())

    def execute(self, sql: str, params: Sequence[Any] = ()) -> tuple[int, int]:
        with self.transaction() as connection:
            cursor = connection.execute(sql, params)
            return cursor.rowcount, int(cursor.lastrowid or 0)
