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
CREATE INDEX IF NOT EXISTS idx_memory_task_sequence ON memory_messages(task_id, sequence_no);
CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_logs(timestamp);
CREATE INDEX IF NOT EXISTS idx_rag_classification ON rag_documents(classification);
CREATE INDEX IF NOT EXISTS idx_rag_chunks_document ON rag_chunks(document_id, chunk_index);
CREATE INDEX IF NOT EXISTS idx_evidence_task ON evidence_items(task_id, created_at DESC);
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
            connection.execute("PRAGMA user_version=5")
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
