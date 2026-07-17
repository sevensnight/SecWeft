from __future__ import annotations

import asyncio
import builtins
import hashlib
import json
import re
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

from .agent_registry import AgentRegistry
from .audit import AuditService
from .context import scrub_secrets
from .db import Database
from .schemas import TaskCreate
from .scope import ScopeService, ScopeViolation, row_scope_hash
from .security import Principal, redact
from .skills import SkillRegistry

TERMINAL_STATES = frozenset({"succeeded", "failed", "cancelled"})
LEASE_SECONDS = 60


class TaskStateError(RuntimeError):
    pass


def _json(value: str | None, default: Any = None) -> Any:
    return json.loads(value) if value else default


def _now() -> str:
    return datetime.now(UTC).isoformat()


def _future(seconds: int) -> str:
    return (datetime.now(UTC) + timedelta(seconds=seconds)).isoformat()


def _sha256(value: Any) -> str:
    return hashlib.sha256(
        json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def _is_expired(value: str | None) -> bool:
    if not value:
        return True
    return datetime.fromisoformat(value) <= datetime.now(UTC)


def serialize_stage(row: Any) -> dict[str, Any]:
    return {
        "id": row["id"],
        "task_id": row["task_id"],
        "stage_code": row["stage_code"],
        "display_name": row["display_name"],
        "sequence_no": row["sequence_no"],
        "agent_name": row["agent_name"],
        "agent_version": row["agent_version"],
        "skill_name": row["skill_name"],
        "skill_version": row["skill_version"],
        "depends_on": _json(row["depends_on_json"], []),
        "status": row["status"],
        "attempt": row["attempt"],
        "max_attempts": row["max_attempts"],
        "checkpoint": _json(row["checkpoint_json"]),
        "output": _json(row["output_json"]),
        "error": row["error"],
        "started_at": row["started_at"],
        "finished_at": row["finished_at"],
        "created_at": row["created_at"],
        "updated_at": row["updated_at"],
    }


def serialize_execution(row: Any) -> dict[str, Any]:
    return {
        "id": row["id"],
        "task_id": row["task_id"],
        "worker_id": row["worker_id"],
        "fencing_token": row["fencing_token"],
        "status": row["status"],
        "started_at": row["started_at"],
        "heartbeat_at": row["heartbeat_at"],
        "finished_at": row["finished_at"],
        "error": row["error"],
        "created_at": row["created_at"],
        "updated_at": row["updated_at"],
    }


def serialize_dead_letter(row: Any) -> dict[str, Any]:
    return {
        "id": row["id"],
        "task_id": row["task_id"],
        "queue_message_id": row["queue_message_id"],
        "reason": row["reason"],
        "payload": _json(row["payload_json"], {}),
        "created_at": row["created_at"],
    }


def serialize_task(row: Any, stages: builtins.list[dict[str, Any]] | None = None) -> dict[str, Any]:
    value = {
        "id": row["id"],
        "title": row["title"],
        "target": row["target"],
        "intent": row["intent"],
        "indicators": _json(row["indicators_json"], []),
        "scope_id": row["scope_id"],
        "status": row["status"],
        "approval_status": row["approval_status"],
        "created_by": row["created_by"],
        "assigned_skills": _json(row["assigned_skills_json"], []),
        "workflow_name": row["workflow_name"],
        "workflow_version": row["workflow_version"],
        "plan": _json(row["plan_json"]),
        "result": _json(row["result_json"]),
        "error": row["error"],
        "current_stage": row["current_stage"],
        "pause_requested": bool(row["pause_requested"]),
        "cancel_requested": bool(row["cancel_requested"]),
        "retry_count": int(row["retry_count"]),
        "max_retries": int(row["max_retries"]),
        "fencing_token": int(row["fencing_token"]),
        "created_at": row["created_at"],
        "updated_at": row["updated_at"],
    }
    if stages is not None:
        value["stages"] = stages
    return value


class Orchestrator:
    def __init__(
        self,
        db: Database,
        scope: ScopeService,
        skills: SkillRegistry,
        agents: AgentRegistry,
        audit: AuditService,
        max_concurrency: int,
    ):
        self.db = db
        self.scope = scope
        self.skills = skills
        self.agents = agents
        self.audit = audit
        self._semaphore = asyncio.Semaphore(max_concurrency)

    def _event(
        self,
        task_id: str,
        event_type: str,
        payload: dict[str, Any],
        connection: Any | None = None,
    ) -> None:
        params = (
            task_id,
            event_type,
            json.dumps(payload, ensure_ascii=False),
            _now(),
        )
        if connection is not None:
            connection.execute(
                "INSERT INTO task_events(task_id,event_type,payload_json,created_at) VALUES(?,?,?,?)",
                params,
            )
            return
        self.db.execute(
            "INSERT INTO task_events(task_id,event_type,payload_json,created_at) VALUES(?,?,?,?)",
            params,
        )

    def create(self, principal: Principal, value: TaskCreate) -> dict[str, Any]:
        target = self.scope.validate(value.target, value.scope_id)
        scope_row = self.db.fetch_one("SELECT * FROM scopes WHERE id=?", (value.scope_id,))
        assert scope_row is not None
        workflow = self.agents.workflow_by_name("p3.synthetic.defensive", "1.0")
        assigned = [stage["skill_name"] for stage in workflow["stages"]]
        try:
            self.skills.assert_enabled(assigned)
        except ValueError as exc:
            raise TaskStateError(str(exc)) from exc
        task_id = str(uuid.uuid4())
        plan = self._compile_plan(task_id, value, target, scope_row, workflow)
        now = _now()
        with self.db.transaction() as connection:
            connection.execute(
                """INSERT INTO tasks(id,title,target,intent,indicators_json,scope_id,status,
                   approval_status,approved_by,approved_at,approval_reason,scope_hash,created_by,
                   assigned_skills_json,workflow_name,workflow_version,plan_json,result_json,error,
                   current_stage,pause_requested,cancel_requested,retry_count,max_retries,
                   lease_owner,lease_token,lease_expires_at,fencing_token,deadline_at,created_at,updated_at)
                   VALUES(?,?,?,?,?,?,'pending_approval','pending',NULL,NULL,NULL,?,?,?,?,?,
                   ?,NULL,NULL,NULL,0,0,0,2,NULL,NULL,NULL,0,NULL,?,?)""",
                (
                    task_id,
                    value.title,
                    value.target,
                    value.intent,
                    json.dumps(value.indicators, ensure_ascii=False),
                    value.scope_id,
                    scope_row["scope_hash"],
                    principal.id,
                    json.dumps(assigned, ensure_ascii=False),
                    workflow["name"],
                    workflow["version"],
                    json.dumps(plan, ensure_ascii=False),
                    now,
                    now,
                ),
            )
            self._insert_stages(connection, task_id, workflow["stages"], now)
            self._event(
                task_id,
                "task.created",
                {
                    "status": "pending_approval",
                    "scope_hash": scope_row["scope_hash"],
                    "workflow": f"{workflow['name']}@{workflow['version']}",
                },
                connection,
            )
        self.audit.record(
            principal.id,
            "task.create",
            "task",
            task_id,
            details={
                "target": target.host,
                "intent": value.intent,
                "scope_id": value.scope_id,
                "scope_hash": scope_row["scope_hash"],
                "assigned_skills": assigned,
                "workflow": f"{workflow['name']}@{workflow['version']}",
            },
        )
        return self.get(task_id)

    def _insert_stages(
        self, connection: Any, task_id: str, stages: builtins.list[dict[str, Any]], now: str
    ) -> None:
        for sequence_no, stage in enumerate(stages):
            status = "ready" if not stage.get("depends_on") else "pending"
            connection.execute(
                """INSERT INTO task_stages(
                   id,task_id,stage_code,display_name,sequence_no,agent_name,agent_version,
                   skill_name,skill_version,depends_on_json,status,attempt,max_attempts,
                   lease_owner,lease_token,lease_expires_at,checkpoint_json,output_json,error,
                   started_at,finished_at,created_at,updated_at)
                   VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,?,?)""",
                (
                    str(uuid.uuid4()),
                    task_id,
                    stage["code"],
                    stage["display_name"],
                    sequence_no,
                    stage["agent_name"],
                    stage.get("agent_version", "1.0"),
                    stage["skill_name"],
                    stage.get("skill_version", "1.0"),
                    json.dumps(stage.get("depends_on", []), ensure_ascii=False),
                    status,
                    0,
                    stage.get("max_attempts", 1),
                    now,
                    now,
                ),
            )

    @staticmethod
    def _compile_plan(
        task_id: str, value: TaskCreate, target: Any, scope_row: Any, workflow: dict[str, Any]
    ) -> dict[str, Any]:
        allowed_ports = json.loads(scope_row["ports_json"])
        port = target.port or min(allowed_ports)
        steps: list[dict[str, Any]] = [{"kind": "tcp_connect", "host": target.host, "port": port}]
        if target.scheme == "http":
            pattern = None
            if value.indicators:
                candidate = re.sub(r"[^A-Za-z0-9_ .:/+-]", "", value.indicators[0])[:128].strip()
                pattern = candidate or None
            steps.append(
                {
                    "kind": "http_request",
                    "host": target.host,
                    "port": port,
                    "method": "GET",
                    "path": "/",
                    "expected_status": [200, 204, 301, 302, 401, 403, 404],
                    "body_pattern": pattern,
                }
            )
        return {
            "version": "1.1",
            "task_id": task_id,
            "workflow": {"name": workflow["name"], "version": workflow["version"]},
            "destructive": False,
            "objectives": [
                "revalidate authorization scope",
                "execute a persisted and recoverable stage DAG",
                "collect non-destructive reachability evidence when explicitly approved",
                "compare evidence with explicit indicators",
                "produce a defensive report",
            ],
            "dag": [
                {
                    "id": stage["code"],
                    "agent": stage["agent_name"],
                    "skill": stage["skill_name"],
                    "depends_on": stage.get("depends_on", []),
                }
                for stage in workflow["stages"]
            ],
            "steps": steps,
            "rollback": [
                "no target mutation is performed",
                "leases are released by expiry or completion",
                "failed queue messages move to DLQ with redacted payloads",
            ],
            "safety": {
                "forbidden": [
                    "persistence",
                    "evasion",
                    "credential access",
                    "destructive payloads",
                    "scope expansion",
                    "unapproved sandbox or validation execution",
                ],
                "approval_required": True,
                "p3_execution_boundary": "synthetic workflow plus explicitly approved non-destructive probes",
            },
        }

    def approve(
        self, principal: Principal, task_id: str, approved: bool, reason: str
    ) -> dict[str, Any]:
        task = self.db.fetch_one("SELECT * FROM tasks WHERE id=?", (task_id,))
        if task is None:
            raise KeyError("task not found")
        if task["status"] != "pending_approval":
            raise TaskStateError("only pending tasks can be approved or rejected")
        if task["created_by"] == principal.id:
            raise PermissionError("task creators cannot approve their own task")
        scope_row = self.db.fetch_one("SELECT * FROM scopes WHERE id=?", (task["scope_id"],))
        if (
            scope_row is None
            or task["scope_hash"] != row_scope_hash(scope_row)
            or task["scope_hash"] != scope_row["scope_hash"]
        ):
            raise ScopeViolation("scope changed after task creation; create a new task")
        self.scope.validate(task["target"], task["scope_id"])
        now = _now()
        status = "approved" if approved else "cancelled"
        approval_status = "approved" if approved else "rejected"
        count, _ = self.db.execute(
            """UPDATE tasks SET status=?,approval_status=?,approved_by=?,approved_at=?,
               approval_reason=?,updated_at=?
               WHERE id=? AND status='pending_approval'""",
            (status, approval_status, principal.id, now, reason, now, task_id),
        )
        if count != 1:
            raise TaskStateError("task approval raced with another state transition")
        self._event(
            task_id, f"task.{approval_status}", {"reason": reason, "approver": principal.id}
        )
        self.audit.record(
            principal.id,
            f"task.{approval_status}",
            "task",
            task_id,
            details={"reason": reason, "scope_hash": task["scope_hash"]},
        )
        return self.get(task_id)

    def enqueue(
        self, principal: Principal, task_id: str, idempotency_key: str | None = None
    ) -> dict[str, Any]:
        operation = "task.enqueue"
        request_hash = _sha256({"task_id": task_id, "operation": operation})
        if idempotency_key:
            existing = self.db.fetch_one(
                """SELECT * FROM task_idempotency_records
                   WHERE principal_id=? AND operation=? AND idempotency_key=?""",
                (principal.id, operation, idempotency_key),
            )
            if existing is not None:
                if existing["request_hash"] != request_hash:
                    raise TaskStateError("idempotency key was reused with a different request")
                if existing["response_json"]:
                    return json.loads(existing["response_json"])
                return self.get(task_id)

        now = _now()
        response: dict[str, Any]
        with self.db.transaction() as connection:
            task = connection.execute("SELECT * FROM tasks WHERE id=?", (task_id,)).fetchone()
            if task is None:
                raise KeyError("task not found")
            if task["status"] in TERMINAL_STATES:
                raise TaskStateError("terminal tasks cannot be enqueued")
            if task["status"] == "pending_approval":
                raise TaskStateError("task must be approved before execution")
            if task["approval_status"] != "approved":
                raise TaskStateError("task approval is not active")
            if task["status"] in {"approved", "paused"}:
                connection.execute(
                    """UPDATE tasks SET status='queued',pause_requested=0,cancel_requested=0,
                       lease_owner=NULL,lease_token=NULL,lease_expires_at=NULL,updated_at=?
                       WHERE id=?""",
                    (now, task_id),
                )
                active = connection.execute(
                    """SELECT id FROM task_queue_messages
                       WHERE task_id=? AND status IN ('ready','leased') LIMIT 1""",
                    (task_id,),
                ).fetchone()
                if active is None:
                    connection.execute(
                        """INSERT INTO task_queue_messages(
                           id,task_id,message_id,status,attempt,max_attempts,available_at,
                           locked_by,lock_token,locked_until,last_error,payload_json,created_at,updated_at)
                           VALUES(?,?,?,'ready',0,3,?,NULL,NULL,NULL,NULL,?,?,?)""",
                        (
                            str(uuid.uuid4()),
                            task_id,
                            str(uuid.uuid4()),
                            now,
                            json.dumps(
                                {"task_id": task_id, "reason": operation}, ensure_ascii=False
                            ),
                            now,
                            now,
                        ),
                    )
                self._event(task_id, "task.queued", {"actor": principal.id}, connection)
            elif task["status"] not in {"queued", "running", "pausing", "cancelling"}:
                raise TaskStateError(f"task cannot be enqueued from state {task['status']}")

            if idempotency_key:
                connection.execute(
                    """INSERT INTO task_idempotency_records(
                       id,principal_id,operation,idempotency_key,request_hash,response_json,
                       resource_type,resource_id,status,expires_at,created_at,updated_at)
                       VALUES(?,?,?,?,?,NULL,'task',?,'processing',?,?,?)""",
                    (
                        str(uuid.uuid4()),
                        principal.id,
                        operation,
                        idempotency_key,
                        request_hash,
                        task_id,
                        _future(24 * 3600),
                        now,
                        now,
                    ),
                )
        response = self.get(task_id)
        if idempotency_key:
            self.db.execute(
                """UPDATE task_idempotency_records SET response_json=?,status='completed',
                   updated_at=? WHERE principal_id=? AND operation=? AND idempotency_key=?""",
                (
                    json.dumps(response, ensure_ascii=False),
                    _now(),
                    principal.id,
                    operation,
                    idempotency_key,
                ),
            )
        self.audit.record(
            principal.id, "task.enqueue", "task", task_id, details={"status": "queued"}
        )
        return response

    async def run(self, principal: Principal, task_id: str) -> dict[str, Any]:
        """Lease and execute one approved queued task.

        This compatibility worker method is intentionally database-driven: a second process can
        acquire the same task only after the persisted lease expires or is completed.
        """

        if not bool(self.audit.verify()["valid"]):
            raise TaskStateError("audit integrity check failed; execution is blocked")
        async with self._semaphore:
            execution = self._acquire_execution(principal, task_id)
            try:
                return await self._run_leased(principal, task_id, execution)
            finally:
                self._clear_task_lease(task_id, execution["lease_token"])

    def _acquire_execution(self, principal: Principal, task_id: str) -> dict[str, Any]:
        worker_id = f"user:{principal.id}"
        lease_token = str(uuid.uuid4())
        execution_id = str(uuid.uuid4())
        now = _now()
        lease_expires_at = _future(LEASE_SECONDS)
        with self.db.transaction() as connection:
            task = connection.execute("SELECT * FROM tasks WHERE id=?", (task_id,)).fetchone()
            if task is None:
                raise KeyError("task not found")
            if task["status"] == "approved":
                connection.execute(
                    "UPDATE tasks SET status='queued',updated_at=? WHERE id=?",
                    (now, task_id),
                )
                connection.execute(
                    """INSERT INTO task_queue_messages(
                       id,task_id,message_id,status,attempt,max_attempts,available_at,
                       locked_by,lock_token,locked_until,last_error,payload_json,created_at,updated_at)
                       VALUES(?,?,?,'ready',0,3,?,NULL,NULL,NULL,NULL,?,?,?)""",
                    (
                        str(uuid.uuid4()),
                        task_id,
                        str(uuid.uuid4()),
                        now,
                        json.dumps({"task_id": task_id, "reason": "direct_worker_run"}),
                        now,
                        now,
                    ),
                )
                task = connection.execute("SELECT * FROM tasks WHERE id=?", (task_id,)).fetchone()
            if task["status"] == "running" and not _is_expired(task["lease_expires_at"]):
                raise TaskStateError("task lease is active")
            if task["status"] == "running" and _is_expired(task["lease_expires_at"]):
                self._recover_task_in_tx(connection, task_id, "lease expired before acquisition")
                task = connection.execute("SELECT * FROM tasks WHERE id=?", (task_id,)).fetchone()
            if task["status"] != "queued":
                raise TaskStateError("task must be queued before worker execution")
            if task["approval_status"] != "approved":
                raise TaskStateError("task approval is not active")
            scope_row = connection.execute(
                "SELECT * FROM scopes WHERE id=?", (task["scope_id"],)
            ).fetchone()
            if (
                scope_row is None
                or task["scope_hash"] != scope_row["scope_hash"]
                or task["scope_hash"] != row_scope_hash(scope_row)
            ):
                raise ScopeViolation("scope signature no longer matches the approved task")

            queue_row = connection.execute(
                """SELECT * FROM task_queue_messages
                   WHERE task_id=? AND (
                       status='ready'
                       OR (status='leased' AND (locked_until IS NULL OR locked_until <= ?))
                   )
                   ORDER BY created_at LIMIT 1""",
                (task_id, now),
            ).fetchone()
            if queue_row is None:
                raise TaskStateError("no ready queue message exists for task")
            if int(queue_row["attempt"]) >= int(queue_row["max_attempts"]):
                self._dead_letter_in_tx(
                    connection,
                    task_id,
                    queue_row["id"],
                    "queue message exceeded max attempts",
                    _json(queue_row["payload_json"], {}),
                )
                raise TaskStateError("queue message exceeded max attempts")

            fencing_token = int(task["fencing_token"]) + 1
            connection.execute(
                """UPDATE task_queue_messages SET status='leased',attempt=attempt+1,
                   locked_by=?,lock_token=?,locked_until=?,updated_at=?
                   WHERE id=?""",
                (worker_id, lease_token, lease_expires_at, now, queue_row["id"]),
            )
            connection.execute(
                """UPDATE tasks SET status='running',lease_owner=?,lease_token=?,
                   lease_expires_at=?,fencing_token=?,started_at=COALESCE(started_at,?),
                   updated_at=?
                   WHERE id=?""",
                (worker_id, lease_token, lease_expires_at, fencing_token, now, now, task_id),
            )
            connection.execute(
                """INSERT INTO task_executions(
                   id,task_id,worker_id,lease_token,fencing_token,status,started_at,
                   heartbeat_at,finished_at,error,created_at,updated_at)
                   VALUES(?,?,?,?,?,'running',?,?,NULL,NULL,?,?)""",
                (
                    execution_id,
                    task_id,
                    worker_id,
                    lease_token,
                    fencing_token,
                    now,
                    now,
                    now,
                    now,
                ),
            )
            self._event(
                task_id,
                "task.running",
                {"actor": principal.id, "worker_id": worker_id, "fencing_token": fencing_token},
                connection,
            )
        self.audit.record(
            principal.id,
            "task.execute.start",
            "task",
            task_id,
            details={"fencing_token": fencing_token, "lease_seconds": LEASE_SECONDS},
        )
        return {
            "execution_id": execution_id,
            "worker_id": worker_id,
            "lease_token": lease_token,
            "fencing_token": fencing_token,
        }

    async def _run_leased(
        self, principal: Principal, task_id: str, execution: dict[str, Any]
    ) -> dict[str, Any]:
        stages = self.db.fetch_all(
            "SELECT * FROM task_stages WHERE task_id=? ORDER BY sequence_no", (task_id,)
        )
        try:
            self.skills.assert_enabled([row["skill_name"] for row in stages])
        except ValueError as exc:
            self._finish_failed(principal, task_id, execution, "missing_skill", str(exc))
            raise TaskStateError(str(exc)) from exc

        try:
            for row in stages:
                stage = self.db.fetch_one("SELECT * FROM task_stages WHERE id=?", (row["id"],))
                if stage is None or stage["status"] == "succeeded":
                    continue
                while True:
                    control = self.db.fetch_one("SELECT * FROM tasks WHERE id=?", (task_id,))
                    if control is None:
                        raise KeyError("task not found")
                    if bool(control["cancel_requested"]) or control["status"] == "cancelling":
                        self._finish_cancelled(principal, task_id, execution)
                        return self.get(task_id)
                    if bool(control["pause_requested"]) or control["status"] == "pausing":
                        self._pause_leased(principal, task_id, execution, stage["stage_code"])
                        return self.get(task_id)

                    stage = self._start_stage(task_id, stage["id"], execution)
                    try:
                        output = await self._execute_stage(task_id, stage)
                    except Exception as exc:
                        self.skills.record_invocation(stage["skill_name"], succeeded=False)
                        retry = int(stage["attempt"]) < int(stage["max_attempts"])
                        self._fail_stage(task_id, stage, execution, exc, retry=retry)
                        if retry:
                            stage = self.db.fetch_one(
                                "SELECT * FROM task_stages WHERE id=?", (stage["id"],)
                            )
                            assert stage is not None
                            continue
                        self._finish_failed(
                            principal,
                            task_id,
                            execution,
                            type(exc).__name__,
                            str(exc)[:500],
                        )
                        return self.get(task_id)
                    self.skills.record_invocation(stage["skill_name"], succeeded=True)
                    self._succeed_stage(task_id, stage, execution, output)
                    self._heartbeat(task_id, execution)
                    break
            self._finish_succeeded(principal, task_id, execution)
        except asyncio.CancelledError:
            self._finish_cancelled(principal, task_id, execution)
        return self.get(task_id)

    def _start_stage(self, task_id: str, stage_id: str, execution: dict[str, Any]) -> Any:
        now = _now()
        lease_expires_at = _future(LEASE_SECONDS)
        with self.db.transaction() as connection:
            row = connection.execute("SELECT * FROM task_stages WHERE id=?", (stage_id,)).fetchone()
            if row is None:
                raise KeyError("stage not found")
            missing = self._missing_dependencies_in_tx(connection, task_id, row)
            if missing:
                raise TaskStateError(f"stage dependencies are not complete: {', '.join(missing)}")
            connection.execute(
                """UPDATE task_stages SET status='running',attempt=attempt+1,
                   lease_owner=?,lease_token=?,lease_expires_at=?,started_at=COALESCE(started_at,?),
                   updated_at=? WHERE id=?""",
                (
                    execution["worker_id"],
                    execution["lease_token"],
                    lease_expires_at,
                    now,
                    now,
                    stage_id,
                ),
            )
            connection.execute(
                "UPDATE tasks SET current_stage=?,lease_expires_at=?,updated_at=? WHERE id=?",
                (row["stage_code"], lease_expires_at, now, task_id),
            )
            self._event(
                task_id,
                "task.stage.running",
                {
                    "stage": row["stage_code"],
                    "agent": row["agent_name"],
                    "skill": row["skill_name"],
                    "attempt": int(row["attempt"]) + 1,
                    "fencing_token": execution["fencing_token"],
                },
                connection,
            )
            self._event(
                task_id,
                "task.agent.invoked",
                {
                    "stage": row["stage_code"],
                    "agent": row["agent_name"],
                    "agent_version": row["agent_version"],
                    "skill": row["skill_name"],
                },
                connection,
            )
        updated = self.db.fetch_one("SELECT * FROM task_stages WHERE id=?", (stage_id,))
        assert updated is not None
        return updated

    @staticmethod
    def _missing_dependencies_in_tx(
        connection: Any, task_id: str, stage: Any
    ) -> builtins.list[str]:
        missing: builtins.list[str] = []
        for dependency in _json(stage["depends_on_json"], []):
            row = connection.execute(
                "SELECT status FROM task_stages WHERE task_id=? AND stage_code=?",
                (task_id, dependency),
            ).fetchone()
            if row is None or row["status"] != "succeeded":
                missing.append(str(dependency))
        return missing

    async def _execute_stage(self, task_id: str, stage: Any) -> dict[str, Any]:
        task = self.db.fetch_one("SELECT * FROM tasks WHERE id=?", (task_id,))
        if task is None:
            raise KeyError("task not found")
        plan = _json(task["plan_json"], {})
        skill = stage["skill_name"]
        if skill == "scope.check":
            scope_row = self.db.fetch_one("SELECT * FROM scopes WHERE id=?", (task["scope_id"],))
            assert scope_row is not None
            target = self.scope.validate(task["target"], task["scope_id"])
            return {
                "target": task["target"],
                "host": target.host,
                "scope_id": task["scope_id"],
                "scope_hash": scope_row["scope_hash"],
                "non_destructive": True,
            }
        if skill == "task.plan":
            return {
                "workflow": plan.get("workflow"),
                "stage_count": len(plan.get("dag", [])),
                "dag": plan.get("dag", []),
                "destructive": False,
            }
        if skill == "rag.retrieve":
            return {
                "query": f"{task['intent']} {' '.join(_json(task['indicators_json'], []))}".strip(),
                "references": [],
                "acl_filtered": True,
                "non_destructive": True,
            }
        if skill == "asset.safe_probe":
            return {"evidence": await self._collect_evidence(task, plan), "non_destructive": True}
        if skill == "validation.safe_check":
            evidence = self._stage_output(task_id, "evidence").get("evidence", [])
            validation_signal = self._validation_signal(task, evidence)
            return {
                "validation_signal": validation_signal,
                "evidence_count": len(evidence),
                "non_destructive": True,
                "limitations": (
                    "Reachability or an indicator match is evidence, not proof of exploitability."
                ),
            }
        if skill == "report.generate":
            evaluation = self._stage_output(task_id, "evaluate")
            evidence = self._stage_output(task_id, "evidence").get("evidence", [])
            return {
                "summary": "Defensive workflow completed with persisted stage evidence.",
                "validation_signal": bool(evaluation.get("validation_signal", False)),
                "evidence_count": len(evidence),
                "non_destructive": True,
                "limitations": evaluation.get(
                    "limitations",
                    "Reachability or an indicator match is evidence, not proof of exploitability.",
                ),
            }
        return {"skipped": True, "skill": skill}

    async def _collect_evidence(
        self, task: Any, plan: dict[str, Any]
    ) -> builtins.list[dict[str, Any]]:
        evidence: builtins.list[dict[str, Any]] = []
        for index, step in enumerate(plan.get("steps", [])):
            self.scope.validate(task["target"], task["scope_id"], [step["port"]])
            if step["kind"] == "tcp_connect":
                item = await self.scope.probe(task["target"], task["scope_id"], [step["port"]], 1.5)
            elif step["kind"] == "http_request":
                item = await self.scope.http_probe(
                    task["target"],
                    task["scope_id"],
                    step["port"],
                    step["method"],
                    step["path"],
                    2.0,
                )
                body = str(item.pop("body", ""))
                pattern = step.get("body_pattern")
                item["body_excerpt"] = scrub_secrets(body)[:1000]
                item["indicator_matched"] = bool(pattern and pattern.lower() in body.lower())
                item["expected_status_matched"] = item.get("status") in step.get(
                    "expected_status", []
                )
            else:
                item = {"kind": step["kind"], "skipped": True}
            evidence.append({"step": index, "kind": step["kind"], "evidence": item})
            self._event(
                task["id"],
                "task.tool.called",
                {
                    "tool": step["kind"],
                    "step": index,
                    "non_destructive": True,
                    "target_port": step.get("port"),
                },
            )
        return evidence

    @staticmethod
    def _validation_signal(task: Any, evidence: builtins.list[dict[str, Any]]) -> bool:
        if task["intent"] == "asset_inventory":
            return any(
                any(
                    result.get("status") == "open" for result in item["evidence"].get("results", [])
                )
                for item in evidence
            )
        if _json(task["indicators_json"], []):
            return any(item["evidence"].get("indicator_matched", False) for item in evidence)
        return False

    def _stage_output(self, task_id: str, stage_code: str) -> dict[str, Any]:
        row = self.db.fetch_one(
            "SELECT output_json FROM task_stages WHERE task_id=? AND stage_code=?",
            (task_id, stage_code),
        )
        if row is None:
            return {}
        return _json(row["output_json"], {})

    def _succeed_stage(
        self, task_id: str, stage: Any, execution: dict[str, Any], output: dict[str, Any]
    ) -> None:
        now = _now()
        with self.db.transaction() as connection:
            connection.execute(
                """UPDATE task_stages SET status='succeeded',checkpoint_json=?,output_json=?,
                   error=NULL,lease_owner=NULL,lease_token=NULL,lease_expires_at=NULL,
                   finished_at=?,updated_at=?
                   WHERE id=? AND lease_token=?""",
                (
                    json.dumps({"finished_at": now, "output_sha256": _sha256(output)}),
                    json.dumps(output, ensure_ascii=False),
                    now,
                    now,
                    stage["id"],
                    execution["lease_token"],
                ),
            )
            connection.execute(
                """UPDATE task_stages SET status='ready',updated_at=?
                   WHERE task_id=? AND status='pending' AND NOT EXISTS (
                       SELECT 1 FROM json_each(task_stages.depends_on_json) dep
                       JOIN task_stages prior
                         ON prior.task_id=task_stages.task_id
                        AND prior.stage_code=dep.value
                       WHERE prior.status <> 'succeeded'
                   )""",
                (now, task_id),
            )
            self._event(
                task_id,
                "task.stage.succeeded",
                {"stage": stage["stage_code"], "skill": stage["skill_name"]},
                connection,
            )

    def _fail_stage(
        self,
        task_id: str,
        stage: Any,
        execution: dict[str, Any],
        exc: Exception,
        *,
        retry: bool,
    ) -> None:
        now = _now()
        status = "ready" if retry else "failed"
        error = f"{type(exc).__name__}: {str(exc)[:500]}"
        with self.db.transaction() as connection:
            connection.execute(
                """UPDATE task_stages SET status=?,error=?,lease_owner=NULL,lease_token=NULL,
                   lease_expires_at=NULL,updated_at=? WHERE id=? AND lease_token=?""",
                (status, error, now, stage["id"], execution["lease_token"]),
            )
            self._event(
                task_id,
                "task.stage.retrying" if retry else "task.stage.failed",
                {
                    "stage": stage["stage_code"],
                    "skill": stage["skill_name"],
                    "error_type": type(exc).__name__,
                    "attempt": int(stage["attempt"]),
                    "max_attempts": int(stage["max_attempts"]),
                },
                connection,
            )

    def _finish_succeeded(
        self, principal: Principal, task_id: str, execution: dict[str, Any]
    ) -> None:
        evidence = self._stage_output(task_id, "evidence").get("evidence", [])
        evaluation = self._stage_output(task_id, "evaluate")
        report = self._stage_output(task_id, "report")
        result = {
            "outcome": "evidence_collected",
            "validation_signal": bool(evaluation.get("validation_signal", False)),
            "non_destructive": True,
            "evidence": evidence,
            "report": report,
            "limitations": evaluation.get(
                "limitations",
                "Reachability or an indicator match is evidence, not proof of exploitability.",
            ),
        }
        now = _now()
        with self.db.transaction() as connection:
            connection.execute(
                """UPDATE tasks SET status='succeeded',result_json=?,error=NULL,current_stage=NULL,
                   cancel_requested=0,pause_requested=0,lease_owner=NULL,lease_token=NULL,
                   lease_expires_at=NULL,finished_at=?,updated_at=?
                   WHERE id=? AND lease_token=?""",
                (
                    json.dumps(result, ensure_ascii=False),
                    now,
                    now,
                    task_id,
                    execution["lease_token"],
                ),
            )
            connection.execute(
                """UPDATE task_executions SET status='succeeded',finished_at=?,heartbeat_at=?,
                   updated_at=? WHERE id=?""",
                (now, now, now, execution["execution_id"]),
            )
            connection.execute(
                """UPDATE task_queue_messages SET status='done',locked_until=NULL,updated_at=?
                   WHERE task_id=? AND lock_token=?""",
                (now, task_id, execution["lease_token"]),
            )
            self._event(
                task_id,
                "task.succeeded",
                {
                    "validation_signal": result["validation_signal"],
                    "fencing_token": execution["fencing_token"],
                },
                connection,
            )
        self.audit.record(
            principal.id,
            "task.execute.finish",
            "task",
            task_id,
            details={
                "outcome": "succeeded",
                "validation_signal": result["validation_signal"],
                "evidence_count": len(evidence),
                "fencing_token": execution["fencing_token"],
            },
        )

    def _finish_failed(
        self,
        principal: Principal,
        task_id: str,
        execution: dict[str, Any],
        error_code: str,
        error: str,
    ) -> None:
        now = _now()
        with self.db.transaction() as connection:
            connection.execute(
                """UPDATE tasks SET status='failed',error=?,lease_owner=NULL,lease_token=NULL,
                   lease_expires_at=NULL,finished_at=?,updated_at=?
                   WHERE id=? AND lease_token=?""",
                (f"{error_code}: {error}", now, now, task_id, execution["lease_token"]),
            )
            connection.execute(
                """UPDATE task_executions SET status='failed',error=?,finished_at=?,
                   heartbeat_at=?,updated_at=? WHERE id=?""",
                (f"{error_code}: {error}", now, now, now, execution["execution_id"]),
            )
            queue = connection.execute(
                "SELECT * FROM task_queue_messages WHERE task_id=? AND lock_token=?",
                (task_id, execution["lease_token"]),
            ).fetchone()
            if queue is not None:
                connection.execute(
                    "UPDATE task_queue_messages SET status='dead',last_error=?,updated_at=? WHERE id=?",
                    (error, now, queue["id"]),
                )
                self._dead_letter_in_tx(
                    connection,
                    task_id,
                    queue["id"],
                    f"{error_code}: {error}",
                    _json(queue["payload_json"], {}),
                )
            self._event(
                task_id,
                "task.failed",
                {"error_code": error_code, "fencing_token": execution["fencing_token"]},
                connection,
            )
        self.audit.record(
            principal.id,
            "task.execute.finish",
            "task",
            task_id,
            "failure",
            {"error_type": error_code, "fencing_token": execution["fencing_token"]},
        )

    def _finish_cancelled(
        self, principal: Principal, task_id: str, execution: dict[str, Any]
    ) -> None:
        now = _now()
        with self.db.transaction() as connection:
            connection.execute(
                """UPDATE tasks SET status='cancelled',error='cancelled',cancel_requested=1,
                   lease_owner=NULL,lease_token=NULL,lease_expires_at=NULL,finished_at=?,
                   updated_at=? WHERE id=?""",
                (now, now, task_id),
            )
            connection.execute(
                """UPDATE task_stages SET status='cancelled',updated_at=?
                   WHERE task_id=? AND status IN ('pending','ready','running','paused')""",
                (now, task_id),
            )
            connection.execute(
                """UPDATE task_executions SET status='cancelled',finished_at=?,heartbeat_at=?,
                   updated_at=? WHERE id=?""",
                (now, now, now, execution["execution_id"]),
            )
            connection.execute(
                "UPDATE task_queue_messages SET status='cancelled',updated_at=? WHERE task_id=?",
                (now, task_id),
            )
            self._event(task_id, "task.cancelled", {"actor": principal.id}, connection)
        self.audit.record(
            principal.id,
            "task.execute.finish",
            "task",
            task_id,
            "cancelled",
            {"fencing_token": execution["fencing_token"]},
        )

    def _pause_leased(
        self, principal: Principal, task_id: str, execution: dict[str, Any], stage_code: str
    ) -> None:
        now = _now()
        with self.db.transaction() as connection:
            connection.execute(
                """UPDATE tasks SET status='paused',pause_requested=1,lease_owner=NULL,
                   lease_token=NULL,lease_expires_at=NULL,updated_at=? WHERE id=?""",
                (now, task_id),
            )
            connection.execute(
                """UPDATE task_stages SET status='paused',lease_owner=NULL,lease_token=NULL,
                   lease_expires_at=NULL,updated_at=?
                   WHERE task_id=? AND stage_code=? AND status='running'""",
                (now, task_id, stage_code),
            )
            connection.execute(
                """UPDATE task_executions SET status='paused',finished_at=?,heartbeat_at=?,
                   updated_at=? WHERE id=?""",
                (now, now, now, execution["execution_id"]),
            )
            connection.execute(
                """UPDATE task_queue_messages SET status='ready',locked_by=NULL,lock_token=NULL,
                   locked_until=NULL,updated_at=? WHERE task_id=? AND lock_token=?""",
                (now, task_id, execution["lease_token"]),
            )
            self._event(task_id, "task.paused", {"actor": principal.id}, connection)

    def _heartbeat(self, task_id: str, execution: dict[str, Any]) -> None:
        now = _now()
        lease_expires_at = _future(LEASE_SECONDS)
        self.db.execute(
            """UPDATE tasks SET lease_expires_at=?,updated_at=?
               WHERE id=? AND lease_token=? AND status='running'""",
            (lease_expires_at, now, task_id, execution["lease_token"]),
        )
        self.db.execute(
            """UPDATE task_executions SET heartbeat_at=?,updated_at=?
               WHERE id=? AND lease_token=? AND status='running'""",
            (now, now, execution["execution_id"], execution["lease_token"]),
        )

    def _clear_task_lease(self, task_id: str, lease_token: str) -> None:
        self.db.execute(
            """UPDATE tasks SET lease_owner=NULL,lease_token=NULL,lease_expires_at=NULL,updated_at=?
               WHERE id=? AND lease_token=? AND status IN ('succeeded','failed','cancelled')""",
            (_now(), task_id, lease_token),
        )

    def pause(
        self, principal: Principal, task_id: str, reason: str | None = None
    ) -> dict[str, Any]:
        task = self.db.fetch_one("SELECT * FROM tasks WHERE id=?", (task_id,))
        if task is None:
            raise KeyError("task not found")
        if task["status"] in TERMINAL_STATES:
            return self.get(task_id)
        now = _now()
        if task["status"] == "running":
            self.db.execute(
                """UPDATE tasks SET status='pausing',pause_requested=1,updated_at=?
                   WHERE id=? AND status='running'""",
                (now, task_id),
            )
        elif task["status"] in {"approved", "queued"}:
            self.db.execute(
                "UPDATE tasks SET status='paused',pause_requested=1,updated_at=? WHERE id=?",
                (now, task_id),
            )
        self._event(task_id, "task.pause.requested", {"actor": principal.id, "reason": reason})
        self.audit.record(principal.id, "task.pause", "task", task_id, details={"reason": reason})
        return self.get(task_id)

    def resume(
        self, principal: Principal, task_id: str, reason: str | None = None
    ) -> dict[str, Any]:
        task = self.db.fetch_one("SELECT * FROM tasks WHERE id=?", (task_id,))
        if task is None:
            raise KeyError("task not found")
        if task["status"] != "paused":
            raise TaskStateError("only paused tasks can be resumed")
        now = _now()
        self.db.execute(
            """UPDATE task_stages SET status='ready',updated_at=?
               WHERE task_id=? AND status='paused'""",
            (now, task_id),
        )
        self.db.execute(
            """UPDATE tasks SET status='approved',pause_requested=0,lease_owner=NULL,
               lease_token=NULL,lease_expires_at=NULL,updated_at=? WHERE id=?""",
            (now, task_id),
        )
        self._event(task_id, "task.resumed", {"actor": principal.id, "reason": reason})
        self.audit.record(principal.id, "task.resume", "task", task_id, details={"reason": reason})
        return self.enqueue(principal, task_id)

    def retry(
        self, principal: Principal, task_id: str, reason: str | None = None
    ) -> dict[str, Any]:
        task = self.db.fetch_one("SELECT * FROM tasks WHERE id=?", (task_id,))
        if task is None:
            raise KeyError("task not found")
        if task["status"] != "failed":
            raise TaskStateError("only failed tasks can be retried")
        if int(task["retry_count"]) >= int(task["max_retries"]):
            raise TaskStateError("task retry budget is exhausted")
        now = _now()
        with self.db.transaction() as connection:
            connection.execute(
                """UPDATE tasks SET status='approved',error=NULL,retry_count=retry_count+1,
                   cancel_requested=0,pause_requested=0,current_stage=NULL,updated_at=? WHERE id=?""",
                (now, task_id),
            )
            connection.execute(
                """UPDATE task_stages SET status='ready',error=NULL,lease_owner=NULL,lease_token=NULL,
                   lease_expires_at=NULL,updated_at=?
                   WHERE task_id=? AND status IN ('failed','timed_out')""",
                (now, task_id),
            )
            self._event(
                task_id,
                "task.retry.requested",
                {"actor": principal.id, "reason": reason},
                connection,
            )
        self.audit.record(principal.id, "task.retry", "task", task_id, details={"reason": reason})
        return self.enqueue(principal, task_id)

    def cancel(self, principal: Principal, task_id: str) -> dict[str, Any]:
        task = self.db.fetch_one("SELECT * FROM tasks WHERE id=?", (task_id,))
        if task is None:
            raise KeyError("task not found")
        if task["status"] in TERMINAL_STATES:
            return serialize_task(task)
        now = _now()
        if task["status"] == "running":
            self.db.execute(
                """UPDATE tasks SET status='cancelling',cancel_requested=1,updated_at=?
                   WHERE id=? AND status='running'""",
                (now, task_id),
            )
        else:
            with self.db.transaction() as connection:
                connection.execute(
                    """UPDATE tasks SET status='cancelled',cancel_requested=1,updated_at=?
                       WHERE id=? AND status NOT IN ('succeeded','failed','cancelled')""",
                    (now, task_id),
                )
                connection.execute(
                    """UPDATE task_stages SET status='cancelled',updated_at=?
                       WHERE task_id=? AND status IN ('pending','ready','paused')""",
                    (now, task_id),
                )
                connection.execute(
                    "UPDATE task_queue_messages SET status='cancelled',updated_at=? WHERE task_id=?",
                    (now, task_id),
                )
        self._event(task_id, "task.cancel.requested", {"actor": principal.id})
        self.audit.record(principal.id, "task.cancel", "task", task_id)
        return self.get(task_id)

    def recover_stale_leases(self, reason: str = "stale lease recovery") -> dict[str, int]:
        now = _now()
        recovered = 0
        with self.db.transaction() as connection:
            rows = connection.execute(
                """SELECT id FROM tasks
                   WHERE status='running' AND lease_expires_at IS NOT NULL AND lease_expires_at <= ?""",
                (now,),
            ).fetchall()
            for row in rows:
                self._recover_task_in_tx(connection, row["id"], reason)
                recovered += 1
        return {"recovered": recovered}

    def _recover_task_in_tx(self, connection: Any, task_id: str, reason: str) -> None:
        now = _now()
        connection.execute(
            """UPDATE tasks SET status='queued',lease_owner=NULL,lease_token=NULL,
               lease_expires_at=NULL,current_stage=NULL,updated_at=? WHERE id=?""",
            (now, task_id),
        )
        connection.execute(
            """UPDATE task_stages SET status='ready',lease_owner=NULL,lease_token=NULL,
               lease_expires_at=NULL,updated_at=? WHERE task_id=? AND status='running'""",
            (now, task_id),
        )
        connection.execute(
            """UPDATE task_executions SET status='timed_out',finished_at=?,updated_at=?
               WHERE task_id=? AND status='running'""",
            (now, now, task_id),
        )
        connection.execute(
            """UPDATE task_queue_messages SET status='ready',locked_by=NULL,lock_token=NULL,
               locked_until=NULL,last_error=?,updated_at=?
               WHERE task_id=? AND status='leased'""",
            (reason, now, task_id),
        )
        self._event(task_id, "task.lease.recovered", {"reason": reason}, connection)

    def _dead_letter_in_tx(
        self,
        connection: Any,
        task_id: str | None,
        queue_message_id: str | None,
        reason: str,
        payload: dict[str, Any],
    ) -> None:
        connection.execute(
            """INSERT INTO task_dead_letters(id,task_id,queue_message_id,reason,payload_json,created_at)
               VALUES(?,?,?,?,?,?)""",
            (
                str(uuid.uuid4()),
                task_id,
                queue_message_id,
                reason,
                json.dumps(redact(payload), ensure_ascii=False),
                _now(),
            ),
        )

    def get(self, task_id: str) -> dict[str, Any]:
        row = self.db.fetch_one("SELECT * FROM tasks WHERE id=?", (task_id,))
        if row is None:
            raise KeyError("task not found")
        return serialize_task(row, self.stages(task_id))

    def list(self, principal: Principal, limit: int = 100) -> builtins.list[dict[str, Any]]:
        if principal.role.value == "admin":
            rows = self.db.fetch_all(
                "SELECT * FROM tasks ORDER BY created_at DESC LIMIT ?", (limit,)
            )
        else:
            rows = self.db.fetch_all(
                "SELECT * FROM tasks WHERE created_by=? ORDER BY created_at DESC LIMIT ?",
                (principal.id, limit),
            )
        return [serialize_task(row) for row in rows]

    def stages(self, task_id: str) -> builtins.list[dict[str, Any]]:
        return [
            serialize_stage(row)
            for row in self.db.fetch_all(
                "SELECT * FROM task_stages WHERE task_id=? ORDER BY sequence_no", (task_id,)
            )
        ]

    def executions(self, task_id: str) -> builtins.list[dict[str, Any]]:
        return [
            serialize_execution(row)
            for row in self.db.fetch_all(
                "SELECT * FROM task_executions WHERE task_id=? ORDER BY created_at DESC", (task_id,)
            )
        ]

    def dead_letters(self, limit: int = 100) -> builtins.list[dict[str, Any]]:
        return [
            serialize_dead_letter(row)
            for row in self.db.fetch_all(
                "SELECT * FROM task_dead_letters ORDER BY created_at DESC LIMIT ?", (limit,)
            )
        ]

    def events(self, task_id: str) -> builtins.list[dict[str, Any]]:
        return [
            {
                "id": row["id"],
                "event_type": row["event_type"],
                "payload": json.loads(row["payload_json"]),
                "created_at": row["created_at"],
            }
            for row in self.db.fetch_all(
                "SELECT * FROM task_events WHERE task_id=? ORDER BY id", (task_id,)
            )
        ]
