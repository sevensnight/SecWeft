from __future__ import annotations

import asyncio
import builtins
import json
import re
import uuid
from datetime import UTC, datetime
from typing import Any

from .audit import AuditService
from .context import scrub_secrets
from .db import Database
from .schemas import TaskCreate
from .scope import ScopeService, ScopeViolation, row_scope_hash
from .security import Principal
from .skills import SkillRegistry

TERMINAL_STATES = frozenset({"succeeded", "failed", "cancelled"})


class TaskStateError(RuntimeError):
    pass


def _json(value: str | None, default: Any = None) -> Any:
    return json.loads(value) if value else default


def serialize_task(row: Any) -> dict[str, Any]:
    return {
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
        "plan": _json(row["plan_json"]),
        "result": _json(row["result_json"]),
        "error": row["error"],
        "created_at": row["created_at"],
        "updated_at": row["updated_at"],
    }


class Orchestrator:
    def __init__(
        self,
        db: Database,
        scope: ScopeService,
        skills: SkillRegistry,
        audit: AuditService,
        max_concurrency: int,
    ):
        self.db = db
        self.scope = scope
        self.skills = skills
        self.audit = audit
        self._semaphore = asyncio.Semaphore(max_concurrency)
        self._locks: dict[str, asyncio.Lock] = {}
        self._cancel: dict[str, asyncio.Event] = {}

    def _event(self, task_id: str, event_type: str, payload: dict[str, Any]) -> None:
        self.db.execute(
            "INSERT INTO task_events(task_id,event_type,payload_json,created_at) VALUES(?,?,?,?)",
            (
                task_id,
                event_type,
                json.dumps(payload, ensure_ascii=False),
                datetime.now(UTC).isoformat(),
            ),
        )

    def create(self, principal: Principal, value: TaskCreate) -> dict[str, Any]:
        target = self.scope.validate(value.target, value.scope_id)
        scope_row = self.db.fetch_one("SELECT * FROM scopes WHERE id=?", (value.scope_id,))
        assert scope_row is not None
        task_id = str(uuid.uuid4())
        try:
            assigned = self.skills.assignments(value.intent)
        except ValueError as exc:
            raise TaskStateError(str(exc)) from exc
        plan = self._compile_plan(task_id, value, target, scope_row)
        now = datetime.now(UTC).isoformat()
        self.db.execute(
            """INSERT INTO tasks(id,title,target,intent,indicators_json,scope_id,status,approval_status,
               approved_by,approved_at,approval_reason,scope_hash,created_by,assigned_skills_json,plan_json,
               result_json,error,created_at,updated_at)
               VALUES(?,?,?,?,?,?,'pending_approval','pending',NULL,NULL,NULL,?,?,?, ?,NULL,NULL,?,?)""",
            (
                task_id,
                value.title,
                value.target,
                value.intent,
                json.dumps(value.indicators, ensure_ascii=False),
                value.scope_id,
                scope_row["scope_hash"],
                principal.id,
                json.dumps(assigned),
                json.dumps(plan, ensure_ascii=False),
                now,
                now,
            ),
        )
        self._event(
            task_id,
            "task.created",
            {"status": "pending_approval", "scope_hash": scope_row["scope_hash"]},
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
            },
        )
        return self.get(task_id)

    @staticmethod
    def _compile_plan(
        task_id: str, value: TaskCreate, target: Any, scope_row: Any
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
            "version": "1.0",
            "task_id": task_id,
            "destructive": False,
            "objectives": [
                "revalidate authorization scope",
                "collect non-destructive reachability evidence",
                "compare evidence with explicit indicators",
                "produce a defensive report",
            ],
            "dag": [
                {"id": "scope", "skill": "scope.check", "depends_on": []},
                {"id": "probe", "skill": "asset.safe_probe", "depends_on": ["scope"]},
                {"id": "evaluate", "skill": "validation.safe_check", "depends_on": ["probe"]},
                {"id": "report", "skill": "report.generate", "depends_on": ["evaluate"]},
            ],
            "steps": steps,
            "rollback": [
                "no target mutation is performed",
                "discard the per-task temporary workspace",
            ],
            "safety": {
                "forbidden": [
                    "persistence",
                    "evasion",
                    "credential access",
                    "destructive payloads",
                    "scope expansion",
                ],
                "approval_required": True,
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
        now = datetime.now(UTC).isoformat()
        status = "approved" if approved else "cancelled"
        approval_status = "approved" if approved else "rejected"
        count, _ = self.db.execute(
            """UPDATE tasks SET status=?,approval_status=?,approved_by=?,approved_at=?,approval_reason=?,updated_at=?
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
            details={
                "reason": reason,
                "scope_hash": task["scope_hash"],
            },
        )
        return self.get(task_id)

    async def run(self, principal: Principal, task_id: str) -> dict[str, Any]:
        if not bool(self.audit.verify()["valid"]):
            raise TaskStateError("audit integrity check failed; execution is blocked")
        lock = self._locks.setdefault(task_id, asyncio.Lock())
        async with lock, self._semaphore:
            task = self.db.fetch_one("SELECT * FROM tasks WHERE id=?", (task_id,))
            if task is None:
                raise KeyError("task not found")
            if task["status"] != "approved" or task["approval_status"] != "approved":
                raise TaskStateError("task must be approved before execution")
            try:
                self.skills.assert_enabled(json.loads(task["assigned_skills_json"]))
            except ValueError as exc:
                raise TaskStateError(str(exc)) from exc
            scope_row = self.db.fetch_one("SELECT * FROM scopes WHERE id=?", (task["scope_id"],))
            if (
                scope_row is None
                or task["scope_hash"] != scope_row["scope_hash"]
                or task["scope_hash"] != row_scope_hash(scope_row)
            ):
                raise ScopeViolation("scope signature no longer matches the approved task")
            self.scope.validate(task["target"], task["scope_id"])
            now = datetime.now(UTC).isoformat()
            changed, _ = self.db.execute(
                "UPDATE tasks SET status='running',updated_at=? WHERE id=? AND status='approved'",
                (now, task_id),
            )
            if changed != 1:
                raise TaskStateError("task is already running or changed state")
            cancel_event = self._cancel.setdefault(task_id, asyncio.Event())
            self._event(task_id, "task.running", {"actor": principal.id})
            self.audit.record(
                principal.id,
                "task.execute.start",
                "task",
                task_id,
                details={
                    "scope_hash": task["scope_hash"],
                    "plan_version": "1.0",
                },
            )
            try:
                plan = json.loads(task["plan_json"])
                evidence: list[dict[str, Any]] = []
                for index, step in enumerate(plan["steps"]):
                    if cancel_event.is_set():
                        raise asyncio.CancelledError()
                    # Revalidate immediately before every network side effect.
                    self.scope.validate(task["target"], task["scope_id"], [step["port"]])
                    if step["kind"] == "tcp_connect":
                        item = await self.scope.probe(
                            task["target"], task["scope_id"], [step["port"]], 1.5
                        )
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
                        item["indicator_matched"] = bool(
                            pattern and pattern.lower() in body.lower()
                        )
                        item["expected_status_matched"] = item.get("status") in step.get(
                            "expected_status", []
                        )
                    else:
                        item = {"kind": step["kind"], "skipped": True}
                    evidence.append({"step": index, "kind": step["kind"], "evidence": item})
                    self._event(
                        task_id, "task.step.completed", {"step": index, "kind": step["kind"]}
                    )
                if task["intent"] == "asset_inventory":
                    validation_signal = any(
                        any(
                            result.get("status") == "open"
                            for result in item["evidence"].get("results", [])
                        )
                        for item in evidence
                    )
                elif json.loads(task["indicators_json"]):
                    validation_signal = any(
                        item["evidence"].get("indicator_matched", False) for item in evidence
                    )
                else:
                    # A vulnerability claim needs an explicit success criterion. Reachability
                    # alone is retained as evidence but never promoted to a vulnerability signal.
                    validation_signal = False
                result = {
                    "outcome": "evidence_collected",
                    "validation_signal": validation_signal,
                    "non_destructive": True,
                    "evidence": evidence,
                    "limitations": "Reachability or an indicator match is evidence, not proof of exploitability.",
                }
                finished = datetime.now(UTC).isoformat()
                changed, _ = self.db.execute(
                    """UPDATE tasks SET status='succeeded',result_json=?,error=NULL,updated_at=?
                       WHERE id=? AND status='running'""",
                    (json.dumps(result, ensure_ascii=False), finished, task_id),
                )
                if changed != 1:
                    raise asyncio.CancelledError()
                self._event(task_id, "task.succeeded", {"validation_signal": validation_signal})
                self.audit.record(
                    principal.id,
                    "task.execute.finish",
                    "task",
                    task_id,
                    details={
                        "outcome": "succeeded",
                        "validation_signal": validation_signal,
                        "evidence_count": len(evidence),
                    },
                )
            except asyncio.CancelledError:
                self.db.execute(
                    "UPDATE tasks SET status='cancelled',error='cancelled',updated_at=? WHERE id=? AND status='running'",
                    (datetime.now(UTC).isoformat(), task_id),
                )
                self._event(task_id, "task.cancelled", {})
                self.audit.record(
                    principal.id, "task.execute.finish", "task", task_id, "cancelled", {}
                )
            except Exception as exc:
                self.db.execute(
                    "UPDATE tasks SET status='failed',error=?,updated_at=? WHERE id=? AND status='running'",
                    (
                        f"{type(exc).__name__}: {str(exc)[:500]}",
                        datetime.now(UTC).isoformat(),
                        task_id,
                    ),
                )
                self._event(task_id, "task.failed", {"error_type": type(exc).__name__})
                self.audit.record(
                    principal.id,
                    "task.execute.finish",
                    "task",
                    task_id,
                    "failure",
                    {
                        "error_type": type(exc).__name__,
                    },
                )
            finally:
                self._cancel.pop(task_id, None)
            return self.get(task_id)

    def cancel(self, principal: Principal, task_id: str) -> dict[str, Any]:
        task = self.db.fetch_one("SELECT * FROM tasks WHERE id=?", (task_id,))
        if task is None:
            raise KeyError("task not found")
        if task["status"] in TERMINAL_STATES:
            return serialize_task(task)
        if task["status"] == "running":
            self._cancel.setdefault(task_id, asyncio.Event()).set()
        else:
            self.db.execute(
                "UPDATE tasks SET status='cancelled',updated_at=? WHERE id=? AND status NOT IN ('succeeded','failed','cancelled')",
                (datetime.now(UTC).isoformat(), task_id),
            )
        self._event(task_id, "task.cancel.requested", {"actor": principal.id})
        self.audit.record(principal.id, "task.cancel", "task", task_id)
        return self.get(task_id)

    def get(self, task_id: str) -> dict[str, Any]:
        row = self.db.fetch_one("SELECT * FROM tasks WHERE id=?", (task_id,))
        if row is None:
            raise KeyError("task not found")
        return serialize_task(row)

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
