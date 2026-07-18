from __future__ import annotations

import asyncio
import hashlib
import json
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from .audit import AuditService
from .config import Settings
from .db import Database
from .evidence import EvidenceService
from .policy import PolicyDenied, PolicyService
from .schemas import EvidenceCreate, PolicyEvaluationRequest, Role
from .scope import ScopeService, ScopeViolation
from .security import Principal
from .validation_evidence_store import EvidenceStore, EvidenceStoreError
from .validation_queue import VALIDATION_QUEUE_SUBJECT, ValidationQueue, ValidationQueueMessage
from .validation_sandbox import (
    HttpResponseSandboxRequest,
    SandboxBackend,
    ValidationSandboxError,
    ValidationSandboxResourceExceeded,
)

QUEUE_SUBJECT = VALIDATION_QUEUE_SUBJECT
REPOSITORY_ROOT = Path(__file__).resolve().parents[4]
TERMINAL_STATUSES = frozenset(
    {
        "SUCCEEDED",
        "FAILED",
        "CANCELLED",
        "EXPIRED",
        "POLICY_REJECTED",
        "APPROVAL_REVOKED",
        "SCOPE_INVALID",
        "SANDBOX_FAILED",
        "RESOURCE_EXCEEDED",
        "EXECUTION_TIMEOUT",
        "EVIDENCE_INCOMPLETE",
    }
)


class ValidationExecutionStateError(ValueError):
    pass


class ValidationTemplateError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class ValidationTemplate:
    id: str
    version: str
    name: str
    description: str
    risk_level: str
    enabled: bool
    input_schema: dict[str, Any]
    output_schema: dict[str, Any]
    timeout_seconds: float
    sandbox: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "version": self.version,
            "name": self.name,
            "description": self.description,
            "risk_level": self.risk_level,
            "enabled": self.enabled,
            "input_schema": self.input_schema,
            "output_schema": self.output_schema,
            "timeout_seconds": self.timeout_seconds,
            "sandbox": self.sandbox,
        }


TEMPLATES: dict[str, ValidationTemplate] = {
    "http.response": ValidationTemplate(
        id="http.response",
        version="1.0.0",
        name="HTTP response characteristic validation",
        description="Performs a bounded HEAD/GET request against an approved HTTP target and checks status/body assertions.",
        risk_level="low",
        enabled=True,
        input_schema={
            "type": "object",
            "required": ["kind", "host", "port", "method", "path"],
            "properties": {
                "kind": {"const": "http_request"},
                "host": {"type": "string", "minLength": 1, "maxLength": 255},
                "port": {"type": "integer", "minimum": 1, "maximum": 65535},
                "method": {"enum": ["HEAD", "GET"]},
                "path": {"type": "string", "pattern": "^/"},
                "expected_status": {
                    "type": "array",
                    "items": {"type": "integer", "minimum": 100, "maximum": 599},
                    "maxItems": 16,
                },
                "body_pattern": {"type": ["string", "null"], "maxLength": 256},
            },
            "additionalProperties": False,
        },
        output_schema={
            "type": "object",
            "required": ["matched", "observed"],
            "properties": {
                "matched": {"type": "boolean"},
                "observed": {"type": "object"},
                "assertions": {"type": "object"},
            },
        },
        timeout_seconds=8.0,
        sandbox={
            "mode": "docker-required-in-production",
            "non_root": True,
            "privileged": False,
            "host_network": False,
            "docker_socket": False,
            "cpu": "0.5",
            "memory": "256m",
            "pids_limit": 64,
            "read_only_rootfs": True,
            "cap_drop": ["ALL"],
            "no_new_privileges": True,
            "default_internet": "deny",
        },
    ),
    "sbom.dependency-version": ValidationTemplate(
        id="sbom.dependency-version",
        version="1.0.0",
        name="SBOM dependency version evidence validation",
        description="Collects fixed project manifest and lockfile evidence without executing package manager commands.",
        risk_level="low",
        enabled=True,
        input_schema={
            "type": "object",
            "properties": {
                "package_json": {"const": "package.json"},
                "pnpm_lock": {"const": "pnpm-lock.yaml"},
                "requirements_lock": {"const": "requirements.lock"},
            },
            "additionalProperties": False,
        },
        output_schema={
            "type": "object",
            "required": ["matched", "observed"],
            "properties": {
                "matched": {"type": "boolean"},
                "observed": {"type": "object"},
            },
        },
        timeout_seconds=5.0,
        sandbox={
            "mode": "metadata-only",
            "executes_shell": False,
            "network": "none",
            "artifact_sources": ["package.json", "pnpm-lock.yaml", "requirements.lock"],
        },
    ),
    "local.training-lab": ValidationTemplate(
        id="local.training-lab",
        version="1.0.0",
        name="Fixed local training lab validation",
        description="Validates the repository-owned synthetic lab fixture and Dockerfile safety markers.",
        risk_level="low",
        enabled=True,
        input_schema={
            "type": "object",
            "properties": {
                "lab_app": {"const": "lab/app.py"},
                "lab_dockerfile": {"const": "lab/Dockerfile"},
            },
            "additionalProperties": False,
        },
        output_schema={
            "type": "object",
            "required": ["matched", "observed"],
            "properties": {
                "matched": {"type": "boolean"},
                "observed": {"type": "object"},
            },
        },
        timeout_seconds=5.0,
        sandbox={
            "mode": "fixed-local-fixture",
            "executes_shell": False,
            "network": "none",
            "artifact_sources": ["lab/app.py", "lab/Dockerfile"],
        },
    ),
}


def _now() -> str:
    return datetime.now(UTC).isoformat()


def _future(seconds: int) -> str:
    return (datetime.now(UTC) + timedelta(seconds=seconds)).isoformat()


def _json(value: str | None, default: Any) -> Any:
    if value is None or value == "":
        return default
    return json.loads(value)


def _digest(value: Any) -> str:
    return hashlib.sha256(
        json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


class ValidationExecutionService:
    def __init__(
        self,
        db: Database,
        settings: Settings,
        scope: ScopeService,
        evidence: EvidenceService,
        policy: PolicyService,
        audit: AuditService,
        queue: ValidationQueue,
        sandbox_backend: SandboxBackend,
        evidence_store: EvidenceStore,
    ):
        self.db = db
        self.settings = settings
        self.scope = scope
        self.evidence = evidence
        self.policy = policy
        self.audit = audit
        self.queue = queue
        self.sandbox_backend = sandbox_backend
        self.evidence_store = evidence_store

    @staticmethod
    def templates() -> list[dict[str, Any]]:
        return [template.to_dict() for template in TEMPLATES.values()]

    @staticmethod
    def template(template_id: str) -> dict[str, Any]:
        template = TEMPLATES.get(template_id)
        if template is None:
            raise KeyError("validation template not found")
        return template.to_dict()

    @staticmethod
    def _execution_row(row: Any) -> dict[str, Any]:
        return {
            "id": row["id"],
            "plan_id": row["plan_id"],
            "task_id": row["task_id"],
            "tenant_id": row["tenant_id"],
            "template_id": row["template_id"],
            "template_version": row["template_version"],
            "status": row["status"],
            "trace_id": row["trace_id"],
            "sandbox_id": row["sandbox_id"],
            "approval_id": row["approval_id"],
            "policy_decision_id": row["policy_decision_id"],
            "idempotency_key": row["idempotency_key"],
            "queue_message_id": row["queue_message_id"],
            "result": _json(row["result_json"], {}),
            "error": row["error"],
            "review_decision": row["review_decision"],
            "review_reason": row["review_reason"],
            "reviewed_by": row["reviewed_by"],
            "reviewed_at": row["reviewed_at"],
            "retry_of": row["retry_of"],
            "created_by": row["created_by"],
            "started_at": row["started_at"],
            "finished_at": row["finished_at"],
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
        }

    @staticmethod
    def _event_row(row: Any) -> dict[str, Any]:
        return {
            "id": int(row["id"]),
            "execution_id": row["execution_id"],
            "event_type": row["event_type"],
            "status": row["status"],
            "payload": _json(row["payload_json"], {}),
            "created_at": row["created_at"],
        }

    @staticmethod
    def _evidence_row(row: Any) -> dict[str, Any]:
        return {
            "id": row["id"],
            "execution_id": row["execution_id"],
            "task_id": row["task_id"],
            "evidence_item_id": row["evidence_item_id"],
            "title": row["title"],
            "artifact_ref": row["artifact_ref"],
            "content_sha256": row["content_sha256"],
            "metadata": _json(row["metadata_json"], {}),
            "created_at": row["created_at"],
        }

    @staticmethod
    def _template_input(plan: dict[str, Any], template_id: str | None = None) -> dict[str, Any]:
        selected_template = template_id or "http.response"
        template = TEMPLATES.get(selected_template)
        if template is None or not template.enabled:
            raise ValidationTemplateError("unknown or disabled validation template")
        if template.id == "sbom.dependency-version":
            return {
                "kind": "sbom_metadata",
                "template_id": template.id,
                "template_version": template.version,
            }
        if template.id == "local.training-lab":
            return {
                "kind": "local_training_lab",
                "template_id": template.id,
                "template_version": template.version,
            }
        for step in plan.get("steps", []):
            if step.get("kind") == "http_request":
                method = step.get("method") or "GET"
                path = step.get("path") or "/"
                return {
                    **step,
                    "method": method,
                    "path": path,
                    "template_id": template.id,
                    "template_version": template.version,
                }
        raise ValidationTemplateError(
            "approved validation plan does not contain an HTTP response template step"
        )

    def _principal_for_user(self, user_id: str) -> Principal:
        row = self.db.fetch_one("SELECT id,username,role FROM users WHERE id=?", (user_id,))
        if row is None:
            raise KeyError("execution owner no longer exists")
        return Principal(id=row["id"], username=row["username"], role=Role(row["role"]))

    def _record_event(
        self,
        execution_id: str,
        event_type: str,
        status: str,
        payload: dict[str, Any],
        connection: Any | None = None,
    ) -> None:
        params = (
            execution_id,
            event_type,
            status,
            json.dumps(payload, ensure_ascii=False, sort_keys=True),
            _now(),
        )
        sql = """INSERT INTO validation_execution_events(
                 execution_id,event_type,status,payload_json,created_at
                 ) VALUES(?,?,?,?,?)"""
        if connection is not None:
            connection.execute(sql, params)
            return
        self.db.execute(sql, params)

    def _set_status(
        self,
        execution_id: str,
        status: str,
        event_type: str,
        payload: dict[str, Any] | None = None,
        *,
        error: str | None = None,
        result: dict[str, Any] | None = None,
        policy_decision_id: str | None = None,
    ) -> None:
        payload = payload or {}
        now = _now()
        finished_at = now if status in TERMINAL_STATUSES else None
        started_at_sql = ",started_at=COALESCE(started_at,?)" if status == "RUNNING" else ""
        finished_at_sql = ",finished_at=?" if finished_at else ""
        result_sql = ",result_json=?" if result is not None else ""
        policy_sql = ",policy_decision_id=?" if policy_decision_id is not None else ""
        lease_sql = (
            ",lease_owner=NULL,lease_token=NULL,lease_expires_at=NULL"
            if status in TERMINAL_STATUSES
            else ""
        )
        params: list[Any] = [status, now]
        if status == "RUNNING":
            params.append(now)
        if finished_at:
            params.append(finished_at)
        if result is not None:
            params.append(json.dumps(result, ensure_ascii=False, sort_keys=True))
        if policy_decision_id is not None:
            params.append(policy_decision_id)
        params.extend([error, execution_id])
        with self.db.transaction() as connection:
            connection.execute(
                f"""UPDATE validation_executions
                    SET status=?,updated_at=?{started_at_sql}{finished_at_sql}{result_sql}{policy_sql}{lease_sql},
                        error=COALESCE(?, error)
                    WHERE id=?""",
                tuple(params),
            )
            self._record_event(execution_id, event_type, status, payload, connection)

    def _authorize_create(
        self, principal: Principal, plan_row: Any, task_row: Any, step: dict[str, Any]
    ) -> dict[str, Any]:
        if step["template_id"] == "http.response":
            target = f"http://{step['host']}:{step['port']}"
            ports = [int(step["port"])]
        else:
            target = task_row["target"]
            parsed = self.scope.validate(target, task_row["scope_id"])
            ports = [parsed.port] if parsed.port is not None else []
        return self.policy.enforce(
            principal,
            PolicyEvaluationRequest(
                action="validation.execute",
                resource_type="validation_execution",
                resource_id=plan_row["id"],
                task_id=task_row["id"],
                scope_id=task_row["scope_id"],
                target=target,
                ports=ports,
                metadata={
                    "template_id": step["template_id"],
                    "template_version": step["template_version"],
                    "plan_id": plan_row["id"],
                },
            ),
        )

    def create(
        self,
        principal: Principal,
        plan_id: str,
        *,
        idempotency_key: str | None,
        template_id: str | None = None,
        request_id: str | None = None,
    ) -> dict[str, Any]:
        if not idempotency_key or len(idempotency_key) > 200:
            raise ValidationExecutionStateError(
                "Idempotency-Key is required and must be at most 200 characters"
            )
        plan_row = self.db.fetch_one("SELECT * FROM validation_plans WHERE id=?", (plan_id,))
        if plan_row is None:
            raise KeyError("validation plan not found")
        if plan_row["status"] != "approved":
            raise ValidationExecutionStateError("only approved validation plans can be executed")
        task_row = self.db.fetch_one("SELECT * FROM tasks WHERE id=?", (plan_row["task_id"],))
        if task_row is None:
            raise KeyError("task not found")
        plan = json.loads(plan_row["plan_json"])
        step = self._template_input(plan, template_id)
        request_hash = _digest(
            {
                "plan_id": plan_id,
                "plan_hash": plan_row["plan_hash"],
                "template_id": step["template_id"],
                "template_version": step["template_version"],
            }
        )
        existing = self.db.fetch_one(
            """SELECT * FROM task_idempotency_records
               WHERE principal_id=? AND operation='validation_execution.create'
                 AND idempotency_key=?""",
            (principal.id, idempotency_key),
        )
        if existing is not None:
            if existing["request_hash"] != request_hash:
                raise ValidationExecutionStateError(
                    "Idempotency-Key was reused with a different validation request"
                )
            if existing["resource_id"]:
                return self.get(existing["resource_id"])
            raise ValidationExecutionStateError("idempotent validation request is still processing")

        decision = self._authorize_create(principal, plan_row, task_row, step)
        execution_id = str(uuid.uuid4())
        queue_id = str(uuid.uuid4())
        message_id = str(uuid.uuid4())
        trace_id = uuid.uuid4().hex
        sandbox_id = f"vlsbx-{uuid.uuid4().hex[:20]}"
        approval_id = f"validation-plan:{plan_id}:{plan_row['reviewed_at']}"
        now = _now()
        queue_subject = self.settings.nats_subject or QUEUE_SUBJECT
        payload = {
            "schema_version": self.settings.validation_message_schema_version,
            "message_id": message_id,
            "queue_message_id": queue_id,
            "execution_id": execution_id,
            "tenant_id": task_row["created_by"],
            "plan_id": plan_id,
            "task_id": task_row["id"],
            "template_id": step["template_id"],
            "template_version": step["template_version"],
            "trace_id": trace_id,
            "request_id": request_id or str(uuid.uuid4()),
            "sandbox_id": sandbox_id,
            "approval_id": approval_id,
            "policy_decision_id": decision["id"],
        }
        response_snapshot: dict[str, Any] | None = None
        with self.db.transaction() as connection:
            connection.execute(
                """INSERT INTO validation_executions(
                   id,plan_id,task_id,tenant_id,template_id,template_version,status,
                   trace_id,sandbox_id,approval_id,policy_decision_id,idempotency_key,
                   queue_message_id,result_json,error,review_decision,review_reason,reviewed_by,
                   reviewed_at,retry_of,created_by,started_at,finished_at,created_at,updated_at
                   ) VALUES(?,?,?,?,?,?,'QUEUED',?,?,?,?,?,?,?,NULL,NULL,NULL,NULL,NULL,NULL,?,
                   NULL,NULL,?,?)""",
                (
                    execution_id,
                    plan_id,
                    task_row["id"],
                    task_row["created_by"],
                    step["template_id"],
                    step["template_version"],
                    trace_id,
                    sandbox_id,
                    approval_id,
                    decision["id"],
                    idempotency_key,
                    queue_id,
                    "{}",
                    principal.id,
                    now,
                    now,
                ),
            )
            connection.execute(
                """INSERT INTO validation_queue_messages(
                   id,execution_id,message_id,subject,schema_version,status,attempt,
                   max_attempts,available_at,
                   locked_by,lock_token,locked_until,last_error,payload_json,created_at,updated_at
                   ) VALUES(?,?,?,?,?,'ready',0,3,?,NULL,NULL,NULL,NULL,?,?,?)""",
                (
                    queue_id,
                    execution_id,
                    message_id,
                    queue_subject,
                    self.settings.validation_message_schema_version,
                    now,
                    json.dumps(payload, ensure_ascii=False, sort_keys=True),
                    now,
                    now,
                ),
            )
            self._record_event(
                execution_id,
                "validation_execution.queued",
                "QUEUED",
                {
                    "message_id": message_id,
                    "subject": queue_subject,
                    "schema_version": self.settings.validation_message_schema_version,
                    "trace_id": trace_id,
                    "request_id": payload["request_id"],
                    "sandbox_id": sandbox_id,
                    "approval_id": approval_id,
                    "policy_decision_id": decision["id"],
                },
                connection,
            )
            connection.execute(
                """INSERT INTO task_idempotency_records(
                   id,principal_id,operation,idempotency_key,request_hash,response_json,
                   resource_type,resource_id,status,expires_at,created_at,updated_at
                   ) VALUES(?,?,?,?,?,NULL,'validation_execution',?,'completed',?,?,?)""",
                (
                    str(uuid.uuid4()),
                    principal.id,
                    "validation_execution.create",
                    idempotency_key,
                    request_hash,
                    execution_id,
                    _future(86400),
                    now,
                    now,
                ),
            )
        response_snapshot = self.get(execution_id)
        self.db.execute(
            """UPDATE task_idempotency_records
               SET response_json=?,updated_at=?
               WHERE principal_id=? AND operation='validation_execution.create'
                 AND idempotency_key=?""",
            (
                json.dumps(response_snapshot, ensure_ascii=False, sort_keys=True),
                _now(),
                principal.id,
                idempotency_key,
            ),
        )
        self.audit.record(
            principal.id,
            "validation_execution.create",
            "validation_plan",
            plan_id,
            details={
                "execution_id": execution_id,
                "trace_id": trace_id,
                "sandbox_id": sandbox_id,
                "approval_id": approval_id,
                "policy_decision_id": decision["id"],
                "queue_subject": queue_subject,
            },
        )
        return response_snapshot

    def _create_retry(
        self,
        principal: Principal,
        original: dict[str, Any],
    ) -> dict[str, Any]:
        plan_row = self.db.fetch_one(
            "SELECT * FROM validation_plans WHERE id=?", (original["plan_id"],)
        )
        if plan_row is None:
            raise KeyError("validation plan not found")
        if plan_row["status"] != "approved":
            raise ValidationExecutionStateError(
                "only executions with still-approved plans can be retried"
            )
        task_row = self.db.fetch_one("SELECT * FROM tasks WHERE id=?", (original["task_id"],))
        if task_row is None:
            raise KeyError("task not found")
        step = self._template_input(json.loads(plan_row["plan_json"]), original["template_id"])
        decision = self._authorize_create(principal, plan_row, task_row, step)
        execution_id = str(uuid.uuid4())
        queue_id = str(uuid.uuid4())
        message_id = str(uuid.uuid4())
        trace_id = uuid.uuid4().hex
        sandbox_id = f"vlsbx-{uuid.uuid4().hex[:20]}"
        approval_id = f"validation-plan:{plan_row['id']}:{plan_row['reviewed_at']}"
        now = _now()
        queue_subject = self.settings.nats_subject or QUEUE_SUBJECT
        payload = {
            "schema_version": self.settings.validation_message_schema_version,
            "message_id": message_id,
            "queue_message_id": queue_id,
            "execution_id": execution_id,
            "tenant_id": task_row["created_by"],
            "plan_id": plan_row["id"],
            "task_id": task_row["id"],
            "template_id": step["template_id"],
            "template_version": step["template_version"],
            "trace_id": trace_id,
            "request_id": str(uuid.uuid4()),
            "sandbox_id": sandbox_id,
            "approval_id": approval_id,
            "policy_decision_id": decision["id"],
            "retry_of": original["id"],
        }
        with self.db.transaction() as connection:
            connection.execute(
                """INSERT INTO validation_executions(
                   id,plan_id,task_id,tenant_id,template_id,template_version,status,
                   trace_id,sandbox_id,approval_id,policy_decision_id,idempotency_key,
                   queue_message_id,result_json,error,review_decision,review_reason,reviewed_by,
                   reviewed_at,retry_of,created_by,started_at,finished_at,created_at,updated_at
                   ) VALUES(?,?,?,?,?,?,'QUEUED',?,?,?,?,NULL,?, '{}', NULL,NULL,NULL,NULL,NULL,?,
                   ?,NULL,NULL,?,?)""",
                (
                    execution_id,
                    plan_row["id"],
                    task_row["id"],
                    task_row["created_by"],
                    step["template_id"],
                    step["template_version"],
                    trace_id,
                    sandbox_id,
                    approval_id,
                    decision["id"],
                    queue_id,
                    original["id"],
                    principal.id,
                    now,
                    now,
                ),
            )
            connection.execute(
                """INSERT INTO validation_queue_messages(
                   id,execution_id,message_id,subject,schema_version,status,attempt,
                   max_attempts,available_at,
                   locked_by,lock_token,locked_until,last_error,payload_json,created_at,updated_at
                   ) VALUES(?,?,?,?,?,'ready',0,3,?,NULL,NULL,NULL,NULL,?,?,?)""",
                (
                    queue_id,
                    execution_id,
                    message_id,
                    queue_subject,
                    self.settings.validation_message_schema_version,
                    now,
                    json.dumps(payload, ensure_ascii=False, sort_keys=True),
                    now,
                    now,
                ),
            )
            self._record_event(
                execution_id,
                "validation_execution.retry_queued",
                "QUEUED",
                {
                    "retry_of": original["id"],
                    "message_id": message_id,
                    "schema_version": self.settings.validation_message_schema_version,
                    "trace_id": trace_id,
                    "request_id": payload["request_id"],
                },
                connection,
            )
        self.audit.record(
            principal.id,
            "validation_execution.retry",
            "validation_execution",
            original["id"],
            details={"new_execution_id": execution_id},
        )
        return self.get(execution_id)

    def list_executions(
        self,
        principal: Principal,
        *,
        limit: int = 100,
        status: str | None = None,
        task_id: str | None = None,
    ) -> list[dict[str, Any]]:
        clauses = []
        params: list[Any] = []
        if principal.role.value != "admin":
            clauses.append("t.created_by=?")
            params.append(principal.id)
        if status:
            clauses.append("e.status=?")
            params.append(status)
        if task_id:
            clauses.append("e.task_id=?")
            params.append(task_id)
        where = "WHERE " + " AND ".join(clauses) if clauses else ""
        rows = self.db.fetch_all(
            f"""SELECT e.* FROM validation_executions e
                JOIN tasks t ON t.id=e.task_id
                {where}
                ORDER BY e.created_at DESC,e.id DESC LIMIT ?""",
            (*params, min(max(limit, 1), 500)),
        )
        return [self._execution_row(row) for row in rows]

    def get(self, execution_id: str) -> dict[str, Any]:
        row = self.db.fetch_one("SELECT * FROM validation_executions WHERE id=?", (execution_id,))
        if row is None:
            raise KeyError("validation execution not found")
        return self._execution_row(row)

    def events(
        self, execution_id: str, *, after_id: int = 0, limit: int = 500
    ) -> list[dict[str, Any]]:
        rows = self.db.fetch_all(
            """SELECT * FROM validation_execution_events
               WHERE execution_id=? AND id>? ORDER BY id LIMIT ?""",
            (execution_id, max(after_id, 0), min(max(limit, 1), 1000)),
        )
        return [self._event_row(row) for row in rows]

    def evidence_items(self, execution_id: str, *, limit: int = 200) -> list[dict[str, Any]]:
        rows = self.db.fetch_all(
            """SELECT * FROM validation_execution_evidence
               WHERE execution_id=? ORDER BY created_at DESC,id DESC LIMIT ?""",
            (execution_id, min(max(limit, 1), 500)),
        )
        return [self._evidence_row(row) for row in rows]

    def cancel(
        self, principal: Principal, execution_id: str, reason: str | None = None
    ) -> dict[str, Any]:
        execution = self.get(execution_id)
        if execution["status"] in TERMINAL_STATUSES:
            return execution
        now = _now()
        with self.db.transaction() as connection:
            connection.execute(
                """UPDATE validation_executions
                   SET status='CANCELLED',error=?,finished_at=?,updated_at=?
                   WHERE id=? AND status NOT IN (
                       'SUCCEEDED','FAILED','CANCELLED','EXPIRED','POLICY_REJECTED',
                       'APPROVAL_REVOKED','SCOPE_INVALID','SANDBOX_FAILED','RESOURCE_EXCEEDED',
                       'EXECUTION_TIMEOUT','EVIDENCE_INCOMPLETE'
                   )""",
                (reason or "cancelled by operator", now, now, execution_id),
            )
            connection.execute(
                """UPDATE validation_queue_messages
                   SET status='cancelled',updated_at=?
                   WHERE execution_id=? AND status IN ('ready','leased')""",
                (now, execution_id),
            )
            self._record_event(
                execution_id,
                "validation_execution.cancelled",
                "CANCELLED",
                {"reason": reason or "cancelled by operator"},
                connection,
            )
        self.audit.record(
            principal.id,
            "validation_execution.cancel",
            "validation_execution",
            execution_id,
            details={"reason": reason},
        )
        self.queue.cancel_execution(execution_id)
        return self.get(execution_id)

    def retry(self, principal: Principal, execution_id: str) -> dict[str, Any]:
        execution = self.get(execution_id)
        if execution["status"] not in TERMINAL_STATUSES or execution["status"] == "SUCCEEDED":
            raise ValidationExecutionStateError(
                "only terminal non-succeeded executions can be retried"
            )
        return self._create_retry(principal, execution)

    def review(
        self,
        principal: Principal,
        execution_id: str,
        *,
        accepted: bool,
        reason: str,
    ) -> dict[str, Any]:
        if principal.role.value != "admin":
            raise PermissionError("only administrators can review validation executions")
        execution = self.get(execution_id)
        if execution["status"] not in TERMINAL_STATUSES:
            raise ValidationExecutionStateError(
                "only terminal validation executions can be reviewed"
            )
        now = _now()
        decision = "accepted" if accepted else "rejected"
        with self.db.transaction() as connection:
            connection.execute(
                """UPDATE validation_executions
                   SET review_decision=?,review_reason=?,reviewed_by=?,reviewed_at=?,updated_at=?
                   WHERE id=?""",
                (decision, reason, principal.id, now, now, execution_id),
            )
            self._record_event(
                execution_id,
                "validation_execution.reviewed",
                execution["status"],
                {"review_decision": decision, "reason": reason},
                connection,
            )
        self.audit.record(
            principal.id,
            "validation_execution.review",
            "validation_execution",
            execution_id,
            details={"review_decision": decision},
        )
        return self.get(execution_id)

    def _acquire_execution_lease(self, message: ValidationQueueMessage, worker_id: str) -> bool:
        now = _now()
        lease_token = message.lock_token or str(uuid.uuid4())
        with self.db.transaction() as connection:
            updated = connection.execute(
                f"""UPDATE validation_executions
                    SET lease_owner=?,lease_token=?,lease_expires_at=?,
                        worker_attempt=worker_attempt+1,updated_at=?
                    WHERE id=? AND status NOT IN ({",".join("?" for _ in TERMINAL_STATUSES)})
                      AND (lease_expires_at IS NULL OR lease_expires_at<=? OR lease_token=?)""",
                (
                    worker_id,
                    lease_token,
                    _future(self.settings.validation_queue_lease_seconds),
                    now,
                    message.execution_id,
                    *sorted(TERMINAL_STATUSES),
                    now,
                    lease_token,
                ),
            ).rowcount
            if updated == 1:
                self._record_event(
                    message.execution_id,
                    "validation_execution.lease_acquired",
                    "QUEUED",
                    {
                        "worker_id": worker_id,
                        "queue_message_id": message.id,
                        "message_id": message.message_id,
                        "redelivered": message.redelivered,
                    },
                    connection,
                )
        return updated == 1

    def run_worker_once(self, worker_id: str = "validation-worker") -> dict[str, Any] | None:
        message = self.queue.consume_once(worker_id)
        if message is None:
            return None
        execution = self.get(message.execution_id)
        if execution["status"] in TERMINAL_STATUSES:
            self.queue.complete(message.id)
            return execution
        if not self._acquire_execution_lease(message, worker_id):
            self.queue.retry(
                message.id, "execution lease is held by another worker", delay_seconds=1
            )
            return self.get(message.execution_id)
        try:
            result = self._execute(message)
        except Exception as exc:  # defensive final catch: the message is not lost.
            if message.attempt >= message.max_attempts:
                self._set_status(
                    message.execution_id,
                    "SANDBOX_FAILED",
                    "validation_execution.worker_failed",
                    {"error": type(exc).__name__},
                    error=str(exc),
                )
                self.queue.dead(message.id, str(exc))
            else:
                self.queue.retry(message.id, str(exc), delay_seconds=1)
            return self.get(message.execution_id)
        self.queue.complete(message.id)
        return result

    def dispatch_outbox_once(self) -> dict[str, Any] | None:
        return self.queue.dispatch_outbox_once()

    def _execute(self, message: ValidationQueueMessage) -> dict[str, Any]:
        if message.schema_version != self.settings.validation_message_schema_version:
            raise ValidationTemplateError("unsupported validation queue message schema version")
        execution = self.get(message.execution_id)
        if (
            message.payload.get("execution_id") != execution["id"]
            or message.payload.get("tenant_id") != execution["tenant_id"]
        ):
            self._set_status(
                execution["id"],
                "SCOPE_INVALID",
                "validation_execution.message_scope_invalid",
                {
                    "message_id": message.message_id,
                    "queue_message_id": message.id,
                    "payload_execution_id": message.payload.get("execution_id"),
                    "payload_tenant_id": message.payload.get("tenant_id"),
                },
                error="queue message payload does not match execution tenant/scope",
            )
            return self.get(execution["id"])
        template = TEMPLATES.get(execution["template_id"])
        if (
            template is None
            or not template.enabled
            or template.version != execution["template_version"]
        ):
            self._set_status(
                execution["id"],
                "POLICY_REJECTED",
                "validation_execution.template_rejected",
                {
                    "template_id": execution["template_id"],
                    "template_version": execution["template_version"],
                },
                error="validation template version is not registered or enabled",
            )
            return self.get(execution["id"])
        principal = self._principal_for_user(execution["created_by"])
        plan_row = self.db.fetch_one(
            "SELECT * FROM validation_plans WHERE id=?", (execution["plan_id"],)
        )
        if plan_row is None or plan_row["status"] != "approved":
            self._set_status(
                execution["id"],
                "APPROVAL_REVOKED",
                "validation_execution.approval_revoked",
                {"plan_id": execution["plan_id"]},
                error="validation plan approval is not current",
            )
            return self.get(execution["id"])
        task_row = self.db.fetch_one("SELECT * FROM tasks WHERE id=?", (execution["task_id"],))
        if task_row is None:
            self._set_status(
                execution["id"],
                "SCOPE_INVALID",
                "validation_execution.task_missing",
                {"task_id": execution["task_id"]},
                error="task not found",
            )
            return self.get(execution["id"])
        try:
            step = self._template_input(json.loads(plan_row["plan_json"]), execution["template_id"])
            decision = self._authorize_create(principal, plan_row, task_row, step)
        except ValidationTemplateError as exc:
            self._set_status(
                execution["id"],
                "POLICY_REJECTED",
                "validation_execution.template_rejected",
                {"template_id": execution["template_id"]},
                error=str(exc),
            )
            return self.get(execution["id"])
        except PolicyDenied as exc:
            self._set_status(
                execution["id"],
                "POLICY_REJECTED",
                "validation_execution.policy_rejected",
                {"reason": str(exc)},
                error=str(exc),
            )
            return self.get(execution["id"])

        self._set_status(
            execution["id"],
            "PROVISIONING",
            "validation_execution.provisioning",
            {
                "sandbox_id": execution["sandbox_id"],
                "sandbox": TEMPLATES[execution["template_id"]].sandbox,
                "sandbox_backend": self.sandbox_backend.describe(),
                "execution_mode": self.settings.execution_mode,
            },
            policy_decision_id=decision["id"],
        )
        self._set_status(
            execution["id"],
            "RUNNING",
            "validation_execution.running",
            {
                "template_id": execution["template_id"],
                "template_version": execution["template_version"],
            },
        )
        try:
            if execution["template_id"] == "http.response":
                result = self._run_http_response_template(execution, task_row, step, decision["id"])
            elif execution["template_id"] == "sbom.dependency-version":
                result = self._run_sbom_template(execution, decision["id"])
            elif execution["template_id"] == "local.training-lab":
                result = self._run_training_lab_template(execution, decision["id"])
            else:
                raise ValidationTemplateError("unknown validation template")
        except TimeoutError as exc:
            self._set_status(
                execution["id"],
                "EXECUTION_TIMEOUT",
                "validation_execution.timeout",
                {"template_id": execution["template_id"]},
                error=str(exc) or "execution timed out",
            )
            return self.get(execution["id"])
        except ValidationSandboxResourceExceeded as exc:
            self._set_status(
                execution["id"],
                "RESOURCE_EXCEEDED",
                "validation_execution.resource_exceeded",
                {"template_id": execution["template_id"]},
                error=str(exc),
            )
            return self.get(execution["id"])
        except ValidationSandboxError as exc:
            self._set_status(
                execution["id"],
                "SANDBOX_FAILED",
                "validation_execution.sandbox_failed",
                {"template_id": execution["template_id"]},
                error=str(exc),
            )
            return self.get(execution["id"])
        except ScopeViolation as exc:
            self._set_status(
                execution["id"],
                "SCOPE_INVALID",
                "validation_execution.scope_invalid",
                {"template_id": execution["template_id"]},
                error=str(exc),
            )
            return self.get(execution["id"])
        except ValidationTemplateError as exc:
            self._set_status(
                execution["id"],
                "POLICY_REJECTED",
                "validation_execution.template_rejected",
                {"template_id": execution["template_id"]},
                error=str(exc),
            )
            return self.get(execution["id"])

        matched = bool(result["matched"])
        self._set_status(
            execution["id"],
            "COLLECTING_EVIDENCE",
            "validation_execution.collecting_evidence",
            {"matched": matched},
        )
        try:
            evidence = self._store_evidence(principal, execution, task_row["id"], result)
        except EvidenceStoreError as exc:
            self._set_status(
                execution["id"],
                "EVIDENCE_INCOMPLETE",
                "validation_execution.evidence_store_failed",
                {"reason": type(exc).__name__},
                error=str(exc),
                result=result,
            )
            return self.get(execution["id"])
        if not evidence:
            self._set_status(
                execution["id"],
                "EVIDENCE_INCOMPLETE",
                "validation_execution.evidence_incomplete",
                {"reason": "no evidence persisted"},
                error="evidence incomplete",
                result=result,
            )
            return self.get(execution["id"])
        self._set_status(
            execution["id"],
            "VERIFYING",
            "validation_execution.verifying",
            {"evidence_id": evidence["id"], "content_sha256": evidence["content_sha256"]},
        )
        terminal = "SUCCEEDED" if matched else "FAILED"
        self._set_status(
            execution["id"],
            terminal,
            "validation_execution.completed",
            {"matched": matched, "evidence_id": evidence["id"]},
            error=None if matched else "validation assertions did not match observed evidence",
            result={**result, "evidence": evidence},
        )
        return self.get(execution["id"])

    def _base_result(
        self,
        execution: dict[str, Any],
        policy_decision_id: str,
        *,
        matched: bool,
        observed: dict[str, Any],
        assertions: dict[str, Any],
    ) -> dict[str, Any]:
        return {
            "matched": matched,
            "assertions": assertions,
            "observed": observed,
            "trace_id": execution["trace_id"],
            "execution_id": execution["id"],
            "sandbox_id": execution["sandbox_id"],
            "approval_id": execution["approval_id"],
            "policy_decision_id": policy_decision_id,
        }

    def _run_http_response_template(
        self,
        execution: dict[str, Any],
        task_row: Any,
        step: dict[str, Any],
        policy_decision_id: str,
    ) -> dict[str, Any]:
        timeout_seconds = min(
            self.settings.request_timeout_seconds,
            TEMPLATES[execution["template_id"]].timeout_seconds,
        )
        self.scope.validate(
            f"http://{step['host']}:{step['port']}",
            task_row["scope_id"],
            [int(step["port"])],
        )
        observed = asyncio.run(
            self.sandbox_backend.run_http_response(
                HttpResponseSandboxRequest(
                    sandbox_id=execution["sandbox_id"],
                    task_id=task_row["id"],
                    scope_id=task_row["scope_id"],
                    host=step["host"],
                    port=int(step["port"]),
                    method=step["method"],
                    path=step["path"],
                    timeout_seconds=timeout_seconds,
                )
            )
        )
        expected_status = [int(item) for item in step.get("expected_status", [])]
        observed_status = observed.get("status")
        status_ok = isinstance(observed_status, int) and (
            not expected_status or observed_status in set(expected_status)
        )
        body_pattern = step.get("body_pattern")
        body_ok = True
        if body_pattern:
            body_ok = body_pattern in str(observed.get("body", ""))
        matched = bool(status_ok and body_ok and "error" not in observed)
        return self._base_result(
            execution,
            policy_decision_id,
            matched=matched,
            observed=observed,
            assertions={
                "expected_status": expected_status,
                "status_ok": status_ok,
                "body_pattern": body_pattern,
                "body_ok": body_ok,
            },
        )

    def _file_digest(self, relative_path: str) -> dict[str, Any]:
        path = REPOSITORY_ROOT / relative_path
        if not path.is_file():
            return {"path": relative_path, "exists": False, "sha256": None, "size": 0}
        content = path.read_bytes()
        return {
            "path": relative_path,
            "exists": True,
            "sha256": hashlib.sha256(content).hexdigest(),
            "size": len(content),
        }

    def _run_sbom_template(
        self, execution: dict[str, Any], policy_decision_id: str
    ) -> dict[str, Any]:
        package_path = REPOSITORY_ROOT / "package.json"
        package_json = json.loads(package_path.read_text(encoding="utf-8"))
        manifests = [
            self._file_digest("package.json"),
            self._file_digest("pnpm-lock.yaml"),
            self._file_digest("requirements.lock"),
        ]
        observed = {
            "package_name": package_json.get("name"),
            "package_version": package_json.get("version"),
            "manifests": manifests,
            "dependency_evidence": {
                "pnpm_lock_present": manifests[1]["exists"],
                "requirements_lock_present": manifests[2]["exists"],
            },
            "non_executing": True,
        }
        matched = all(item["exists"] for item in manifests)
        return self._base_result(
            execution,
            policy_decision_id,
            matched=matched,
            observed=observed,
            assertions={
                "all_manifest_files_present": matched,
                "package_version_recorded": bool(package_json.get("version")),
                "no_package_manager_commands_executed": True,
            },
        )

    def _run_training_lab_template(
        self, execution: dict[str, Any], policy_decision_id: str
    ) -> dict[str, Any]:
        root = REPOSITORY_ROOT
        app_path = root / "lab" / "app.py"
        dockerfile_path = root / "lab" / "Dockerfile"
        app_text = app_path.read_text(encoding="utf-8") if app_path.is_file() else ""
        dockerfile_text = (
            dockerfile_path.read_text(encoding="utf-8") if dockerfile_path.is_file() else ""
        )
        files = [
            self._file_digest("lab/app.py"),
            self._file_digest("lab/Dockerfile"),
        ]
        markers = {
            "patched_marker": "PATCH_APPLIED" in app_text,
            "synthetic_marker": "VULNLAB_SYNTHETIC_FINDING" in app_text,
            "non_root_user": "USER labuser" in dockerfile_text,
            "fixed_port": "EXPOSE 8080" in dockerfile_text,
        }
        observed: dict[str, Any] = {
            "files": files,
            "markers": markers,
            "non_executing": True,
        }
        matched = all(markers.values()) and all(item["exists"] for item in files)
        return self._base_result(
            execution,
            policy_decision_id,
            matched=matched,
            observed=observed,
            assertions={
                "fixed_lab_fixture_present": matched,
                "no_lab_container_started": True,
                "dockerfile_declares_non_root_user": markers["non_root_user"],
            },
        )

    def _store_evidence(
        self,
        principal: Principal,
        execution: dict[str, Any],
        task_id: str,
        result: dict[str, Any],
    ) -> dict[str, Any] | None:
        evidence_id = str(uuid.uuid4())
        artifact_content = json.dumps(result, ensure_ascii=False, sort_keys=True, indent=2)
        stored = self.evidence_store.put_json(
            tenant_id=execution["tenant_id"],
            project_id=None,
            execution_id=execution["id"],
            evidence_id=evidence_id,
            content=artifact_content,
        )
        evidence_item = self.evidence.add(
            principal,
            task_id,
            EvidenceCreate(
                title=f"Validation execution {execution['id']} HTTP response evidence",
                source_type="task_output",
                source_ref=f"validation-execution://{execution['id']}",
                content=artifact_content,
                classification="internal",
                trust="system_observed",
                metadata={
                    "execution_id": execution["id"],
                    "trace_id": execution["trace_id"],
                    "sandbox_id": execution["sandbox_id"],
                    "artifact_ref": stored.artifact_ref,
                    "object_key": stored.object_key,
                    "local_artifact_path": stored.local_path,
                    "content_sha256": stored.content_sha256,
                    "object_size": stored.size,
                    "content_type": stored.content_type,
                    "object_store_mode": stored.backend,
                },
            ),
        )
        created_at = _now()
        metadata = {
            "trace_id": execution["trace_id"],
            "sandbox_id": execution["sandbox_id"],
            "approval_id": execution["approval_id"],
            "policy_decision_id": result["policy_decision_id"],
            "evidence_item_id": evidence_item["id"],
            "object_key": stored.object_key,
            "local_artifact_path": stored.local_path,
            "object_store_mode": stored.backend,
            "object_size": stored.size,
            "content_type": stored.content_type,
        }
        self.db.execute(
            """INSERT INTO validation_execution_evidence(
               id,execution_id,task_id,evidence_item_id,title,artifact_ref,
               content_sha256,metadata_json,created_at
               ) VALUES(?,?,?,?,?,?,?,?,?)""",
            (
                evidence_id,
                execution["id"],
                task_id,
                evidence_item["id"],
                "HTTP response evidence",
                stored.artifact_ref,
                stored.content_sha256,
                json.dumps(metadata, ensure_ascii=False, sort_keys=True),
                created_at,
            ),
        )
        self._record_event(
            execution["id"],
            "validation_execution.evidence_persisted",
            "COLLECTING_EVIDENCE",
            {
                "evidence_id": evidence_id,
                "content_sha256": stored.content_sha256,
                "artifact_ref": stored.artifact_ref,
                "object_store_mode": stored.backend,
            },
        )
        return {
            "id": evidence_id,
            "execution_id": execution["id"],
            "task_id": task_id,
            "evidence_item_id": evidence_item["id"],
            "title": "HTTP response evidence",
            "artifact_ref": stored.artifact_ref,
            "content_sha256": stored.content_sha256,
            "metadata": metadata,
            "created_at": created_at,
        }
