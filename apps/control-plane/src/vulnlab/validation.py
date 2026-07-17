from __future__ import annotations

import hashlib
import json
import uuid
from datetime import UTC, datetime
from typing import Any

from .audit import AuditService
from .db import Database
from .policy import PolicyDenied, PolicyService
from .schemas import PolicyEvaluationRequest, ValidationPlanCreate
from .security import Principal


class ValidationPlanStateError(ValueError):
    pass


class ValidationPlanService:
    def __init__(self, db: Database, policy: PolicyService, audit: AuditService):
        self.db = db
        self.policy = policy
        self.audit = audit

    @staticmethod
    def _canonical_plan(task_id: str, value: ValidationPlanCreate) -> dict[str, Any]:
        return {
            "version": "1.0",
            "task_id": task_id,
            "destructive": False,
            "objectives": value.objectives,
            "steps": [step.model_dump(mode="json") for step in value.steps],
            "rollback": value.rollback,
        }

    @staticmethod
    def _hash_plan(plan: dict[str, Any]) -> str:
        encoded = json.dumps(plan, sort_keys=True, separators=(",", ":")).encode()
        return hashlib.sha256(encoded).hexdigest()

    @staticmethod
    def _row(row: Any) -> dict[str, Any]:
        return {
            "id": row["id"],
            "task_id": row["task_id"],
            "status": row["status"],
            "plan": json.loads(row["plan_json"]),
            "plan_hash": row["plan_hash"],
            "policy_decision_ids": json.loads(row["policy_decision_ids_json"]),
            "created_by": row["created_by"],
            "submitted_at": row["submitted_at"],
            "reviewed_by": row["reviewed_by"],
            "reviewed_at": row["reviewed_at"],
            "review_reason": row["review_reason"],
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
        }

    def _preflight_steps(
        self,
        principal: Principal,
        task: Any,
        value: ValidationPlanCreate,
    ) -> list[str]:
        decision_ids: list[str] = []
        for index, step in enumerate(value.steps):
            target = f"tcp://{step.host}:{step.port}"
            if step.kind in {"http_request", "assertion"}:
                target = f"http://{step.host}:{step.port}"
            decision = self.policy.evaluate(
                principal,
                PolicyEvaluationRequest(
                    action="asset.probe",
                    resource_type="validation_plan_step",
                    resource_id=f"{task['id']}:{index}",
                    task_id=task["id"],
                    scope_id=task["scope_id"],
                    target=target,
                    ports=[step.port],
                    metadata={"kind": step.kind, "method": step.method, "path": step.path},
                ),
                enforced=False,
            )
            decision_ids.append(decision["id"])
            if decision["decision"] == "deny":
                raise PolicyDenied(f"validation plan step denied: {decision['reason']}")
        return decision_ids

    def create(
        self,
        principal: Principal,
        task: Any,
        value: ValidationPlanCreate,
    ) -> dict[str, Any]:
        decision_ids = self._preflight_steps(principal, task, value)
        plan = self._canonical_plan(task["id"], value)
        plan_hash = self._hash_plan(plan)
        plan_id = str(uuid.uuid4())
        now = datetime.now(UTC).isoformat()
        self.db.execute(
            """INSERT INTO validation_plans(
               id,task_id,status,plan_json,plan_hash,policy_decision_ids_json,
               created_by,created_at,updated_at
               ) VALUES(?,?,?,?,?,?,?,?,?)""",
            (
                plan_id,
                task["id"],
                "draft",
                json.dumps(plan, ensure_ascii=False, sort_keys=True),
                plan_hash,
                json.dumps(decision_ids, ensure_ascii=False),
                principal.id,
                now,
                now,
            ),
        )
        self.audit.record(
            principal.id,
            "validation_plan.create",
            "task",
            task["id"],
            details={
                "validation_plan_id": plan_id,
                "plan_hash": plan_hash,
                "policy_decision_ids": decision_ids,
            },
        )
        row = self.db.fetch_one("SELECT * FROM validation_plans WHERE id=?", (plan_id,))
        if row is None:
            raise RuntimeError("validation plan was not persisted")
        return self._row(row)

    def list(self, task_id: str, limit: int = 100) -> list[dict[str, Any]]:
        rows = self.db.fetch_all(
            "SELECT * FROM validation_plans WHERE task_id=? ORDER BY created_at DESC,id DESC LIMIT ?",
            (task_id, min(max(limit, 1), 500)),
        )
        return [self._row(row) for row in rows]

    def get(self, plan_id: str) -> dict[str, Any]:
        row = self.db.fetch_one("SELECT * FROM validation_plans WHERE id=?", (plan_id,))
        if row is None:
            raise KeyError("validation plan not found")
        return self._row(row)

    def submit(self, principal: Principal, plan_id: str) -> dict[str, Any]:
        row = self.db.fetch_one("SELECT * FROM validation_plans WHERE id=?", (plan_id,))
        if row is None:
            raise KeyError("validation plan not found")
        if row["status"] != "draft":
            raise ValidationPlanStateError("only draft validation plans can be submitted")
        now = datetime.now(UTC).isoformat()
        self.db.execute(
            "UPDATE validation_plans SET status='submitted',submitted_at=?,updated_at=? WHERE id=?",
            (now, now, plan_id),
        )
        self.audit.record(
            principal.id,
            "validation_plan.submit",
            "validation_plan",
            plan_id,
            details={"task_id": row["task_id"], "plan_hash": row["plan_hash"]},
        )
        return self.get(plan_id)

    def review(
        self,
        principal: Principal,
        plan_id: str,
        *,
        approved: bool,
        reason: str,
    ) -> dict[str, Any]:
        if principal.role.value != "admin":
            raise PermissionError("only administrators can review validation plans")
        row = self.db.fetch_one("SELECT * FROM validation_plans WHERE id=?", (plan_id,))
        if row is None:
            raise KeyError("validation plan not found")
        if row["status"] != "submitted":
            raise ValidationPlanStateError("only submitted validation plans can be reviewed")
        now = datetime.now(UTC).isoformat()
        status = "approved" if approved else "rejected"
        self.db.execute(
            """UPDATE validation_plans
               SET status=?,reviewed_by=?,reviewed_at=?,review_reason=?,updated_at=?
               WHERE id=?""",
            (status, principal.id, now, reason, now, plan_id),
        )
        self.audit.record(
            principal.id,
            "validation_plan.review",
            "validation_plan",
            plan_id,
            details={
                "task_id": row["task_id"],
                "approved": approved,
                "plan_hash": row["plan_hash"],
            },
        )
        return self.get(plan_id)
