from __future__ import annotations

import hashlib
import json
import re
import uuid
from datetime import UTC, datetime
from typing import Any, Literal

from .audit import AuditService
from .config import Settings
from .repository import ControlPlaneRepository
from .schemas import PolicyEvaluationRequest
from .scope import ScopeService, ScopeViolation
from .security import Principal, redact

POLICY_VERSION = "p5-default-policy-v1"
SHELL_META = re.compile(r"[;&|<>`$]")


class PolicyDenied(PermissionError):
    pass


class PolicyService:
    def __init__(
        self,
        db: ControlPlaneRepository,
        scope: ScopeService,
        settings: Settings,
        audit: AuditService,
    ):
        self.db = db
        self.scope = scope
        self.settings = settings
        self.audit = audit

    @staticmethod
    def policy_hash() -> str:
        rules = {
            "version": POLICY_VERSION,
            "rules": [
                "destructive actions are denied",
                "legacy execution actions are denied when legacy execution is disabled",
                "validation execution is allowed only through registered versioned templates",
                "task-bound execution requires current approval",
                "scope-bound actions must pass current scope validation",
                "sandbox argv must not contain shell metacharacters",
                "policy decisions do not grant capabilities",
            ],
        }
        encoded = json.dumps(rules, sort_keys=True, separators=(",", ":")).encode()
        return hashlib.sha256(encoded).hexdigest()

    def _task_decision(self, principal: Principal, task_id: str | None) -> tuple[str | None, str]:
        if task_id is None:
            return None, "no task context supplied"
        task = self.db.fetch_one("SELECT * FROM tasks WHERE id=?", (task_id,))
        if task is None:
            return "deny", "task does not exist"
        if principal.role.value != "admin" and task["created_by"] != principal.id:
            return "deny", "task belongs to another principal"
        if task["approval_status"] != "approved" or task["status"] not in {
            "approved",
            "queued",
            "running",
            "paused",
        }:
            return "requires_approval", "task is not currently approved for execution"
        return None, "task approval is current"

    def _scope_decision(self, value: PolicyEvaluationRequest) -> tuple[str | None, str]:
        if value.target is None or value.scope_id is None:
            return None, "no scope-bound target supplied"
        try:
            self.scope.validate(
                value.target,
                value.scope_id,
                value.ports or None,
                require_approved=True,
            )
        except ScopeViolation as exc:
            return "deny", str(exc)
        return None, "scope validation succeeded"

    @staticmethod
    def _argv_decision(value: PolicyEvaluationRequest) -> tuple[str | None, str]:
        if not value.argv:
            return None, "no argv supplied"
        if any(SHELL_META.search(argument) for argument in value.argv):
            return "deny", "sandbox argv contains forbidden shell metacharacters"
        return None, "argv passes policy precheck"

    def evaluate(
        self,
        principal: Principal,
        value: PolicyEvaluationRequest,
        *,
        enforced: bool = False,
    ) -> dict[str, Any]:
        decision: Literal["allow", "deny", "requires_approval"] = "allow"
        reasons: list[str] = []

        if value.destructive:
            decision = "deny"
            reasons.append("destructive actions are forbidden")

        if (
            value.action in {"asset.probe", "sandbox.run"}
            and not self.settings.legacy_execution_enabled
        ):
            decision = "deny"
            reasons.append("legacy execution capability is disabled")

        if value.action in {"task.execute", "sandbox.run"}:
            task_decision, task_reason = self._task_decision(principal, value.task_id)
            reasons.append(task_reason)
            if task_decision == "deny":
                decision = "deny"
            elif task_decision == "requires_approval" and decision == "allow":
                decision = "requires_approval"

        scope_decision, scope_reason = self._scope_decision(value)
        reasons.append(scope_reason)
        if scope_decision == "deny":
            decision = "deny"

        argv_decision, argv_reason = self._argv_decision(value)
        reasons.append(argv_reason)
        if argv_decision == "deny":
            decision = "deny"

        if decision == "allow":
            reasons.insert(0, "all policy checks passed")

        decision_id = str(uuid.uuid4())
        created_at = datetime.now(UTC).isoformat()
        details = {
            "task_id": value.task_id,
            "scope_id": value.scope_id,
            "target": value.target,
            "ports": value.ports,
            "argv": value.argv,
            "destructive": value.destructive,
            "enforced": enforced,
            "metadata": value.metadata,
        }
        safe_details = redact(details)
        policy_hash = self.policy_hash()
        self.db.execute(
            """INSERT INTO policy_decisions(
               id,actor_id,action,resource_type,resource_id,decision,reason,
               details_json,policy_hash,created_at
               ) VALUES(?,?,?,?,?,?,?,?,?,?)""",
            (
                decision_id,
                principal.id,
                value.action,
                value.resource_type,
                value.resource_id,
                decision,
                "; ".join(reasons),
                json.dumps(safe_details, ensure_ascii=False, sort_keys=True),
                policy_hash,
                created_at,
            ),
        )
        self.audit.record(
            principal.id,
            "policy.evaluate",
            value.resource_type,
            value.resource_id,
            "denied" if decision == "deny" else "success",
            {
                "decision_id": decision_id,
                "action": value.action,
                "decision": decision,
                "policy_hash": policy_hash,
                "enforced": enforced,
            },
        )
        return {
            "id": decision_id,
            "action": value.action,
            "resource_type": value.resource_type,
            "resource_id": value.resource_id,
            "decision": decision,
            "reason": "; ".join(reasons),
            "details": safe_details,
            "policy_hash": policy_hash,
            "created_at": created_at,
        }

    def enforce(self, principal: Principal, value: PolicyEvaluationRequest) -> dict[str, Any]:
        decision = self.evaluate(principal, value, enforced=True)
        if decision["decision"] != "allow":
            raise PolicyDenied(f"policy decision {decision['decision']}: {decision['reason']}")
        return decision
