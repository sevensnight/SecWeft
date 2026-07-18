from __future__ import annotations

import builtins
import json
import uuid
from datetime import UTC, datetime
from typing import Any

from .audit import AuditService
from .repository import ControlPlaneRepository
from .schemas import SkillCreate
from .security import Principal

BUILTIN_SKILLS: tuple[dict[str, Any], ...] = (
    {
        "name": "scope.check",
        "description": "Deterministically validate target, protocol, port, and expiry",
        "version": "1.0",
        "risk_level": "low",
        "required_role": "analyst",
        "input_schema": {"type": "object", "required": ["target", "scope_id"]},
        "output_schema": {"type": "object", "required": ["target", "scope_id", "scope_hash"]},
        "permissions": ["scope:read"],
        "resource_limits": {"network": "none", "cpu_ms": 100},
        "timeout_seconds": 5,
        "execution_type": "internal",
        "tool_dependencies": [],
        "approval_required": False,
    },
    {
        "name": "task.plan",
        "description": "Compile a bounded non-destructive validation DAG",
        "version": "1.0",
        "risk_level": "low",
        "required_role": "analyst",
        "input_schema": {"type": "object", "required": ["task_id"]},
        "output_schema": {"type": "object", "required": ["workflow", "stage_count"]},
        "permissions": ["task:read"],
        "resource_limits": {"network": "none", "cpu_ms": 250},
        "timeout_seconds": 10,
        "execution_type": "internal",
        "tool_dependencies": [],
        "approval_required": False,
    },
    {
        "name": "rag.retrieve",
        "description": "Retrieve ACL-filtered defensive knowledge with provenance",
        "version": "1.0",
        "risk_level": "low",
        "required_role": "analyst",
        "input_schema": {"type": "object", "required": ["query"]},
        "output_schema": {"type": "object", "required": ["references"]},
        "permissions": ["rag:read"],
        "resource_limits": {"network": "none", "cpu_ms": 500},
        "timeout_seconds": 15,
        "execution_type": "internal",
        "tool_dependencies": [],
        "approval_required": False,
    },
    {
        "name": "asset.safe_probe",
        "description": "Low-rate TCP reachability check for an approved target",
        "version": "1.0",
        "risk_level": "medium",
        "required_role": "operator",
        "input_schema": {"type": "object", "required": ["target", "scope_id", "ports"]},
        "output_schema": {"type": "object", "required": ["evidence", "non_destructive"]},
        "permissions": ["asset:probe"],
        "resource_limits": {"network": "approved_scope_only", "max_ports": 1, "timeout_seconds": 2},
        "timeout_seconds": 20,
        "execution_type": "internal",
        "tool_dependencies": ["scope.check"],
        "approval_required": True,
    },
    {
        "name": "validation.safe_check",
        "description": "Run a structured non-destructive lab validation plan",
        "version": "1.0",
        "risk_level": "high",
        "required_role": "operator",
        "input_schema": {"type": "object", "required": ["task_id", "approved_plan"]},
        "output_schema": {"type": "object", "required": ["validation_signal"]},
        "permissions": ["task:execute"],
        "resource_limits": {"network": "none", "cpu_ms": 500},
        "timeout_seconds": 20,
        "execution_type": "internal",
        "tool_dependencies": ["scope.check"],
        "approval_required": True,
    },
    {
        "name": "report.generate",
        "description": "Generate a defensive evidence summary",
        "version": "1.0",
        "risk_level": "low",
        "required_role": "analyst",
        "input_schema": {"type": "object", "required": ["task_id", "evidence"]},
        "output_schema": {"type": "object", "required": ["summary"]},
        "permissions": ["task:read"],
        "resource_limits": {"network": "none", "cpu_ms": 500},
        "timeout_seconds": 15,
        "execution_type": "internal",
        "tool_dependencies": [],
        "approval_required": False,
    },
)


class SkillRegistry:
    def __init__(self, db: ControlPlaneRepository, audit: AuditService):
        self.db = db
        self.audit = audit

    def ensure_builtins(self) -> None:
        now = datetime.now(UTC).isoformat()
        with self.db.transaction() as connection:
            for skill in BUILTIN_SKILLS:
                connection.execute(
                    """INSERT OR IGNORE INTO skills(
                       id,name,version,description,risk_level,required_role,input_schema_json,
                       output_schema_json,permissions_json,resource_limits_json,timeout_seconds,
                       execution_type,tool_dependencies_json,approval_required,enabled,builtin,
                       created_at,updated_at)
                       VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,1,1,?,?)""",
                    (
                        str(uuid.uuid4()),
                        skill["name"],
                        skill["version"],
                        skill["description"],
                        skill["risk_level"],
                        skill["required_role"],
                        json.dumps(skill["input_schema"], ensure_ascii=False),
                        json.dumps(skill["output_schema"], ensure_ascii=False),
                        json.dumps(skill["permissions"], ensure_ascii=False),
                        json.dumps(skill["resource_limits"], ensure_ascii=False),
                        skill["timeout_seconds"],
                        skill["execution_type"],
                        json.dumps(skill["tool_dependencies"], ensure_ascii=False),
                        int(skill["approval_required"]),
                        now,
                        now,
                    ),
                )
                connection.execute(
                    """UPDATE skills SET version=?,description=?,risk_level=?,required_role=?,
                       input_schema_json=?,output_schema_json=?,permissions_json=?,
                       resource_limits_json=?,timeout_seconds=?,execution_type=?,
                       tool_dependencies_json=?,approval_required=?,updated_at=?
                       WHERE name=? AND builtin=1""",
                    (
                        skill["version"],
                        skill["description"],
                        skill["risk_level"],
                        skill["required_role"],
                        json.dumps(skill["input_schema"], ensure_ascii=False),
                        json.dumps(skill["output_schema"], ensure_ascii=False),
                        json.dumps(skill["permissions"], ensure_ascii=False),
                        json.dumps(skill["resource_limits"], ensure_ascii=False),
                        skill["timeout_seconds"],
                        skill["execution_type"],
                        json.dumps(skill["tool_dependencies"], ensure_ascii=False),
                        int(skill["approval_required"]),
                        now,
                        skill["name"],
                    ),
                )

    def create(self, principal: Principal, value: SkillCreate) -> dict[str, Any]:
        # Dynamic skills are declarative manifests only; executable uploads are intentionally unsupported.
        skill_id = str(uuid.uuid4())
        self.db.execute(
            """INSERT INTO skills(
               id,name,version,description,risk_level,required_role,input_schema_json,
               output_schema_json,permissions_json,resource_limits_json,timeout_seconds,
               execution_type,tool_dependencies_json,approval_required,enabled,builtin,
               created_at,updated_at)
               VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,1,0,?,?)""",
            (
                skill_id,
                value.name,
                value.version,
                value.description,
                value.risk_level,
                value.required_role.value,
                json.dumps(value.input_schema, ensure_ascii=False),
                json.dumps(value.output_schema, ensure_ascii=False),
                json.dumps(value.permissions, ensure_ascii=False),
                json.dumps(value.resource_limits, ensure_ascii=False),
                value.timeout_seconds,
                value.execution_type,
                json.dumps(value.tool_dependencies, ensure_ascii=False),
                int(value.approval_required),
                datetime.now(UTC).isoformat(),
                datetime.now(UTC).isoformat(),
            ),
        )
        self.audit.record(
            principal.id,
            "skill.manifest.create",
            "skill",
            skill_id,
            details={
                "name": value.name,
                "version": value.version,
                "risk_level": value.risk_level,
                "required_role": value.required_role.value,
            },
        )
        return self.get(skill_id)

    def get(self, skill_id: str) -> dict[str, Any]:
        row = self.db.fetch_one("SELECT * FROM skills WHERE id=?", (skill_id,))
        if row is None:
            raise KeyError("skill not found")
        return self._serialize(row)

    def list(self) -> builtins.list[dict[str, Any]]:
        return [
            self._serialize(row) for row in self.db.fetch_all("SELECT * FROM skills ORDER BY name")
        ]

    def set_enabled(self, principal: Principal, skill_id: str, enabled: bool) -> dict[str, Any]:
        count, _ = self.db.execute(
            "UPDATE skills SET enabled=? WHERE id=?", (int(enabled), skill_id)
        )
        if count != 1:
            raise KeyError("skill not found")
        self.audit.record(
            principal.id, "skill.enabled.update", "skill", skill_id, details={"enabled": enabled}
        )
        return self.get(skill_id)

    @staticmethod
    def _serialize(row: Any) -> dict[str, Any]:
        return {
            "id": row["id"],
            "name": row["name"],
            "version": row["version"],
            "description": row["description"],
            "risk_level": row["risk_level"],
            "required_role": row["required_role"],
            "input_schema": json.loads(row["input_schema_json"]),
            "output_schema": json.loads(row["output_schema_json"]),
            "permissions": json.loads(row["permissions_json"]),
            "resource_limits": json.loads(row["resource_limits_json"]),
            "timeout_seconds": row["timeout_seconds"],
            "execution_type": row["execution_type"],
            "tool_dependencies": json.loads(row["tool_dependencies_json"]),
            "approval_required": bool(row["approval_required"]),
            "enabled": bool(row["enabled"]),
            "builtin": bool(row["builtin"]),
            "invocation_count": int(row["invocation_count"]),
            "success_count": int(row["success_count"]),
            "failure_count": int(row["failure_count"]),
        }

    def assignments(self, intent: str) -> builtins.list[str]:
        common = ["scope.check", "task.plan", "rag.retrieve", "report.generate"]
        if intent == "asset_inventory":
            desired = [*common[:3], "asset.safe_probe", common[-1]]
        else:
            desired = [*common[:3], "validation.safe_check", common[-1]]
        self.assert_enabled(desired)
        return desired

    def assert_enabled(self, names: builtins.list[str]) -> None:
        if not names:
            return
        placeholders = ",".join("?" for _ in names)
        rows = self.db.fetch_all(
            f"SELECT name,enabled FROM skills WHERE name IN ({placeholders})", tuple(names)
        )
        enabled = {row["name"] for row in rows if bool(row["enabled"])}
        unavailable = sorted(set(names) - enabled)
        if unavailable:
            raise ValueError(f"required skills are missing or disabled: {', '.join(unavailable)}")

    def record_invocation(self, name: str, *, succeeded: bool) -> None:
        success_delta = 1 if succeeded else 0
        failure_delta = 0 if succeeded else 1
        self.db.execute(
            """UPDATE skills
               SET invocation_count=invocation_count+1,
                   success_count=success_count+?,
                   failure_count=failure_count+?,
                   updated_at=?
               WHERE name=?""",
            (success_delta, failure_delta, datetime.now(UTC).isoformat(), name),
        )

    def protocol_manifest(self) -> dict[str, Any]:
        return {
            "protocol": "vulnlab-tool-schema",
            "version": "1.1",
            "policy": "manifests describe tools but never grant capabilities",
            "tools": [
                {
                    "name": item["name"],
                    "version": item["version"],
                    "description": item["description"],
                    "inputSchema": item["input_schema"],
                    "outputSchema": item["output_schema"],
                    "permissions": item["permissions"],
                    "resourceLimits": item["resource_limits"],
                    "timeoutSeconds": item["timeout_seconds"],
                    "executionType": item["execution_type"],
                    "toolDependencies": item["tool_dependencies"],
                    "approvalRequired": item["approval_required"],
                    "riskLevel": item["risk_level"],
                    "requiredRole": item["required_role"],
                    "enabled": item["enabled"],
                    "stats": {
                        "invocationCount": item["invocation_count"],
                        "successCount": item["success_count"],
                        "failureCount": item["failure_count"],
                    },
                }
                for item in self.list()
            ],
        }
