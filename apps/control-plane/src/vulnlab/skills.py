from __future__ import annotations

import builtins
import json
import uuid
from datetime import UTC, datetime
from typing import Any

from .audit import AuditService
from .db import Database
from .schemas import SkillCreate
from .security import Principal

BUILTIN_SKILLS: tuple[dict[str, Any], ...] = (
    {
        "name": "scope.check",
        "description": "Deterministically validate target, protocol, port, and expiry",
        "risk_level": "low",
        "required_role": "analyst",
        "input_schema": {"type": "object", "required": ["target", "scope_id"]},
    },
    {
        "name": "task.plan",
        "description": "Compile a bounded non-destructive validation DAG",
        "risk_level": "low",
        "required_role": "analyst",
        "input_schema": {"type": "object", "required": ["task_id"]},
    },
    {
        "name": "rag.retrieve",
        "description": "Retrieve ACL-filtered defensive knowledge with provenance",
        "risk_level": "low",
        "required_role": "analyst",
        "input_schema": {"type": "object", "required": ["query"]},
    },
    {
        "name": "asset.safe_probe",
        "description": "Low-rate TCP reachability check for an approved target",
        "risk_level": "medium",
        "required_role": "operator",
        "input_schema": {"type": "object", "required": ["target", "scope_id", "ports"]},
    },
    {
        "name": "validation.safe_check",
        "description": "Run a structured non-destructive lab validation plan",
        "risk_level": "high",
        "required_role": "operator",
        "input_schema": {"type": "object", "required": ["task_id", "approved_plan"]},
    },
    {
        "name": "report.generate",
        "description": "Generate a defensive evidence summary",
        "risk_level": "low",
        "required_role": "analyst",
        "input_schema": {"type": "object", "required": ["task_id", "evidence"]},
    },
)


class SkillRegistry:
    def __init__(self, db: Database, audit: AuditService):
        self.db = db
        self.audit = audit

    def ensure_builtins(self) -> None:
        now = datetime.now(UTC).isoformat()
        with self.db.transaction() as connection:
            for skill in BUILTIN_SKILLS:
                connection.execute(
                    """INSERT OR IGNORE INTO skills(id,name,description,risk_level,required_role,
                       input_schema_json,enabled,builtin,created_at) VALUES(?,?,?,?,?,?,1,1,?)""",
                    (
                        str(uuid.uuid4()),
                        skill["name"],
                        skill["description"],
                        skill["risk_level"],
                        skill["required_role"],
                        json.dumps(skill["input_schema"]),
                        now,
                    ),
                )

    def create(self, principal: Principal, value: SkillCreate) -> dict[str, Any]:
        # Dynamic skills are declarative manifests only; executable uploads are intentionally unsupported.
        skill_id = str(uuid.uuid4())
        self.db.execute(
            """INSERT INTO skills(id,name,description,risk_level,required_role,input_schema_json,
               enabled,builtin,created_at) VALUES(?,?,?,?,?,?,1,0,?)""",
            (
                skill_id,
                value.name,
                value.description,
                value.risk_level,
                value.required_role.value,
                json.dumps(value.input_schema, ensure_ascii=False),
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
            "description": row["description"],
            "risk_level": row["risk_level"],
            "required_role": row["required_role"],
            "input_schema": json.loads(row["input_schema_json"]),
            "enabled": bool(row["enabled"]),
            "builtin": bool(row["builtin"]),
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

    def protocol_manifest(self) -> dict[str, Any]:
        return {
            "protocol": "vulnlab-tool-schema",
            "version": "1.0",
            "policy": "manifests describe tools but never grant capabilities",
            "tools": [
                {
                    "name": item["name"],
                    "description": item["description"],
                    "inputSchema": item["input_schema"],
                    "riskLevel": item["risk_level"],
                    "requiredRole": item["required_role"],
                    "enabled": item["enabled"],
                }
                for item in self.list()
            ],
        }
