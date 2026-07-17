from __future__ import annotations

import builtins
import json
import uuid
from datetime import UTC, datetime
from typing import Any

from .audit import AuditService
from .db import Database
from .schemas import AgentCreate, WorkflowCreate
from .security import Principal

BUILTIN_AGENTS: tuple[dict[str, Any], ...] = (
    {
        "name": "task_planner",
        "version": "1.0",
        "description": "Compile bounded task plans and select approved workflow stages.",
        "responsibilities": ["task decomposition", "stage dependency validation"],
        "allowed_tools": ["scope.check", "task.plan"],
        "data_scope": "task",
        "token_budget": 2048,
        "timeout_seconds": 20,
        "risk_level": "low",
        "retry_policy": {"max_attempts": 1, "backoff_seconds": 0},
    },
    {
        "name": "code_analyzer",
        "version": "1.0",
        "description": "Hold a placeholder capability boundary for future static analysis.",
        "responsibilities": ["static analysis planning"],
        "allowed_tools": [],
        "data_scope": "task",
        "token_budget": 4096,
        "timeout_seconds": 30,
        "risk_level": "low",
        "retry_policy": {"max_attempts": 1, "backoff_seconds": 0},
    },
    {
        "name": "vulnerability_researcher",
        "version": "1.0",
        "description": "Research vulnerability hypotheses without executing validation payloads.",
        "responsibilities": ["hypothesis drafting", "risk labeling"],
        "allowed_tools": ["rag.retrieve"],
        "data_scope": "project",
        "token_budget": 4096,
        "timeout_seconds": 30,
        "risk_level": "medium",
        "retry_policy": {"max_attempts": 1, "backoff_seconds": 0},
    },
    {
        "name": "knowledge_retriever",
        "version": "1.0",
        "description": "Retrieve ACL-filtered defensive knowledge and provenance.",
        "responsibilities": ["knowledge lookup", "source attribution"],
        "allowed_tools": ["rag.retrieve"],
        "data_scope": "project",
        "token_budget": 2048,
        "timeout_seconds": 20,
        "risk_level": "low",
        "retry_policy": {"max_attempts": 2, "backoff_seconds": 1},
    },
    {
        "name": "validation_planner",
        "version": "1.0",
        "description": "Collect non-destructive evidence and prepare validation requests.",
        "responsibilities": ["safe evidence collection", "approval boundary preservation"],
        "allowed_tools": ["asset.safe_probe", "validation.safe_check"],
        "data_scope": "task",
        "token_budget": 2048,
        "timeout_seconds": 45,
        "risk_level": "medium",
        "retry_policy": {"max_attempts": 2, "backoff_seconds": 1},
    },
    {
        "name": "sandbox_manager",
        "version": "1.0",
        "description": "Represent sandbox orchestration boundaries; execution remains deferred to P5.",
        "responsibilities": ["sandbox policy precheck"],
        "allowed_tools": [],
        "data_scope": "task",
        "token_budget": 1024,
        "timeout_seconds": 15,
        "risk_level": "medium",
        "retry_policy": {"max_attempts": 1, "backoff_seconds": 0},
    },
    {
        "name": "result_reviewer",
        "version": "1.0",
        "description": "Review collected evidence without promoting reachability to exploitability.",
        "responsibilities": ["signal evaluation", "false-positive guardrails"],
        "allowed_tools": ["validation.safe_check"],
        "data_scope": "task",
        "token_budget": 2048,
        "timeout_seconds": 20,
        "risk_level": "low",
        "retry_policy": {"max_attempts": 1, "backoff_seconds": 0},
    },
    {
        "name": "report_generator",
        "version": "1.0",
        "description": "Generate defensive summaries with limits and audit context.",
        "responsibilities": ["defensive report generation"],
        "allowed_tools": ["report.generate"],
        "data_scope": "task",
        "token_budget": 2048,
        "timeout_seconds": 20,
        "risk_level": "low",
        "retry_policy": {"max_attempts": 1, "backoff_seconds": 0},
    },
    {
        "name": "compliance_checker",
        "version": "1.0",
        "description": "Check that workflow execution stays inside authorization and audit policy.",
        "responsibilities": ["scope guardrail review", "approval audit review"],
        "allowed_tools": ["scope.check"],
        "data_scope": "task",
        "token_budget": 1024,
        "timeout_seconds": 10,
        "risk_level": "low",
        "retry_policy": {"max_attempts": 1, "backoff_seconds": 0},
    },
)


BUILTIN_WORKFLOWS: tuple[dict[str, Any], ...] = (
    {
        "name": "p3.synthetic.defensive",
        "version": "1.0",
        "description": (
            "P3 no-side-effect workflow: scope recheck, planning, ACL-filtered knowledge "
            "lookup, non-destructive evidence collection, review, and defensive report."
        ),
        "stages": [
            {
                "code": "scope",
                "display_name": "信息准备",
                "agent_name": "task_planner",
                "agent_version": "1.0",
                "skill_name": "scope.check",
                "skill_version": "1.0",
                "depends_on": [],
                "max_attempts": 1,
            },
            {
                "code": "plan",
                "display_name": "任务拆解",
                "agent_name": "task_planner",
                "agent_version": "1.0",
                "skill_name": "task.plan",
                "skill_version": "1.0",
                "depends_on": ["scope"],
                "max_attempts": 1,
            },
            {
                "code": "knowledge",
                "display_name": "知识检索",
                "agent_name": "knowledge_retriever",
                "agent_version": "1.0",
                "skill_name": "rag.retrieve",
                "skill_version": "1.0",
                "depends_on": ["plan"],
                "max_attempts": 2,
            },
            {
                "code": "evidence",
                "display_name": "证据收集",
                "agent_name": "validation_planner",
                "agent_version": "1.0",
                "skill_name": "asset.safe_probe",
                "skill_version": "1.0",
                "depends_on": ["knowledge"],
                "max_attempts": 2,
            },
            {
                "code": "evaluate",
                "display_name": "结果分析",
                "agent_name": "result_reviewer",
                "agent_version": "1.0",
                "skill_name": "validation.safe_check",
                "skill_version": "1.0",
                "depends_on": ["evidence"],
                "max_attempts": 1,
            },
            {
                "code": "report",
                "display_name": "报告生成",
                "agent_name": "report_generator",
                "agent_version": "1.0",
                "skill_name": "report.generate",
                "skill_version": "1.0",
                "depends_on": ["evaluate"],
                "max_attempts": 1,
            },
        ],
    },
)


def _loads(value: str | None, default: Any) -> Any:
    return json.loads(value) if value else default


class AgentRegistry:
    def __init__(self, db: Database, audit: AuditService):
        self.db = db
        self.audit = audit

    def ensure_builtins(self) -> None:
        now = datetime.now(UTC).isoformat()
        with self.db.transaction() as connection:
            for agent in BUILTIN_AGENTS:
                connection.execute(
                    """INSERT OR IGNORE INTO agents(
                       id,name,version,description,responsibilities_json,input_schema_json,
                       output_schema_json,allowed_tools_json,data_scope,token_budget,
                       timeout_seconds,risk_level,retry_policy_json,enabled,builtin,
                       created_by,created_at,updated_at)
                       VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,1,1,NULL,?,?)""",
                    (
                        str(uuid.uuid4()),
                        agent["name"],
                        agent["version"],
                        agent["description"],
                        json.dumps(agent["responsibilities"], ensure_ascii=False),
                        json.dumps({"type": "object"}),
                        json.dumps({"type": "object"}),
                        json.dumps(agent["allowed_tools"], ensure_ascii=False),
                        agent["data_scope"],
                        agent["token_budget"],
                        agent["timeout_seconds"],
                        agent["risk_level"],
                        json.dumps(agent["retry_policy"], ensure_ascii=False),
                        now,
                        now,
                    ),
                )
            for workflow in BUILTIN_WORKFLOWS:
                connection.execute(
                    """INSERT OR IGNORE INTO workflows(
                       id,name,version,description,stages_json,enabled,builtin,
                       created_by,created_at,updated_at)
                       VALUES(?,?,?,?,?,1,1,NULL,?,?)""",
                    (
                        str(uuid.uuid4()),
                        workflow["name"],
                        workflow["version"],
                        workflow["description"],
                        json.dumps(workflow["stages"], ensure_ascii=False),
                        now,
                        now,
                    ),
                )

    def create_agent(self, principal: Principal, value: AgentCreate) -> dict[str, Any]:
        agent_id = str(uuid.uuid4())
        now = datetime.now(UTC).isoformat()
        self.db.execute(
            """INSERT INTO agents(
               id,name,version,description,responsibilities_json,input_schema_json,
               output_schema_json,allowed_tools_json,data_scope,token_budget,
               timeout_seconds,risk_level,retry_policy_json,enabled,builtin,
               created_by,created_at,updated_at)
               VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,1,0,?,?,?)""",
            (
                agent_id,
                value.name,
                value.version,
                value.description,
                json.dumps(value.responsibilities, ensure_ascii=False),
                json.dumps(value.input_schema, ensure_ascii=False),
                json.dumps(value.output_schema, ensure_ascii=False),
                json.dumps(value.allowed_tools, ensure_ascii=False),
                value.data_scope,
                value.token_budget,
                value.timeout_seconds,
                value.risk_level,
                json.dumps(value.retry_policy, ensure_ascii=False),
                principal.id,
                now,
                now,
            ),
        )
        self.audit.record(
            principal.id,
            "agent.definition.create",
            "agent",
            agent_id,
            details={
                "name": value.name,
                "version": value.version,
                "risk_level": value.risk_level,
            },
        )
        return self.get_agent(agent_id)

    def create_workflow(self, principal: Principal, value: WorkflowCreate) -> dict[str, Any]:
        workflow_id = str(uuid.uuid4())
        now = datetime.now(UTC).isoformat()
        self.db.execute(
            """INSERT INTO workflows(
               id,name,version,description,stages_json,enabled,builtin,created_by,created_at,updated_at)
               VALUES(?,?,?,?,?,1,0,?,?,?)""",
            (
                workflow_id,
                value.name,
                value.version,
                value.description,
                json.dumps([stage.model_dump() for stage in value.stages], ensure_ascii=False),
                principal.id,
                now,
                now,
            ),
        )
        self.audit.record(
            principal.id,
            "workflow.definition.create",
            "workflow",
            workflow_id,
            details={"name": value.name, "version": value.version, "stages": len(value.stages)},
        )
        return self.get_workflow(workflow_id)

    def get_agent(self, agent_id: str) -> dict[str, Any]:
        row = self.db.fetch_one("SELECT * FROM agents WHERE id=?", (agent_id,))
        if row is None:
            raise KeyError("agent not found")
        return self._serialize_agent(row)

    def get_workflow(self, workflow_id: str) -> dict[str, Any]:
        row = self.db.fetch_one("SELECT * FROM workflows WHERE id=?", (workflow_id,))
        if row is None:
            raise KeyError("workflow not found")
        return self._serialize_workflow(row)

    def workflow_by_name(self, name: str, version: str = "1.0") -> dict[str, Any]:
        row = self.db.fetch_one(
            "SELECT * FROM workflows WHERE name=? AND version=? AND enabled=1",
            (name, version),
        )
        if row is None:
            raise KeyError("workflow not found or disabled")
        return self._serialize_workflow(row)

    def list_agents(self) -> builtins.list[dict[str, Any]]:
        return [
            self._serialize_agent(row)
            for row in self.db.fetch_all("SELECT * FROM agents ORDER BY name, version")
        ]

    def list_workflows(self) -> builtins.list[dict[str, Any]]:
        return [
            self._serialize_workflow(row)
            for row in self.db.fetch_all("SELECT * FROM workflows ORDER BY name, version")
        ]

    @staticmethod
    def _serialize_agent(row: Any) -> dict[str, Any]:
        return {
            "id": row["id"],
            "name": row["name"],
            "version": row["version"],
            "description": row["description"],
            "responsibilities": _loads(row["responsibilities_json"], []),
            "input_schema": _loads(row["input_schema_json"], {"type": "object"}),
            "output_schema": _loads(row["output_schema_json"], {"type": "object"}),
            "allowed_tools": _loads(row["allowed_tools_json"], []),
            "data_scope": row["data_scope"],
            "token_budget": row["token_budget"],
            "timeout_seconds": row["timeout_seconds"],
            "risk_level": row["risk_level"],
            "retry_policy": _loads(row["retry_policy_json"], {}),
            "enabled": bool(row["enabled"]),
            "builtin": bool(row["builtin"]),
            "created_by": row["created_by"],
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
        }

    @staticmethod
    def _serialize_workflow(row: Any) -> dict[str, Any]:
        return {
            "id": row["id"],
            "name": row["name"],
            "version": row["version"],
            "description": row["description"],
            "stages": _loads(row["stages_json"], []),
            "enabled": bool(row["enabled"]),
            "builtin": bool(row["builtin"]),
            "created_by": row["created_by"],
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
        }
