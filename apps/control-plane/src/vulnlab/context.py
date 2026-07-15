from __future__ import annotations

import json
import re
import uuid
from datetime import UTC, datetime
from typing import Any

from .audit import AuditService
from .db import Database
from .security import Principal

SECRET_PATTERNS = (
    re.compile(r"(?i)(authorization\s*:\s*bearer\s+)[A-Za-z0-9._~+/=-]+"),
    re.compile(r"(?i)((?:api[_-]?key|password|secret|token)\s*[=:]\s*)[^\s,;]+"),
    re.compile(r"\bsk-[A-Za-z0-9_-]{12,}\b"),
)


def scrub_secrets(text: str) -> str:
    result = text
    for pattern in SECRET_PATTERNS:
        result = pattern.sub(
            lambda match: (match.group(1) if match.lastindex else "") + "[REDACTED]", result
        )
    return result


class ContextService:
    def __init__(self, db: Database, audit: AuditService):
        self.db = db
        self.audit = audit

    def add(
        self,
        principal: Principal,
        task_id: str,
        role: str,
        content: str,
        visibility: str,
    ) -> dict[str, Any]:
        message_id = str(uuid.uuid4())
        safe_content = scrub_secrets(content)
        created_at = datetime.now(UTC).isoformat()
        self.db.execute(
            """INSERT INTO memory_messages(id,task_id,owner_id,role,content,visibility,token_estimate,created_at)
               VALUES(?,?,?,?,?,?,?,?)""",
            (
                message_id,
                task_id,
                principal.id,
                role,
                safe_content,
                visibility,
                max(1, len(safe_content) // 4),
                created_at,
            ),
        )
        self.audit.record(
            principal.id,
            "context.message.add",
            "task",
            task_id,
            details={
                "message_id": message_id,
                "role": role,
                "visibility": visibility,
                "redacted": safe_content != content,
            },
        )
        return {
            "id": message_id,
            "task_id": task_id,
            "owner_id": principal.id,
            "role": role,
            "content": safe_content,
            "visibility": visibility,
            "token_estimate": max(1, len(safe_content) // 4),
            "created_at": created_at,
        }

    def list(self, principal: Principal, task_id: str, limit: int = 200) -> list[dict[str, Any]]:
        rows = self.db.fetch_all(
            """SELECT * FROM memory_messages WHERE task_id=? AND (visibility='task' OR owner_id=?)
               ORDER BY created_at,id LIMIT ?""",
            (task_id, principal.id, min(max(limit, 1), 1000)),
        )
        return [dict(row) for row in rows]

    def checkpoint(self, principal: Principal, task_id: str) -> dict[str, Any]:
        task = self.db.fetch_one("SELECT * FROM tasks WHERE id=?", (task_id,))
        if task is None:
            raise KeyError("task not found")
        messages = self.list(principal, task_id, 1000)
        latest = messages[-12:]
        excerpts = [f"{item['role']}: {item['content'][:240]}" for item in latest]
        security_envelope = {
            "scope_id": task["scope_id"],
            "target": task["target"],
            "intent": task["intent"],
            "approval_status": task["approval_status"],
            "status": task["status"],
            "policy": "scope and approval must be revalidated before every side effect",
        }
        summary = "\n".join(excerpts) if excerpts else "No conversational context."
        summary = f"SECURITY_ENVELOPE={json.dumps(security_envelope, ensure_ascii=False, sort_keys=True)}\n{summary}"
        checkpoint_id = str(uuid.uuid4())
        created_at = datetime.now(UTC).isoformat()
        state = {
            "security_envelope": security_envelope,
            "assigned_skills": json.loads(task["assigned_skills_json"]),
            "plan": json.loads(task["plan_json"]) if task["plan_json"] else None,
        }
        self.db.execute(
            """INSERT INTO checkpoints(id,task_id,summary,state_json,message_count,created_by,created_at)
               VALUES(?,?,?,?,?,?,?)""",
            (
                checkpoint_id,
                task_id,
                summary,
                json.dumps(state, ensure_ascii=False),
                len(messages),
                principal.id,
                created_at,
            ),
        )
        self.audit.record(
            principal.id,
            "context.checkpoint.create",
            "task",
            task_id,
            details={
                "checkpoint_id": checkpoint_id,
                "message_count": len(messages),
            },
        )
        return {
            "id": checkpoint_id,
            "task_id": task_id,
            "summary": summary,
            "state": state,
            "message_count": len(messages),
            "created_at": created_at,
        }

    def latest_checkpoint(self, task_id: str) -> dict[str, Any] | None:
        row = self.db.fetch_one(
            "SELECT * FROM checkpoints WHERE task_id=? ORDER BY created_at DESC,id DESC LIMIT 1",
            (task_id,),
        )
        if row is None:
            return None
        return {
            "id": row["id"],
            "task_id": row["task_id"],
            "summary": row["summary"],
            "state": json.loads(row["state_json"]),
            "message_count": row["message_count"],
            "created_at": row["created_at"],
        }
