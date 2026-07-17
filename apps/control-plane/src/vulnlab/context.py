from __future__ import annotations

import builtins
import hashlib
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
        content_hash = hashlib.sha256(safe_content.encode()).hexdigest()
        created_at = datetime.now(UTC).isoformat()
        with self.db.transaction() as connection:
            row = connection.execute(
                "SELECT COALESCE(MAX(sequence_no), 0) + 1 AS next_sequence FROM memory_messages WHERE task_id=?",
                (task_id,),
            ).fetchone()
            sequence_no = int(row["next_sequence"]) if row is not None else 1
            connection.execute(
                """INSERT INTO memory_messages(
                   id,task_id,owner_id,role,content,content_hash,visibility,sequence_no,
                   token_estimate,created_at
                   ) VALUES(?,?,?,?,?,?,?,?,?,?)""",
                (
                    message_id,
                    task_id,
                    principal.id,
                    role,
                    safe_content,
                    content_hash,
                    visibility,
                    sequence_no,
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
                "sequence_no": sequence_no,
                "content_hash": content_hash,
                "redacted": safe_content != content,
            },
        )
        return {
            "id": message_id,
            "task_id": task_id,
            "owner_id": principal.id,
            "role": role,
            "content": safe_content,
            "content_hash": content_hash,
            "visibility": visibility,
            "sequence_no": sequence_no,
            "token_estimate": max(1, len(safe_content) // 4),
            "created_at": created_at,
        }

    def list(
        self, principal: Principal, task_id: str, limit: int = 200
    ) -> builtins.list[dict[str, Any]]:
        rows = self.db.fetch_all(
            """SELECT * FROM memory_messages WHERE task_id=? AND (visibility='task' OR owner_id=?)
               ORDER BY sequence_no,created_at,id LIMIT ?""",
            (task_id, principal.id, min(max(limit, 1), 1000)),
        )
        return [dict(row) for row in rows]

    def list_checkpoints(self, task_id: str, limit: int = 50) -> builtins.list[dict[str, Any]]:
        rows = self.db.fetch_all(
            "SELECT * FROM checkpoints WHERE task_id=? ORDER BY created_at DESC,id DESC LIMIT ?",
            (task_id, min(max(limit, 1), 200)),
        )
        return [self._checkpoint_from_row(row) for row in rows]

    def checkpoint(self, principal: Principal, task_id: str) -> dict[str, Any]:
        task = self.db.fetch_one("SELECT * FROM tasks WHERE id=?", (task_id,))
        if task is None:
            raise KeyError("task not found")
        messages = self.list(principal, task_id, 1000)
        latest = messages[-12:]
        excerpts = [f"{item['role']}: {item['content'][:240]}" for item in latest]
        security_envelope = {
            "scope_id": task["scope_id"],
            "scope_hash": task["scope_hash"],
            "target": task["target"],
            "intent": task["intent"],
            "approval_status": task["approval_status"],
            "status": task["status"],
            "policy": "scope and approval must be revalidated before every side effect",
        }
        evidence_rows = self.db.fetch_all(
            """SELECT id, title, source_type, source_ref, content_hash, classification, trust
               FROM evidence_items WHERE task_id=? ORDER BY created_at DESC,id DESC LIMIT 100""",
            (task_id,),
        )
        evidence_refs = [
            {
                "id": row["id"],
                "title": row["title"],
                "source_type": row["source_type"],
                "source_ref": row["source_ref"],
                "content_hash": row["content_hash"],
                "classification": row["classification"],
                "trust": row["trust"],
            }
            for row in evidence_rows
        ]
        summary = "\n".join(excerpts) if excerpts else "No conversational context."
        summary = f"SECURITY_ENVELOPE={json.dumps(security_envelope, ensure_ascii=False, sort_keys=True)}\n{summary}"
        checkpoint_id = str(uuid.uuid4())
        created_at = datetime.now(UTC).isoformat()
        state = {
            "security_envelope": security_envelope,
            "assigned_skills": json.loads(task["assigned_skills_json"]),
            "plan": json.loads(task["plan_json"]) if task["plan_json"] else None,
            "message_hashes": [item["content_hash"] for item in messages],
            "evidence_refs": evidence_refs,
        }
        state_json = json.dumps(state, ensure_ascii=False, sort_keys=True)
        summary_hash = hashlib.sha256(summary.encode()).hexdigest()
        state_hash = hashlib.sha256(state_json.encode()).hexdigest()
        restore_policy_hash = hashlib.sha256(
            b"restored-context-never-restores-authority:v1"
        ).hexdigest()
        self.db.execute(
            """INSERT INTO checkpoints(
               id,task_id,summary,state_json,summary_hash,state_hash,message_count,
               evidence_count,restore_policy_hash,created_by,created_at
               ) VALUES(?,?,?,?,?,?,?,?,?,?,?)""",
            (
                checkpoint_id,
                task_id,
                summary,
                state_json,
                summary_hash,
                state_hash,
                len(messages),
                len(evidence_refs),
                restore_policy_hash,
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
                "evidence_count": len(evidence_refs),
                "summary_hash": summary_hash,
                "state_hash": state_hash,
            },
        )
        return {
            "id": checkpoint_id,
            "task_id": task_id,
            "summary": summary,
            "state": state,
            "summary_hash": summary_hash,
            "state_hash": state_hash,
            "message_count": len(messages),
            "evidence_count": len(evidence_refs),
            "restore_policy_hash": restore_policy_hash,
            "created_at": created_at,
        }

    def latest_checkpoint(self, task_id: str) -> dict[str, Any] | None:
        row = self.db.fetch_one(
            "SELECT * FROM checkpoints WHERE task_id=? ORDER BY created_at DESC,id DESC LIMIT 1",
            (task_id,),
        )
        if row is None:
            return None
        return self._checkpoint_from_row(row)

    @staticmethod
    def _checkpoint_from_row(row: Any) -> dict[str, Any]:
        return {
            "id": row["id"],
            "task_id": row["task_id"],
            "summary": row["summary"],
            "state": json.loads(row["state_json"]),
            "summary_hash": row["summary_hash"],
            "state_hash": row["state_hash"],
            "message_count": row["message_count"],
            "evidence_count": row["evidence_count"],
            "restore_policy_hash": row["restore_policy_hash"],
            "created_at": row["created_at"],
        }
