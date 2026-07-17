from __future__ import annotations

import hashlib
import json
import uuid
from datetime import UTC, datetime
from typing import Any

from .audit import AuditService
from .context import scrub_secrets
from .db import Database
from .rag import ROLE_CLASSIFICATIONS
from .schemas import EvidenceCreate
from .security import Principal


class EvidenceService:
    def __init__(self, db: Database, audit: AuditService):
        self.db = db
        self.audit = audit

    def add(self, principal: Principal, task_id: str, value: EvidenceCreate) -> dict[str, Any]:
        if value.classification not in ROLE_CLASSIFICATIONS[principal.role]:
            raise PermissionError("cannot create evidence above your classification")
        safe_content = scrub_secrets(value.content)
        content_hash = hashlib.sha256(safe_content.encode()).hexdigest()
        evidence_id = str(uuid.uuid4())
        created_at = datetime.now(UTC).isoformat()
        self.db.execute(
            """INSERT INTO evidence_items(
               id, task_id, title, source_type, source_ref, content, content_hash,
               classification, trust, metadata_json, created_by, created_at
               ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                evidence_id,
                task_id,
                value.title,
                value.source_type,
                value.source_ref,
                safe_content,
                content_hash,
                value.classification,
                value.trust,
                json.dumps(value.metadata, ensure_ascii=False, sort_keys=True),
                principal.id,
                created_at,
            ),
        )
        self.audit.record(
            principal.id,
            "evidence.item.add",
            "task",
            task_id,
            details={
                "evidence_id": evidence_id,
                "source_type": value.source_type,
                "classification": value.classification,
                "trust": value.trust,
                "content_hash": content_hash,
                "redacted": safe_content != value.content,
            },
        )
        return {
            "id": evidence_id,
            "task_id": task_id,
            "title": value.title,
            "source_type": value.source_type,
            "source_ref": value.source_ref,
            "content": safe_content,
            "content_hash": content_hash,
            "classification": value.classification,
            "trust": value.trust,
            "metadata": value.metadata,
            "created_by": principal.id,
            "created_at": created_at,
        }

    def list(self, principal: Principal, task_id: str, limit: int = 200) -> list[dict[str, Any]]:
        allowed = ROLE_CLASSIFICATIONS[principal.role]
        placeholders = ",".join("?" for _ in allowed)
        rows = self.db.fetch_all(
            f"""SELECT * FROM evidence_items
                WHERE task_id=? AND classification IN ({placeholders})
                ORDER BY created_at DESC, id DESC LIMIT ?""",
            (task_id, *sorted(allowed), min(max(limit, 1), 500)),
        )
        return [
            {
                "id": row["id"],
                "task_id": row["task_id"],
                "title": row["title"],
                "source_type": row["source_type"],
                "source_ref": row["source_ref"],
                "content": row["content"],
                "content_hash": row["content_hash"],
                "classification": row["classification"],
                "trust": row["trust"],
                "metadata": json.loads(row["metadata_json"]),
                "created_by": row["created_by"],
                "created_at": row["created_at"],
            }
            for row in rows
        ]
