from __future__ import annotations

import hashlib
import json
import math
import re
import uuid
from collections.abc import Sequence
from datetime import UTC, datetime
from typing import Any

from .audit import AuditService
from .context import scrub_secrets
from .db import Database
from .schemas import RAGDocumentCreate, Role
from .security import Principal

TOKEN_RE = re.compile(r"[A-Za-z0-9_+#.-]{2,}|[\u4e00-\u9fff]")


def _tokens(text: str) -> set[str]:
    return {token.lower() for token in TOKEN_RE.findall(text)}


ROLE_CLASSIFICATIONS: dict[Role, frozenset[str]] = {
    Role.VIEWER: frozenset({"public"}),
    Role.ANALYST: frozenset({"public", "internal"}),
    Role.OPERATOR: frozenset({"public", "internal", "restricted"}),
    Role.ADMIN: frozenset({"public", "internal", "restricted"}),
}


class RAGService:
    def __init__(self, db: Database, audit: AuditService):
        self.db = db
        self.audit = audit

    def ingest(self, principal: Principal, value: RAGDocumentCreate) -> dict[str, Any]:
        if value.classification not in ROLE_CLASSIFICATIONS[principal.role]:
            raise PermissionError("cannot create a document above your classification")
        safe_content = scrub_secrets(value.content)
        content_hash = hashlib.sha256(safe_content.encode()).hexdigest()
        document_id = str(uuid.uuid4())
        created_at = datetime.now(UTC).isoformat()
        self.db.execute(
            """INSERT INTO rag_documents(id,title,content,source,classification,version,tags_json,
               content_hash,created_by,created_at) VALUES(?,?,?,?,?,?,?,?,?,?)""",
            (
                document_id,
                value.title,
                safe_content,
                value.source,
                value.classification,
                value.version,
                json.dumps(value.tags, ensure_ascii=False),
                content_hash,
                principal.id,
                created_at,
            ),
        )
        self.audit.record(
            principal.id,
            "rag.document.ingest",
            "rag_document",
            document_id,
            details={
                "source": value.source,
                "version": value.version,
                "classification": value.classification,
                "content_hash": content_hash,
                "secrets_redacted": safe_content != value.content,
            },
        )
        return {
            "id": document_id,
            "title": value.title,
            "source": value.source,
            "classification": value.classification,
            "version": value.version,
            "tags": value.tags,
            "content_hash": content_hash,
            "created_at": created_at,
        }

    def search(
        self,
        principal: Principal,
        query: str,
        top_k: int,
        classifications: Sequence[str] | None,
    ) -> list[dict[str, Any]]:
        allowed = set(ROLE_CLASSIFICATIONS[principal.role])
        if classifications is not None:
            requested = set(classifications)
            if not requested <= allowed:
                raise PermissionError("requested classification is not authorized")
            allowed &= requested
        if not allowed:
            return []
        placeholders = ",".join("?" for _ in allowed)
        # ACL pre-filtering happens in SQL before any scoring or model use.
        rows = self.db.fetch_all(
            f"SELECT * FROM rag_documents WHERE classification IN ({placeholders})",
            tuple(sorted(allowed)),
        )
        query_tokens = _tokens(query)
        results: list[dict[str, Any]] = []
        for row in rows:
            document_tokens = _tokens(row["title"] + " " + row["content"] + " " + row["tags_json"])
            overlap = len(query_tokens & document_tokens)
            if not overlap:
                continue
            score = overlap / math.sqrt(max(1, len(query_tokens)) * max(1, len(document_tokens)))
            results.append(
                {
                    "id": row["id"],
                    "title": row["title"],
                    "excerpt": row["content"][:1000],
                    "source": row["source"],
                    "version": row["version"],
                    "classification": row["classification"],
                    "tags": json.loads(row["tags_json"]),
                    "content_hash": row["content_hash"],
                    "score": round(score, 6),
                    "trust": "untrusted_evidence_only",
                }
            )
        results.sort(key=lambda item: (-item["score"], item["id"]))
        selected = results[:top_k]
        self.audit.record(
            principal.id,
            "rag.search",
            "rag_query",
            hashlib.sha256(query.encode()).hexdigest()[:16],
            details={
                "classifications": sorted(allowed),
                "top_k": top_k,
                "result_ids": [item["id"] for item in selected],
            },
        )
        return selected
