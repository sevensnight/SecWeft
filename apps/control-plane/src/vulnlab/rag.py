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
from .repository import ControlPlaneRepository
from .schemas import RAGDocumentCreate, Role
from .security import Principal

TOKEN_RE = re.compile(r"[A-Za-z0-9_+#.-]{2,}|[\u4e00-\u9fff]")
MAX_CHUNK_CHARS = 1400
CHUNK_OVERLAP_CHARS = 160


def _tokens(text: str) -> set[str]:
    return {token.lower() for token in TOKEN_RE.findall(text)}


def chunk_text(text: str) -> list[str]:
    normalized = re.sub(r"\n{3,}", "\n\n", text.strip())
    if len(normalized) <= MAX_CHUNK_CHARS:
        return [normalized]
    chunks: list[str] = []
    cursor = 0
    while cursor < len(normalized):
        end = min(len(normalized), cursor + MAX_CHUNK_CHARS)
        if end < len(normalized):
            boundary = max(
                normalized.rfind("\n\n", cursor, end),
                normalized.rfind(". ", cursor, end),
                normalized.rfind("。", cursor, end),
            )
            if boundary > cursor + MAX_CHUNK_CHARS // 2:
                end = boundary + 1
        chunk = normalized[cursor:end].strip()
        if chunk:
            chunks.append(chunk)
        if end >= len(normalized):
            break
        cursor = max(end - CHUNK_OVERLAP_CHARS, cursor + 1)
    return chunks or [normalized]


ROLE_CLASSIFICATIONS: dict[Role, frozenset[str]] = {
    Role.VIEWER: frozenset({"public"}),
    Role.ANALYST: frozenset({"public", "internal"}),
    Role.OPERATOR: frozenset({"public", "internal", "restricted"}),
    Role.ADMIN: frozenset({"public", "internal", "restricted"}),
}


class RAGService:
    def __init__(self, db: ControlPlaneRepository, audit: AuditService):
        self.db = db
        self.audit = audit

    def ingest(self, principal: Principal, value: RAGDocumentCreate) -> dict[str, Any]:
        if value.classification not in ROLE_CLASSIFICATIONS[principal.role]:
            raise PermissionError("cannot create a document above your classification")
        safe_content = scrub_secrets(value.content)
        content_hash = hashlib.sha256(safe_content.encode()).hexdigest()
        document_id = str(uuid.uuid4())
        created_at = datetime.now(UTC).isoformat()
        chunks = chunk_text(safe_content)
        with self.db.transaction() as connection:
            connection.execute(
                """INSERT INTO rag_documents(
                   id,tenant_key,project_key,title,content,source,classification,version,
                   tags_json,metadata_json,content_hash,created_by,created_at
                   ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    document_id,
                    "compat",
                    None,
                    value.title,
                    safe_content,
                    value.source,
                    value.classification,
                    value.version,
                    json.dumps(value.tags, ensure_ascii=False),
                    json.dumps(value.metadata, ensure_ascii=False, sort_keys=True),
                    content_hash,
                    principal.id,
                    created_at,
                ),
            )
            for index, chunk in enumerate(chunks):
                chunk_hash = hashlib.sha256(chunk.encode()).hexdigest()
                connection.execute(
                    """INSERT INTO rag_chunks(
                       id,document_id,chunk_index,content,token_estimate,chunk_hash,created_at
                       ) VALUES(?,?,?,?,?,?,?)""",
                    (
                        str(uuid.uuid4()),
                        document_id,
                        index,
                        chunk,
                        max(1, len(chunk) // 4),
                        chunk_hash,
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
                "chunk_count": len(chunks),
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
            "metadata": value.metadata,
            "content_hash": content_hash,
            "chunk_count": len(chunks),
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
            f"""SELECT d.id AS document_id, d.title, d.source, d.version, d.classification,
                       d.tags_json, d.metadata_json, d.content_hash, c.id AS chunk_id,
                       c.chunk_index, c.content AS chunk_content, c.chunk_hash
                FROM rag_documents AS d
                JOIN rag_chunks AS c ON c.document_id = d.id
                WHERE d.classification IN ({placeholders})""",
            tuple(sorted(allowed)),
        )
        query_tokens = _tokens(query)
        results: list[dict[str, Any]] = []
        for row in rows:
            document_tokens = _tokens(
                row["title"] + " " + row["chunk_content"] + " " + row["tags_json"]
            )
            overlap = len(query_tokens & document_tokens)
            if not overlap:
                continue
            score = overlap / math.sqrt(max(1, len(query_tokens)) * max(1, len(document_tokens)))
            results.append(
                {
                    "id": row["document_id"],
                    "document_id": row["document_id"],
                    "chunk_id": row["chunk_id"],
                    "chunk_index": row["chunk_index"],
                    "title": row["title"],
                    "excerpt": row["chunk_content"][:1000],
                    "source": row["source"],
                    "version": row["version"],
                    "classification": row["classification"],
                    "tags": json.loads(row["tags_json"]),
                    "metadata": json.loads(row["metadata_json"]),
                    "content_hash": row["content_hash"],
                    "chunk_hash": row["chunk_hash"],
                    "score": round(score, 6),
                    "trust": "untrusted_evidence_only",
                    "citation": {
                        "document_id": row["document_id"],
                        "chunk_id": row["chunk_id"],
                        "source": row["source"],
                        "version": row["version"],
                        "content_hash": row["content_hash"],
                        "chunk_hash": row["chunk_hash"],
                    },
                }
            )
        results.sort(key=lambda item: (-item["score"], item["document_id"], item["chunk_index"]))
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

    def chunks(self, principal: Principal, document_id: str) -> list[dict[str, Any]]:
        allowed = ROLE_CLASSIFICATIONS[principal.role]
        placeholders = ",".join("?" for _ in allowed)
        rows = self.db.fetch_all(
            f"""SELECT d.id AS document_id, d.title, d.source, d.version, d.classification,
                       d.content_hash, c.id AS chunk_id, c.chunk_index, c.content,
                       c.token_estimate, c.chunk_hash, c.created_at
                FROM rag_documents AS d
                JOIN rag_chunks AS c ON c.document_id = d.id
                WHERE d.id=? AND d.classification IN ({placeholders})
                ORDER BY c.chunk_index""",
            (document_id, *sorted(allowed)),
        )
        return [
            {
                "document_id": row["document_id"],
                "chunk_id": row["chunk_id"],
                "chunk_index": row["chunk_index"],
                "title": row["title"],
                "source": row["source"],
                "version": row["version"],
                "classification": row["classification"],
                "content_hash": row["content_hash"],
                "content": row["content"],
                "token_estimate": row["token_estimate"],
                "chunk_hash": row["chunk_hash"],
                "created_at": row["created_at"],
            }
            for row in rows
        ]
