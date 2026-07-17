from __future__ import annotations

import hashlib
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Query

from ...schemas import (
    ContextMessageCreate,
    EvidenceCreate,
    KnowledgePackRequest,
    RAGDocumentCreate,
    RAGSearchRequest,
)
from ...scope import ScopeViolation
from ...security import Principal
from ..dependencies import ServicesDep, owned_task, require

router = APIRouter(tags=["knowledge"])


@router.post("/api/v1/tasks/{task_id}/context", status_code=201)
def add_context(
    task_id: str,
    value: ContextMessageCreate,
    services: ServicesDep,
    current: Annotated[Principal, Depends(require("context:write"))],
) -> dict[str, Any]:
    owned_task(services, task_id, current)
    return services.context.add(current, task_id, value.role, value.content, value.visibility)


@router.get("/api/v1/tasks/{task_id}/context")
def list_context(
    task_id: str,
    services: ServicesDep,
    current: Annotated[Principal, Depends(require("context:read"))],
    limit: Annotated[int, Query(ge=1, le=1000)] = 200,
) -> list[dict[str, Any]]:
    owned_task(services, task_id, current)
    return services.context.list(current, task_id, limit)


@router.post("/api/v1/tasks/{task_id}/checkpoints", status_code=201)
def checkpoint(
    task_id: str,
    services: ServicesDep,
    current: Annotated[Principal, Depends(require("context:write"))],
) -> dict[str, Any]:
    owned_task(services, task_id, current)
    return services.context.checkpoint(current, task_id)


@router.get("/api/v1/tasks/{task_id}/checkpoints")
def list_checkpoints(
    task_id: str,
    services: ServicesDep,
    current: Annotated[Principal, Depends(require("context:read"))],
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
) -> list[dict[str, Any]]:
    owned_task(services, task_id, current)
    return services.context.list_checkpoints(task_id, limit)


@router.get("/api/v1/tasks/{task_id}/checkpoints/latest")
def latest_checkpoint(
    task_id: str,
    services: ServicesDep,
    current: Annotated[Principal, Depends(require("context:read"))],
) -> dict[str, Any] | None:
    owned_task(services, task_id, current)
    return services.context.latest_checkpoint(task_id)


@router.post("/api/v1/tasks/{task_id}/context/restore")
def restore_context(
    task_id: str,
    services: ServicesDep,
    current: Annotated[Principal, Depends(require("context:write"))],
) -> dict[str, Any]:
    task = owned_task(services, task_id, current)
    checkpoint_value = services.context.latest_checkpoint(task_id)
    if checkpoint_value is None:
        raise HTTPException(status_code=404, detail="checkpoint not found")
    scope_valid = True
    scope_error_message = None
    try:
        services.scope.validate(task["target"], task["scope_id"])
        scope_row = services.db.fetch_one(
            "SELECT scope_hash FROM scopes WHERE id=?", (task["scope_id"],)
        )
        if scope_row is None or scope_row["scope_hash"] != task["scope_hash"]:
            raise ScopeViolation("task scope signature no longer matches")
    except ScopeViolation as exc:
        scope_valid = False
        scope_error_message = str(exc)
    current_envelope = {
        "scope_id": task["scope_id"],
        "scope_hash": task["scope_hash"],
        "target": task["target"],
        "intent": task["intent"],
        "approval_status": task["approval_status"],
        "status": task["status"],
        "scope_valid": scope_valid,
        "execution_authorized": bool(
            scope_valid and task["approval_status"] == "approved" and task["status"] == "approved"
        ),
        "policy": "restored context never restores authority; all policy gates are evaluated from current state",
    }
    services.audit.record(
        current.id,
        "context.restore",
        "task",
        task_id,
        details={
            "checkpoint_id": checkpoint_value["id"],
            "scope_valid": scope_valid,
            "execution_authorized": current_envelope["execution_authorized"],
        },
    )
    return {
        "checkpoint_id": checkpoint_value["id"],
        "summary": checkpoint_value["summary"],
        "summary_hash": checkpoint_value["summary_hash"],
        "state_hash": checkpoint_value["state_hash"],
        "restore_policy_hash": checkpoint_value["restore_policy_hash"],
        "current_security_envelope": current_envelope,
        "scope_error": scope_error_message,
    }


@router.post("/api/v1/tasks/{task_id}/evidence", status_code=201)
def add_evidence(
    task_id: str,
    value: EvidenceCreate,
    services: ServicesDep,
    current: Annotated[Principal, Depends(require("context:write"))],
) -> dict[str, Any]:
    owned_task(services, task_id, current)
    return services.evidence.add(current, task_id, value)


@router.get("/api/v1/tasks/{task_id}/evidence")
def list_evidence(
    task_id: str,
    services: ServicesDep,
    current: Annotated[Principal, Depends(require("context:read"))],
    limit: Annotated[int, Query(ge=1, le=500)] = 200,
) -> list[dict[str, Any]]:
    owned_task(services, task_id, current)
    return services.evidence.list(current, task_id, limit)


@router.post("/api/v1/tasks/{task_id}/knowledge-pack")
def build_knowledge_pack(
    task_id: str,
    value: KnowledgePackRequest,
    services: ServicesDep,
    current: Annotated[Principal, Depends(require("context:read"))],
) -> dict[str, Any]:
    task = owned_task(services, task_id, current)
    context_limit = 200 if value.include_private_context else 100
    messages = services.context.list(current, task_id, context_limit)
    if not value.include_private_context:
        messages = [message for message in messages if message["visibility"] == "task"]
    evidence = services.evidence.list(current, task_id, 100)
    rag_results = services.rag.search(
        current,
        value.query,
        value.top_k,
        value.classifications,
    )
    latest = services.context.latest_checkpoint(task_id)
    security_envelope = {
        "scope_id": task["scope_id"],
        "scope_hash": task["scope_hash"],
        "target": task["target"],
        "intent": task["intent"],
        "approval_status": task["approval_status"],
        "status": task["status"],
        "execution_authorized": False,
        "policy": "knowledge packs are read-only context; authority must be evaluated by current task gates",
    }
    services.audit.record(
        current.id,
        "knowledge.pack.build",
        "task",
        task_id,
        details={
            "query_hash": hashlib.sha256(value.query.encode()).hexdigest()[:16],
            "rag_result_count": len(rag_results),
            "evidence_count": len(evidence),
            "message_count": len(messages),
        },
    )
    return {
        "task_id": task_id,
        "query": value.query,
        "security_envelope": security_envelope,
        "messages": messages,
        "latest_checkpoint": latest,
        "evidence": evidence,
        "rag_results": rag_results,
    }


@router.post("/api/v1/rag/documents", status_code=201)
def ingest_rag(
    value: RAGDocumentCreate,
    services: ServicesDep,
    current: Annotated[Principal, Depends(require("rag:write"))],
) -> dict[str, Any]:
    return services.rag.ingest(current, value)


@router.post("/api/v1/rag/search")
def search_rag(
    value: RAGSearchRequest,
    services: ServicesDep,
    current: Annotated[Principal, Depends(require("rag:read"))],
) -> dict[str, Any]:
    return {
        "query": value.query,
        "results": services.rag.search(
            current,
            value.query,
            value.top_k,
            value.classifications,
        ),
    }


@router.get("/api/v1/rag/documents/{document_id}/chunks")
def rag_chunks(
    document_id: str,
    services: ServicesDep,
    current: Annotated[Principal, Depends(require("rag:read"))],
) -> list[dict[str, Any]]:
    chunks = services.rag.chunks(current, document_id)
    if not chunks:
        raise HTTPException(status_code=404, detail="document not found")
    return chunks
