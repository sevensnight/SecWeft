from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException

from ...schemas import ContextMessageCreate, RAGDocumentCreate, RAGSearchRequest
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
) -> list[dict[str, Any]]:
    owned_task(services, task_id, current)
    return services.context.list(current, task_id)


@router.post("/api/v1/tasks/{task_id}/checkpoints", status_code=201)
def checkpoint(
    task_id: str,
    services: ServicesDep,
    current: Annotated[Principal, Depends(require("context:write"))],
) -> dict[str, Any]:
    owned_task(services, task_id, current)
    return services.context.checkpoint(current, task_id)


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
        "current_security_envelope": current_envelope,
        "scope_error": scope_error_message,
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
