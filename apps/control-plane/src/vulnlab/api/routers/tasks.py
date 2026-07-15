from __future__ import annotations

import asyncio
import json
from collections.abc import AsyncIterator
from typing import Annotated, Any

from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request
from fastapi.responses import StreamingResponse

from ...schemas import ApprovalRequest, SkillCreate, TaskCreate
from ...security import Principal
from ..dependencies import ServicesDep, owned_scope, owned_task, require

router = APIRouter(tags=["tasks"])


@router.post("/api/v1/tasks", status_code=201)
def create_task(
    value: TaskCreate,
    services: ServicesDep,
    current: Annotated[Principal, Depends(require("task:create"))],
) -> dict[str, Any]:
    owned_scope(services, value.scope_id, current)
    return services.orchestrator.create(current, value)


@router.get("/api/v1/tasks")
def list_tasks(
    services: ServicesDep,
    current: Annotated[Principal, Depends(require("task:read"))],
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
) -> list[dict[str, Any]]:
    return services.orchestrator.list(current, limit)


@router.get("/api/v1/tasks/{task_id}")
def get_task(
    task_id: str,
    services: ServicesDep,
    current: Annotated[Principal, Depends(require("task:read"))],
) -> dict[str, Any]:
    owned_task(services, task_id, current)
    try:
        return services.orchestrator.get(task_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.get("/api/v1/tasks/{task_id}/events")
def task_events(
    task_id: str,
    services: ServicesDep,
    current: Annotated[Principal, Depends(require("task:read"))],
) -> list[dict[str, Any]]:
    owned_task(services, task_id, current)
    return services.orchestrator.events(task_id)


@router.get(
    "/api/v1/tasks/{task_id}/events/stream",
    response_class=StreamingResponse,
    responses={
        200: {
            "description": "Incremental task event stream with keepalive comments",
            "content": {"text/event-stream": {"schema": {"type": "string"}}},
        }
    },
)
async def stream_task_events(
    task_id: str,
    request: Request,
    services: ServicesDep,
    current: Annotated[Principal, Depends(require("task:read"))],
    last_event_id: Annotated[int | None, Header(alias="Last-Event-ID", ge=0)] = None,
) -> StreamingResponse:
    """Incrementally stream persisted task events; P3 will replace polling with NATS fan-out."""
    owned_task(services, task_id, current)

    async def events() -> AsyncIterator[str]:
        cursor = last_event_id or 0
        while not await request.is_disconnected():
            rows = services.db.fetch_all(
                "SELECT * FROM task_events WHERE task_id=? AND id>? ORDER BY id LIMIT 100",
                (task_id, cursor),
            )
            for row in rows:
                cursor = int(row["id"])
                data = json.dumps(
                    {
                        "id": cursor,
                        "event_type": row["event_type"],
                        "payload": json.loads(row["payload_json"]),
                        "created_at": row["created_at"],
                    },
                    ensure_ascii=False,
                    separators=(",", ":"),
                )
                yield f"id: {cursor}\nevent: task-event\ndata: {data}\n\n"
            if not rows:
                yield ": keepalive\n\n"
            await asyncio.sleep(1)

    return StreamingResponse(
        events(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache, no-transform",
            "X-Accel-Buffering": "no",
        },
    )


@router.post("/api/v1/tasks/{task_id}/approve")
def approve_task(
    task_id: str,
    value: ApprovalRequest,
    services: ServicesDep,
    current: Annotated[Principal, Depends(require("task:approve"))],
) -> dict[str, Any]:
    try:
        return services.orchestrator.approve(current, task_id, value.approved, value.reason)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.post("/api/v1/tasks/{task_id}/run")
async def run_task(
    task_id: str,
    services: ServicesDep,
    current: Annotated[Principal, Depends(require("task:execute"))],
) -> dict[str, Any]:
    if not services.settings.legacy_execution_enabled:
        raise HTTPException(
            status_code=503,
            detail="legacy execution is disabled during the P0/P1 enterprise migration",
        )
    owned_task(services, task_id, current)
    try:
        return await services.orchestrator.run(current, task_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.post("/api/v1/tasks/{task_id}/cancel")
def cancel_task(
    task_id: str,
    services: ServicesDep,
    current: Annotated[Principal, Depends(require("task:cancel"))],
) -> dict[str, Any]:
    owned_task(services, task_id, current)
    try:
        return services.orchestrator.cancel(current, task_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.get("/api/v1/skills")
def list_skills(
    services: ServicesDep,
    _: Annotated[Principal, Depends(require("skill:read"))],
) -> list[dict[str, Any]]:
    return services.skills.list()


@router.post("/api/v1/skills", status_code=201)
def create_skill(
    value: SkillCreate,
    services: ServicesDep,
    current: Annotated[Principal, Depends(require("skill:create"))],
) -> dict[str, Any]:
    return services.skills.create(current, value)


@router.post("/api/v1/skills/{skill_id}/enabled")
def set_skill_enabled(
    skill_id: str,
    enabled: bool,
    services: ServicesDep,
    current: Annotated[Principal, Depends(require("skill:update"))],
) -> dict[str, Any]:
    try:
        return services.skills.set_enabled(current, skill_id, enabled)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.get("/api/v1/protocols/tools")
def protocol_manifest(
    services: ServicesDep,
    _: Annotated[Principal, Depends(require("skill:read"))],
) -> dict[str, Any]:
    return services.skills.protocol_manifest()
