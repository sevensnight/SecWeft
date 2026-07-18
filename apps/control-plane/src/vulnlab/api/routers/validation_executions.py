from __future__ import annotations

import asyncio
import json
from collections.abc import AsyncIterator
from typing import Annotated, Any

from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request
from fastapi.responses import StreamingResponse

from ...schemas import (
    TaskActionRequest,
    ValidationExecutionCreate,
    ValidationExecutionReview,
)
from ...security import Principal
from ...validation_execution import ValidationExecutionStateError, ValidationTemplateError
from ..dependencies import ServicesDep, owned_task, require

router = APIRouter(tags=["validation-executions"])


def _owned_execution(
    services: ServicesDep, execution_id: str, current: Principal
) -> dict[str, Any]:
    try:
        execution = services.validation_execution.get(execution_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    owned_task(services, execution["task_id"], current)
    return execution


@router.post("/api/v1/validation-plans/{plan_id}/executions", status_code=202)
def create_validation_execution(
    plan_id: str,
    value: ValidationExecutionCreate,
    request: Request,
    services: ServicesDep,
    current: Annotated[Principal, Depends(require("validation:execute"))],
    idempotency_key: Annotated[str | None, Header(alias="Idempotency-Key")] = None,
) -> dict[str, Any]:
    try:
        plan = services.validation.get(plan_id)
        owned_task(services, plan["task_id"], current)
        return services.validation_execution.create(
            current,
            plan_id,
            idempotency_key=idempotency_key,
            template_id=value.template_id,
            request_id=request.state.request_id,
        )
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValidationTemplateError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except ValidationExecutionStateError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc


@router.get("/api/v1/validation-executions")
def list_validation_executions(
    services: ServicesDep,
    current: Annotated[Principal, Depends(require("validation:read"))],
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
    status: Annotated[str | None, Query(max_length=64)] = None,
    task_id: Annotated[str | None, Query(max_length=80)] = None,
) -> list[dict[str, Any]]:
    if task_id is not None:
        owned_task(services, task_id, current)
    return services.validation_execution.list_executions(
        current,
        limit=limit,
        status=status,
        task_id=task_id,
    )


@router.get("/api/v1/validation-executions/{execution_id}")
def get_validation_execution(
    execution_id: str,
    services: ServicesDep,
    current: Annotated[Principal, Depends(require("validation:read"))],
) -> dict[str, Any]:
    return _owned_execution(services, execution_id, current)


@router.post("/api/v1/validation-executions/{execution_id}/cancel")
def cancel_validation_execution(
    execution_id: str,
    value: TaskActionRequest,
    services: ServicesDep,
    current: Annotated[Principal, Depends(require("validation:execute"))],
) -> dict[str, Any]:
    _owned_execution(services, execution_id, current)
    return services.validation_execution.cancel(current, execution_id, value.reason)


@router.post("/api/v1/validation-executions/{execution_id}/retry", status_code=202)
def retry_validation_execution(
    execution_id: str,
    services: ServicesDep,
    current: Annotated[Principal, Depends(require("validation:execute"))],
) -> dict[str, Any]:
    _owned_execution(services, execution_id, current)
    try:
        return services.validation_execution.retry(current, execution_id)
    except ValidationExecutionStateError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc


@router.get("/api/v1/validation-executions/{execution_id}/events")
def validation_execution_events(
    execution_id: str,
    services: ServicesDep,
    current: Annotated[Principal, Depends(require("validation:read"))],
    after_id: Annotated[int, Query(ge=0)] = 0,
    limit: Annotated[int, Query(ge=1, le=1000)] = 500,
) -> list[dict[str, Any]]:
    _owned_execution(services, execution_id, current)
    return services.validation_execution.events(execution_id, after_id=after_id, limit=limit)


@router.get(
    "/api/v1/validation-executions/{execution_id}/events/stream",
    response_class=StreamingResponse,
    responses={
        200: {
            "description": "Incremental validation execution event stream with keepalive comments",
            "content": {"text/event-stream": {"schema": {"type": "string"}}},
        }
    },
)
async def stream_validation_execution_events(
    execution_id: str,
    request: Request,
    services: ServicesDep,
    current: Annotated[Principal, Depends(require("validation:read"))],
    last_event_id: Annotated[int | None, Header(alias="Last-Event-ID", ge=0)] = None,
) -> StreamingResponse:
    _owned_execution(services, execution_id, current)

    async def events() -> AsyncIterator[str]:
        cursor = last_event_id or 0
        while not await request.is_disconnected():
            rows = services.validation_execution.events(
                execution_id,
                after_id=cursor,
                limit=100,
            )
            for row in rows:
                cursor = int(row["id"])
                data = json.dumps(row, ensure_ascii=False, separators=(",", ":"))
                yield f"id: {cursor}\nevent: validation-execution-event\ndata: {data}\n\n"
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


@router.get("/api/v1/validation-executions/{execution_id}/evidence")
def validation_execution_evidence(
    execution_id: str,
    services: ServicesDep,
    current: Annotated[Principal, Depends(require("validation:read"))],
    limit: Annotated[int, Query(ge=1, le=500)] = 200,
) -> list[dict[str, Any]]:
    _owned_execution(services, execution_id, current)
    return services.validation_execution.evidence_items(execution_id, limit=limit)


@router.post("/api/v1/validation-executions/{execution_id}/reviews")
def review_validation_execution(
    execution_id: str,
    value: ValidationExecutionReview,
    services: ServicesDep,
    current: Annotated[Principal, Depends(require("validation:review"))],
) -> dict[str, Any]:
    _owned_execution(services, execution_id, current)
    try:
        return services.validation_execution.review(
            current,
            execution_id,
            accepted=value.accepted,
            reason=value.reason,
        )
    except ValidationExecutionStateError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc


@router.get("/api/v1/validation-templates")
def list_validation_templates(
    services: ServicesDep,
    _: Annotated[Principal, Depends(require("validation:read"))],
) -> list[dict[str, Any]]:
    return services.validation_execution.templates()


@router.get("/api/v1/validation-templates/{template_id}")
def get_validation_template(
    template_id: str,
    services: ServicesDep,
    _: Annotated[Principal, Depends(require("validation:read"))],
) -> dict[str, Any]:
    try:
        return services.validation_execution.template(template_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
