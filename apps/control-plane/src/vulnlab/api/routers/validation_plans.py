from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Query

from ...schemas import ValidationPlanCreate, ValidationPlanReview
from ...security import Principal
from ...validation import ValidationPlanStateError
from ..dependencies import ServicesDep, owned_task, require

router = APIRouter(tags=["validation-plans"])


@router.post("/api/v1/tasks/{task_id}/validation-plans", status_code=201)
def create_validation_plan(
    task_id: str,
    value: ValidationPlanCreate,
    services: ServicesDep,
    current: Annotated[Principal, Depends(require("validation:create"))],
) -> dict[str, Any]:
    task = owned_task(services, task_id, current)
    return services.validation.create(current, task, value)


@router.get("/api/v1/tasks/{task_id}/validation-plans")
def list_validation_plans(
    task_id: str,
    services: ServicesDep,
    current: Annotated[Principal, Depends(require("validation:read"))],
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
) -> list[dict[str, Any]]:
    owned_task(services, task_id, current)
    return services.validation.list(task_id, limit)


@router.get("/api/v1/validation-plans/{plan_id}")
def get_validation_plan(
    plan_id: str,
    services: ServicesDep,
    current: Annotated[Principal, Depends(require("validation:read"))],
) -> dict[str, Any]:
    try:
        plan = services.validation.get(plan_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    owned_task(services, plan["task_id"], current)
    return plan


@router.post("/api/v1/validation-plans/{plan_id}/submit")
def submit_validation_plan(
    plan_id: str,
    services: ServicesDep,
    current: Annotated[Principal, Depends(require("validation:submit"))],
) -> dict[str, Any]:
    try:
        plan = services.validation.get(plan_id)
        owned_task(services, plan["task_id"], current)
        return services.validation.submit(current, plan_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValidationPlanStateError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.post("/api/v1/validation-plans/{plan_id}/review")
def review_validation_plan(
    plan_id: str,
    value: ValidationPlanReview,
    services: ServicesDep,
    current: Annotated[Principal, Depends(require("validation:review"))],
) -> dict[str, Any]:
    try:
        return services.validation.review(
            current,
            plan_id,
            approved=value.approved,
            reason=value.reason,
        )
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValidationPlanStateError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
