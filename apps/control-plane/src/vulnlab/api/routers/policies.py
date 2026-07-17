from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, Depends

from ...schemas import PolicyEvaluationRequest
from ...security import Principal
from ..dependencies import ServicesDep, require

router = APIRouter(tags=["policies"])


@router.post("/api/v1/policies/evaluate")
def evaluate_policy(
    value: PolicyEvaluationRequest,
    services: ServicesDep,
    current: Annotated[Principal, Depends(require("policy:evaluate"))],
) -> dict[str, Any]:
    return services.policy.evaluate(current, value)
