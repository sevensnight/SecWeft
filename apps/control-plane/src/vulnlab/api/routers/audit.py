from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, Depends, Query

from ...security import Principal
from ..dependencies import ServicesDep, require

router = APIRouter(prefix="/api/v1/audit", tags=["audit"])


@router.get("")
def list_audit(
    services: ServicesDep,
    _: Annotated[Principal, Depends(require("audit:read"))],
    limit: Annotated[int, Query(ge=1, le=1000)] = 100,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> list[dict[str, Any]]:
    return services.audit.list(limit, offset)


@router.get("/verify")
def verify_audit(
    services: ServicesDep,
    _: Annotated[Principal, Depends(require("audit:read"))],
) -> dict[str, Any]:
    return services.audit.verify()
