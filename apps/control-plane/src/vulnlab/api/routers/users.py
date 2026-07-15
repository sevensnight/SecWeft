from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException

from ...schemas import UserCreate, UserUpdate
from ...security import Principal
from ..dependencies import ServicesDep, require

router = APIRouter(prefix="/api/v1/users", tags=["authorization"])


@router.post("", status_code=201)
def create_user(
    value: UserCreate,
    services: ServicesDep,
    current: Annotated[Principal, Depends(require("user:create"))],
) -> dict[str, Any]:
    record, api_key = services.security.create_user(value.username, value.role)
    services.audit.record(
        current.id,
        "user.create",
        "user",
        str(record["id"]),
        details={"username": value.username, "role": value.role.value},
    )
    return {**record, "api_key": api_key}


@router.get("")
def list_users(
    services: ServicesDep,
    _: Annotated[Principal, Depends(require("user:read"))],
) -> list[dict[str, Any]]:
    return [
        {
            "id": row["id"],
            "username": row["username"],
            "role": row["role"],
            "active": bool(row["active"]),
            "created_at": row["created_at"],
        }
        for row in services.db.fetch_all(
            "SELECT id,username,role,active,created_at FROM users ORDER BY username"
        )
    ]


@router.patch("/{user_id}")
def update_user(
    user_id: str,
    value: UserUpdate,
    services: ServicesDep,
    current: Annotated[Principal, Depends(require("user:update"))],
) -> dict[str, Any]:
    if user_id == current.id and (
        value.active is False or (value.role is not None and value.role.value != "admin")
    ):
        raise HTTPException(
            status_code=409,
            detail="administrators cannot deactivate or demote their own active session",
        )
    try:
        updated = services.security.update_user(user_id, value.role, value.active)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    services.audit.record(
        current.id,
        "user.update",
        "user",
        user_id,
        details={"role": updated["role"], "active": updated["active"]},
    )
    return updated
