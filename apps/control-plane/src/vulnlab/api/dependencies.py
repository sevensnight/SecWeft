from __future__ import annotations

from collections.abc import Callable
from typing import Annotated, Any

from fastapi import Depends, Header, HTTPException, Request, status

from ..security import AuthenticationError, PermissionDenied, Principal
from .services import Services


def get_services(request: Request) -> Services:
    return request.app.state.services


ServicesDep = Annotated[Services, Depends(get_services)]


def principal(
    services: ServicesDep,
    x_api_key: Annotated[str | None, Header(alias="X-API-Key")] = None,
) -> Principal:
    if services.settings.auth_mode != "compatibility":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="API-key compatibility authentication is disabled",
            headers={"WWW-Authenticate": "Bearer"},
        )
    try:
        return services.security.authenticate(x_api_key)
    except AuthenticationError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(exc),
            headers={"WWW-Authenticate": "ApiKey"},
        ) from exc


CurrentPrincipal = Annotated[Principal, Depends(principal)]


def require(permission: str) -> Callable[..., Principal]:
    def dependency(services: ServicesDep, current: CurrentPrincipal) -> Principal:
        try:
            services.security.require(current, permission)
        except PermissionDenied as exc:
            services.audit.record(
                current.id,
                "authorization.denied",
                "permission",
                permission,
                "denied",
                {"role": current.role.value},
            )
            raise HTTPException(status_code=403, detail=str(exc)) from exc
        return current

    return dependency


def find_task(services: Services, task_id: str) -> Any:
    row = services.db.fetch_one("SELECT * FROM tasks WHERE id=?", (task_id,))
    if row is None:
        raise HTTPException(status_code=404, detail="task not found")
    return row


def require_owner(
    services: Services,
    row: Any,
    current: Principal,
    resource_type: str,
    resource_id: str,
) -> None:
    if current.role.value == "admin" or row["created_by"] == current.id:
        return
    services.audit.record(
        current.id,
        "authorization.object.denied",
        resource_type,
        resource_id,
        "denied",
        {"reason": "resource belongs to another principal"},
    )
    raise HTTPException(status_code=404, detail=f"{resource_type} not found")


def owned_task(services: Services, task_id: str, current: Principal) -> Any:
    row = find_task(services, task_id)
    require_owner(services, row, current, "task", task_id)
    return row


def owned_scope(services: Services, scope_id: str, current: Principal) -> Any:
    row = services.db.fetch_one("SELECT * FROM scopes WHERE id=?", (scope_id,))
    if row is None:
        raise HTTPException(status_code=404, detail="scope not found")
    require_owner(services, row, current, "scope", scope_id)
    return row
