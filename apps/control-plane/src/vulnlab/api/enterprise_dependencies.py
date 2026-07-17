from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Annotated, Literal
from uuid import UUID

from fastapi import Depends, Header, Request

from ..enterprise.errors import (
    EnterpriseAuthenticationError,
    EnterpriseAuthorizationError,
    EnterpriseUnavailableError,
    EnterpriseValidationError,
)
from ..enterprise.models import EnterprisePrincipal
from ..enterprise.services import EnterpriseServices
from .dependencies import ServicesDep


@dataclass(frozen=True, slots=True)
class EnterpriseRequestContext:
    principal: EnterprisePrincipal
    project_id: UUID | None
    request_id: str
    trace_id: str


def enterprise_services(services: ServicesDep) -> EnterpriseServices:
    if services.enterprise is None:
        raise EnterpriseUnavailableError("enterprise API requires VULNLAB_AUTH_MODE=oidc")
    return services.enterprise


EnterpriseServicesDep = Annotated[EnterpriseServices, Depends(enterprise_services)]


def enterprise_context(
    request: Request,
    enterprise: EnterpriseServicesDep,
    authorization: Annotated[str | None, Header(alias="Authorization")] = None,
    x_project_id: Annotated[str | None, Header(alias="X-Project-ID")] = None,
) -> EnterpriseRequestContext:
    if authorization is None:
        raise EnterpriseAuthenticationError()
    scheme, separator, token = authorization.partition(" ")
    if separator != " " or scheme.lower() != "bearer" or not token:
        raise EnterpriseAuthenticationError()
    identity = enterprise.verifier.verify(token)
    principal = enterprise.repository.resolve_principal(identity)
    project_id: UUID | None = None
    if x_project_id is not None:
        try:
            project_id = UUID(x_project_id)
        except ValueError as exc:
            raise EnterpriseValidationError("X-Project-ID must be a UUID") from exc
    request.state.tenant_id = str(principal.tenant_id)
    request.state.user_id = str(principal.user_id)
    request.state.project_id = str(project_id) if project_id else None
    return EnterpriseRequestContext(
        principal=principal,
        project_id=project_id,
        request_id=request.state.request_id,
        trace_id=request.state.trace_id,
    )


EnterpriseContext = Annotated[EnterpriseRequestContext, Depends(enterprise_context)]


def _has_any_project_permission(principal: EnterprisePrincipal, permission: str) -> bool:
    return any(permission in permissions for permissions in principal.project_permissions.values())


def require_enterprise(
    permission: str,
    *,
    scope: Literal["tenant", "project", "any"] = "any",
) -> Callable[..., EnterpriseRequestContext]:
    def dependency(
        request: Request,
        enterprise: EnterpriseServicesDep,
        context: EnterpriseContext,
    ) -> EnterpriseRequestContext:
        if scope == "tenant":
            allowed = context.principal.can(permission)
            project_id = None
        elif scope == "project":
            if context.project_id is None:
                raise EnterpriseValidationError("X-Project-ID is required")
            project_id = context.project_id
            allowed = context.principal.can(permission, project_id)
        else:
            project_id = context.project_id
            allowed = (
                context.principal.can(permission, project_id)
                if project_id is not None
                else context.principal.can(permission)
                or _has_any_project_permission(context.principal, permission)
            )
        if allowed:
            return context
        enterprise.repository.audit_denial(
            context.principal,
            permission=permission,
            project_id=project_id,
            request_id=context.request_id,
            trace_id=context.trace_id,
            resource=request.url.path,
        )
        raise EnterpriseAuthorizationError(f"permission {permission} is required")

    return dependency


def idempotency_key(
    value: Annotated[str | None, Header(alias="Idempotency-Key")] = None,
) -> str:
    if value is None:
        raise EnterpriseValidationError("Idempotency-Key is required")
    return value


IdempotencyKey = Annotated[str, Depends(idempotency_key)]


def authorize_dynamic(
    *,
    request: Request,
    enterprise: EnterpriseServices,
    context: EnterpriseRequestContext,
    permission: str,
    project_id: UUID | None,
) -> None:
    if context.principal.can(permission, project_id):
        return
    enterprise.repository.audit_denial(
        context.principal,
        permission=permission,
        project_id=project_id,
        request_id=context.request_id,
        trace_id=context.trace_id,
        resource=request.url.path,
    )
    raise EnterpriseAuthorizationError(f"permission {permission} is required")
