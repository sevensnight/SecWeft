from __future__ import annotations

from collections.abc import Sequence
from typing import Annotated, Any
from uuid import UUID

from fastapi import APIRouter, Depends, Query, Request, Response, status

from ...enterprise.models import (
    AuditEventResponse,
    ConfigEntryResponse,
    ConfigEntryUpdate,
    EffectiveConfigResponse,
    OrganizationCreate,
    OrganizationResponse,
    PageMeta,
    PageResponse,
    ProjectCreate,
    ProjectResponse,
    RoleAssignmentCreate,
    RoleAssignmentResponse,
    RoleAssignmentRevoke,
    RoleResponse,
    SessionResponse,
    TenantResponse,
    UserProvisionCreate,
    UserResponse,
    session_from_principal,
)
from ..enterprise_dependencies import (
    EnterpriseContext,
    EnterpriseRequestContext,
    EnterpriseServicesDep,
    IdempotencyKey,
    authorize_dynamic,
    require_enterprise,
)

router = APIRouter(prefix="/api/v1", tags=["P1 identity and tenancy"])

PageSize = Annotated[int, Query(ge=1, le=100)]


def _page(items: Sequence[Any], next_cursor: str | None, page_size: int) -> PageResponse[Any]:
    return PageResponse(
        items=list(items),
        page=PageMeta(
            next_cursor=next_cursor,
            has_more=next_cursor is not None,
            page_size=page_size,
        ),
    )


@router.get("/session", response_model=SessionResponse, operation_id="getEnterpriseSession")
def get_session(context: EnterpriseContext) -> SessionResponse:
    return session_from_principal(context.principal)


@router.get(
    "/tenants/current",
    response_model=TenantResponse,
    operation_id="getCurrentTenant",
)
def get_current_tenant(
    enterprise: EnterpriseServicesDep,
    context: Annotated[
        EnterpriseRequestContext, Depends(require_enterprise("tenant.read", scope="tenant"))
    ],
) -> TenantResponse:
    return TenantResponse.model_validate(enterprise.repository.get_tenant(context.principal))


@router.get(
    "/organizations",
    response_model=PageResponse[OrganizationResponse],
    operation_id="listOrganizations",
)
def list_organizations(
    enterprise: EnterpriseServicesDep,
    context: Annotated[
        EnterpriseRequestContext, Depends(require_enterprise("project.read", scope="any"))
    ],
    page_size: PageSize = 50,
    cursor: str | None = None,
) -> PageResponse[Any]:
    items, next_cursor = enterprise.repository.list_organizations(
        context.principal, page_size=page_size, cursor=cursor
    )
    return _page(items, next_cursor, page_size)


@router.post(
    "/organizations",
    response_model=OrganizationResponse,
    status_code=status.HTTP_201_CREATED,
    operation_id="createOrganization",
)
def create_organization(
    payload: OrganizationCreate,
    response: Response,
    enterprise: EnterpriseServicesDep,
    idempotency_key: IdempotencyKey,
    context: Annotated[
        EnterpriseRequestContext, Depends(require_enterprise("project.create", scope="tenant"))
    ],
) -> OrganizationResponse:
    result = enterprise.repository.create_organization(
        context.principal,
        slug=payload.slug,
        display_name=payload.display_name,
        idempotency_key=idempotency_key,
        request_id=context.request_id,
        trace_id=context.trace_id,
    )
    response.headers["Idempotency-Replayed"] = str(result.replayed).lower()
    return OrganizationResponse.model_validate(result.body)


@router.get(
    "/projects",
    response_model=PageResponse[ProjectResponse],
    operation_id="listProjects",
)
def list_projects(
    enterprise: EnterpriseServicesDep,
    context: Annotated[
        EnterpriseRequestContext, Depends(require_enterprise("project.read", scope="any"))
    ],
    page_size: PageSize = 50,
    cursor: str | None = None,
) -> PageResponse[Any]:
    items, next_cursor = enterprise.repository.list_projects(
        context.principal, page_size=page_size, cursor=cursor
    )
    return _page(items, next_cursor, page_size)


@router.post(
    "/projects",
    response_model=ProjectResponse,
    status_code=status.HTTP_201_CREATED,
    operation_id="createProject",
)
def create_project(
    payload: ProjectCreate,
    response: Response,
    enterprise: EnterpriseServicesDep,
    idempotency_key: IdempotencyKey,
    context: Annotated[
        EnterpriseRequestContext, Depends(require_enterprise("project.create", scope="tenant"))
    ],
) -> ProjectResponse:
    result = enterprise.repository.create_project(
        context.principal,
        organization_id=payload.organization_id,
        slug=payload.slug,
        display_name=payload.display_name,
        idempotency_key=idempotency_key,
        request_id=context.request_id,
        trace_id=context.trace_id,
    )
    response.headers["Idempotency-Replayed"] = str(result.replayed).lower()
    return ProjectResponse.model_validate(result.body)


@router.get(
    "/iam/users",
    response_model=PageResponse[UserResponse],
    operation_id="listTenantUsers",
)
def list_users(
    enterprise: EnterpriseServicesDep,
    context: Annotated[
        EnterpriseRequestContext, Depends(require_enterprise("membership.read", scope="tenant"))
    ],
    page_size: PageSize = 50,
    cursor: str | None = None,
) -> PageResponse[Any]:
    items, next_cursor = enterprise.repository.list_users(
        context.principal, page_size=page_size, cursor=cursor
    )
    return _page(items, next_cursor, page_size)


@router.post(
    "/iam/users",
    response_model=UserResponse,
    status_code=status.HTTP_201_CREATED,
    operation_id="provisionTenantUser",
)
def provision_user(
    payload: UserProvisionCreate,
    response: Response,
    enterprise: EnterpriseServicesDep,
    idempotency_key: IdempotencyKey,
    context: Annotated[
        EnterpriseRequestContext, Depends(require_enterprise("membership.invite", scope="tenant"))
    ],
) -> UserResponse:
    result = enterprise.repository.provision_user(
        context.principal,
        issuer=enterprise.verifier.issuer,
        subject=payload.subject,
        username=payload.username,
        email=payload.email,
        idempotency_key=idempotency_key,
        request_id=context.request_id,
        trace_id=context.trace_id,
    )
    response.headers["Idempotency-Replayed"] = str(result.replayed).lower()
    return UserResponse.model_validate(result.body)


@router.get(
    "/iam/roles",
    response_model=PageResponse[RoleResponse],
    operation_id="listTenantRoles",
)
def list_roles(
    enterprise: EnterpriseServicesDep,
    context: Annotated[
        EnterpriseRequestContext, Depends(require_enterprise("role.read", scope="tenant"))
    ],
    page_size: PageSize = 50,
    cursor: str | None = None,
) -> PageResponse[Any]:
    items, next_cursor = enterprise.repository.list_roles(
        context.principal, page_size=page_size, cursor=cursor
    )
    return _page(items, next_cursor, page_size)


@router.post(
    "/iam/role-assignments",
    response_model=RoleAssignmentResponse,
    status_code=status.HTTP_201_CREATED,
    operation_id="grantRoleAssignment",
)
def grant_role_assignment(
    request: Request,
    payload: RoleAssignmentCreate,
    response: Response,
    enterprise: EnterpriseServicesDep,
    context: EnterpriseContext,
    idempotency_key: IdempotencyKey,
) -> RoleAssignmentResponse:
    authorize_dynamic(
        request=request,
        enterprise=enterprise,
        context=context,
        permission="role.assign",
        project_id=payload.project_id,
    )
    result = enterprise.repository.grant_role(
        context.principal,
        user_id=payload.user_id,
        role_code=payload.role_code,
        project_id=payload.project_id,
        reason=payload.reason,
        expires_at=payload.expires_at,
        idempotency_key=idempotency_key,
        request_id=context.request_id,
        trace_id=context.trace_id,
    )
    response.headers["Idempotency-Replayed"] = str(result.replayed).lower()
    return RoleAssignmentResponse.model_validate(result.body)


@router.post(
    "/iam/role-assignments/{assignment_id}/revoke",
    response_model=RoleAssignmentResponse,
    operation_id="revokeRoleAssignment",
)
def revoke_role_assignment(
    assignment_id: UUID,
    request: Request,
    payload: RoleAssignmentRevoke,
    response: Response,
    enterprise: EnterpriseServicesDep,
    context: EnterpriseContext,
    idempotency_key: IdempotencyKey,
) -> RoleAssignmentResponse:
    project_id = enterprise.repository.role_assignment_scope(context.principal, assignment_id)
    authorize_dynamic(
        request=request,
        enterprise=enterprise,
        context=context,
        permission="role.revoke",
        project_id=project_id,
    )
    result = enterprise.repository.revoke_role(
        context.principal,
        assignment_id=assignment_id,
        reason=payload.reason,
        idempotency_key=idempotency_key,
        request_id=context.request_id,
        trace_id=context.trace_id,
    )
    response.headers["Idempotency-Replayed"] = str(result.replayed).lower()
    return RoleAssignmentResponse.model_validate(result.body)


@router.get(
    "/config/effective",
    response_model=EffectiveConfigResponse,
    operation_id="getEffectiveConfiguration",
)
def get_effective_configuration(
    request: Request,
    enterprise: EnterpriseServicesDep,
    context: EnterpriseContext,
    project_id: UUID | None = None,
    user_id: UUID | None = None,
) -> EffectiveConfigResponse:
    authorize_dynamic(
        request=request,
        enterprise=enterprise,
        context=context,
        permission="system_config.read",
        project_id=project_id,
    )
    if user_id is not None and user_id != context.principal.user_id:
        authorize_dynamic(
            request=request,
            enterprise=enterprise,
            context=context,
            permission="membership.read",
            project_id=None,
        )
    return EffectiveConfigResponse.model_validate(
        enterprise.repository.get_effective_config(
            context.principal, project_id=project_id, user_id=user_id
        )
    )


@router.put(
    "/config/{config_key}",
    response_model=ConfigEntryResponse,
    operation_id="putConfigurationEntry",
)
def put_configuration_entry(
    config_key: str,
    request: Request,
    payload: ConfigEntryUpdate,
    response: Response,
    enterprise: EnterpriseServicesDep,
    context: EnterpriseContext,
    idempotency_key: IdempotencyKey,
) -> ConfigEntryResponse:
    authorize_dynamic(
        request=request,
        enterprise=enterprise,
        context=context,
        permission="system_config.update",
        project_id=payload.project_id,
    )
    if payload.user_id is not None and payload.user_id != context.principal.user_id:
        authorize_dynamic(
            request=request,
            enterprise=enterprise,
            context=context,
            permission="membership.update",
            project_id=payload.project_id,
        )
    result = enterprise.repository.update_config(
        context.principal,
        config_key=config_key,
        scope_type=payload.scope_type,
        project_id=payload.project_id,
        user_id=payload.user_id,
        value=payload.value,
        expected_version=payload.expected_version,
        idempotency_key=idempotency_key,
        request_id=context.request_id,
        trace_id=context.trace_id,
    )
    response.headers["Idempotency-Replayed"] = str(result.replayed).lower()
    return ConfigEntryResponse.model_validate(result.body)


@router.get(
    "/audit/events",
    response_model=PageResponse[AuditEventResponse],
    operation_id="listEnterpriseAuditEvents",
)
def list_audit_events(
    request: Request,
    enterprise: EnterpriseServicesDep,
    context: EnterpriseContext,
    page_size: PageSize = 50,
    cursor: str | None = None,
    project_id: UUID | None = None,
) -> PageResponse[Any]:
    authorize_dynamic(
        request=request,
        enterprise=enterprise,
        context=context,
        permission="audit.read",
        project_id=project_id,
    )
    items, next_cursor = enterprise.repository.list_audit_events(
        context.principal,
        page_size=page_size,
        cursor=cursor,
        project_id=project_id,
    )
    return _page(items, next_cursor, page_size)
