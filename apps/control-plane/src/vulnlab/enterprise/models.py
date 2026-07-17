from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from types import MappingProxyType
from typing import Any, Generic, Literal, TypeVar
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


@dataclass(frozen=True, slots=True)
class OidcIdentity:
    issuer: str
    subject: str
    tenant_id: UUID
    username: str
    email: str | None


@dataclass(frozen=True, slots=True)
class EnterprisePrincipal:
    user_id: UUID
    tenant_id: UUID
    issuer: str
    subject: str
    username: str
    email: str | None
    tenant_status: str
    tenant_roles: frozenset[str]
    tenant_permissions: frozenset[str]
    project_roles: MappingProxyType[UUID, frozenset[str]]
    project_permissions: MappingProxyType[UUID, frozenset[str]]

    def can(self, permission: str, project_id: UUID | None = None) -> bool:
        if "*" in permission or permission == "admin":
            return False
        if permission in self.tenant_permissions:
            return True
        return project_id is not None and permission in self.project_permissions.get(
            project_id, frozenset()
        )

    def roles_for(self, project_id: UUID | None = None) -> frozenset[str]:
        if project_id is None:
            return self.tenant_roles
        return self.tenant_roles | self.project_roles.get(project_id, frozenset())

    @property
    def authorized_project_ids(self) -> frozenset[UUID]:
        return frozenset(self.project_permissions)


class EnterpriseAPIModel(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True, from_attributes=True)


class PageMeta(EnterpriseAPIModel):
    next_cursor: str | None = None
    has_more: bool = False
    page_size: int = Field(ge=1, le=100)


ItemT = TypeVar("ItemT")


class PageResponse(EnterpriseAPIModel, Generic[ItemT]):
    items: list[ItemT]
    page: PageMeta


class TenantResponse(EnterpriseAPIModel):
    id: UUID
    slug: str
    display_name: str
    status: str
    created_at: datetime
    updated_at: datetime
    version: int


class OrganizationCreate(EnterpriseAPIModel):
    slug: str = Field(min_length=3, max_length=63, pattern=r"^[a-z0-9][a-z0-9-]{1,61}[a-z0-9]$")
    display_name: str = Field(min_length=1, max_length=200)


class OrganizationResponse(OrganizationCreate):
    id: UUID
    tenant_id: UUID
    status: str
    created_at: datetime
    updated_at: datetime
    version: int


class ProjectCreate(EnterpriseAPIModel):
    organization_id: UUID | None = None
    slug: str = Field(min_length=3, max_length=63, pattern=r"^[a-z0-9][a-z0-9-]{1,61}[a-z0-9]$")
    display_name: str = Field(min_length=1, max_length=200)


class ProjectResponse(ProjectCreate):
    id: UUID
    tenant_id: UUID
    status: str
    created_at: datetime
    updated_at: datetime
    version: int


class UserResponse(EnterpriseAPIModel):
    id: UUID
    tenant_id: UUID
    issuer: str
    subject: str
    username: str
    email: str | None
    active: bool
    created_at: datetime
    updated_at: datetime
    version: int


class UserProvisionCreate(EnterpriseAPIModel):
    subject: str = Field(min_length=1, max_length=255)
    username: str = Field(min_length=1, max_length=128)
    email: str | None = Field(default=None, max_length=320)


class RoleResponse(EnterpriseAPIModel):
    id: UUID
    tenant_id: UUID
    code: str
    display_name: str
    description: str
    scope_type: str
    system_managed: bool
    permissions: list[str]
    created_at: datetime
    updated_at: datetime
    version: int


class RoleAssignmentCreate(EnterpriseAPIModel):
    user_id: UUID
    role_code: str = Field(min_length=3, max_length=80, pattern=r"^[a-z][a-z0-9_.:-]{2,79}$")
    project_id: UUID | None = None
    reason: str = Field(min_length=3, max_length=500)
    expires_at: datetime | None = None

    @field_validator("expires_at")
    @classmethod
    def expiry_must_include_timezone(cls, value: datetime | None) -> datetime | None:
        if value is not None and value.tzinfo is None:
            raise ValueError("expires_at must include a timezone")
        return value


class RoleAssignmentRevoke(EnterpriseAPIModel):
    reason: str = Field(min_length=3, max_length=500)


class RoleAssignmentResponse(EnterpriseAPIModel):
    id: UUID
    tenant_id: UUID
    project_id: UUID | None
    user_id: UUID
    role_id: UUID
    role_code: str
    granted_by: UUID
    reason: str
    starts_at: datetime
    expires_at: datetime | None
    revoked_at: datetime | None
    revoked_by: UUID | None
    revocation_reason: str | None
    created_at: datetime
    updated_at: datetime
    version: int


class ConfigEntryUpdate(EnterpriseAPIModel):
    scope_type: Literal["TENANT", "PROJECT", "USER"]
    project_id: UUID | None = None
    user_id: UUID | None = None
    value: Any
    expected_version: int | None = Field(default=None, ge=1)

    @model_validator(mode="after")
    def validate_scope_shape(self) -> ConfigEntryUpdate:
        valid = (
            (self.scope_type == "TENANT" and self.project_id is None and self.user_id is None)
            or (
                self.scope_type == "PROJECT"
                and self.project_id is not None
                and self.user_id is None
            )
            or (self.scope_type == "USER" and self.user_id is not None)
        )
        if not valid:
            raise ValueError("scope_type does not match project_id/user_id")
        return self


class ConfigEntryResponse(EnterpriseAPIModel):
    id: UUID
    tenant_id: UUID
    project_id: UUID | None
    user_id: UUID | None
    scope_type: str
    config_key: str
    config_value: Any
    created_by: UUID
    updated_by: UUID
    created_at: datetime
    updated_at: datetime
    version: int


class EffectiveConfigResponse(EnterpriseAPIModel):
    values: dict[str, Any]
    sources: dict[str, Literal["TENANT", "PROJECT", "USER"]]


class AuditEventResponse(EnterpriseAPIModel):
    id: int
    event_id: UUID
    tenant_id: UUID
    project_id: UUID | None
    actor_type: str
    actor_user_id: UUID | None
    action: str
    resource_type: str
    resource_id: str
    outcome: str
    risk_level: str
    trace_id: str
    request_id: str
    details: dict[str, Any]
    previous_hash: str
    entry_hash: str
    occurred_at: datetime


class SessionProjectAccess(EnterpriseAPIModel):
    project_id: UUID
    roles: list[str]
    permissions: list[str]


class SessionResponse(EnterpriseAPIModel):
    user_id: UUID
    tenant_id: UUID
    username: str
    email: str | None
    tenant_status: str
    roles: list[str]
    permissions: list[str]
    projects: list[SessionProjectAccess]


def session_from_principal(principal: EnterprisePrincipal) -> SessionResponse:
    project_ids = sorted(set(principal.project_roles) | set(principal.project_permissions), key=str)
    return SessionResponse(
        user_id=principal.user_id,
        tenant_id=principal.tenant_id,
        username=principal.username,
        email=principal.email,
        tenant_status=principal.tenant_status,
        roles=sorted(principal.tenant_roles),
        permissions=sorted(principal.tenant_permissions),
        projects=[
            SessionProjectAccess(
                project_id=project_id,
                roles=sorted(principal.project_roles.get(project_id, frozenset())),
                permissions=sorted(
                    principal.tenant_permissions
                    | principal.project_permissions.get(project_id, frozenset())
                ),
            )
            for project_id in project_ids
        ],
    )
