from __future__ import annotations

import hashlib
import json
import string
from collections.abc import Callable, Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
from types import MappingProxyType
from typing import Any
from uuid import UUID, uuid4

from psycopg import Connection
from psycopg.errors import CheckViolation, ForeignKeyViolation, UniqueViolation
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb
from psycopg_pool import ConnectionPool

from .errors import (
    EnterpriseAuthenticationError,
    EnterpriseConflictError,
    EnterpriseNotFoundError,
    EnterpriseUnavailableError,
    EnterpriseValidationError,
    RequestInProgressError,
)
from .models import EnterprisePrincipal, OidcIdentity
from .permissions import PERMISSION_CODES, ROLE_BY_CODE, ROLE_DEFINITIONS

Row = dict[str, Any]
TenantConnection = Connection[Row]


@dataclass(frozen=True, slots=True)
class IdempotentResult:
    body: dict[str, Any]
    replayed: bool


def _json_default(value: Any) -> str:
    if isinstance(value, (UUID, datetime)):
        return value.isoformat() if isinstance(value, datetime) else str(value)
    raise TypeError(f"unsupported JSON value: {type(value).__name__}")


def _json_copy(value: Any) -> Any:
    return json.loads(json.dumps(value, default=_json_default, sort_keys=True))


def _request_digest(payload: Mapping[str, Any]) -> str:
    encoded = json.dumps(
        payload, default=_json_default, sort_keys=True, separators=(",", ":")
    ).encode()
    return hashlib.sha256(encoded).hexdigest()


def _utc(value: datetime) -> datetime:
    return value.astimezone(UTC)


def _timestamp(value: datetime) -> str:
    return _utc(value).isoformat(timespec="microseconds")


CONFIG_VALIDATORS: dict[str, Callable[[Any], bool]] = {
    "ui.locale": lambda value: isinstance(value, str) and value in {"en-US", "zh-CN"},
    "ui.timezone": lambda value: isinstance(value, str) and 1 <= len(value) <= 64,
    "notifications.email_enabled": lambda value: isinstance(value, bool),
    "retention.audit_days": lambda value: (
        isinstance(value, int) and not isinstance(value, bool) and 30 <= value <= 3650
    ),
    "task.default_timeout_seconds": lambda value: (
        isinstance(value, int) and not isinstance(value, bool) and 30 <= value <= 86_400
    ),
    "security.session_idle_minutes": lambda value: (
        isinstance(value, int) and not isinstance(value, bool) and 5 <= value <= 1440
    ),
}

FORBIDDEN_CONFIG_TERMS = (
    "password",
    "secret",
    "token",
    "credential",
    "api_key",
    "private_key",
)


class EnterpriseRepository:
    """PostgreSQL repository that requires an explicit tenant context for every query."""

    def __init__(
        self,
        database_url: str,
        *,
        min_size: int = 1,
        max_size: int = 8,
        timeout_seconds: float = 10.0,
    ) -> None:
        self.pool: ConnectionPool[TenantConnection] = ConnectionPool(
            database_url,
            min_size=min_size,
            max_size=max_size,
            timeout=timeout_seconds,
            kwargs={"row_factory": dict_row, "autocommit": False},
            check=ConnectionPool.check_connection,
            open=False,
            name="vulnlab-enterprise",
        )
        try:
            self.pool.open(wait=True, timeout=timeout_seconds)
        except Exception as exc:
            self.pool.close()
            raise EnterpriseUnavailableError("enterprise database is unavailable") from exc

    def close(self) -> None:
        self.pool.close()

    @contextmanager
    def tenant_transaction(self, tenant_id: UUID) -> Iterator[TenantConnection]:
        with self.pool.connection() as connection, connection.transaction():
            connection.execute("SELECT set_config('app.tenant_id', %s, true)", (str(tenant_id),))
            yield connection

    @staticmethod
    def _set_tenant(connection: TenantConnection, tenant_id: UUID) -> None:
        connection.execute("SELECT set_config('app.tenant_id', %s, true)", (str(tenant_id),))

    def resolve_principal(self, identity: OidcIdentity) -> EnterprisePrincipal:
        with self.tenant_transaction(identity.tenant_id) as connection:
            account = connection.execute(
                """
                SELECT u.id, u.tenant_id, u.issuer, u.subject, u.username, u.email,
                       t.status AS tenant_status
                FROM iam.users AS u
                JOIN iam.tenants AS t ON t.id = u.tenant_id
                WHERE u.tenant_id = %s AND u.issuer = %s AND u.subject = %s
                  AND u.active AND t.status = 'ACTIVE'
                """,
                (str(identity.tenant_id), identity.issuer, identity.subject),
            ).fetchone()
            if account is None:
                raise EnterpriseAuthenticationError()
            assignments = connection.execute(
                """
                SELECT ur.project_id, r.code AS role_code, p.code AS permission_code
                FROM iam.user_roles AS ur
                JOIN iam.roles AS r
                  ON r.tenant_id = ur.tenant_id AND r.id = ur.role_id
                LEFT JOIN iam.role_permissions AS rp
                  ON rp.tenant_id = r.tenant_id AND rp.role_id = r.id
                LEFT JOIN iam.permissions AS p
                  ON p.tenant_id = rp.tenant_id AND p.id = rp.permission_id
                LEFT JOIN iam.projects AS project
                  ON project.tenant_id = ur.tenant_id AND project.id = ur.project_id
                WHERE ur.tenant_id = %s AND ur.user_id = %s
                  AND ur.revoked_at IS NULL
                  AND ur.starts_at <= CURRENT_TIMESTAMP
                  AND (ur.expires_at IS NULL OR ur.expires_at > CURRENT_TIMESTAMP)
                  AND (ur.project_id IS NULL OR project.status = 'ACTIVE')
                """,
                (str(identity.tenant_id), account["id"]),
            ).fetchall()

        tenant_roles: set[str] = set()
        tenant_permissions: set[str] = set()
        project_roles: dict[UUID, set[str]] = {}
        project_permissions: dict[UUID, set[str]] = {}
        for assignment in assignments:
            project_id = assignment["project_id"]
            role_code = str(assignment["role_code"])
            permission_code = assignment["permission_code"]
            if project_id is None:
                tenant_roles.add(role_code)
                if permission_code is not None:
                    tenant_permissions.add(str(permission_code))
                continue
            project_roles.setdefault(project_id, set()).add(role_code)
            if permission_code is not None:
                project_permissions.setdefault(project_id, set()).add(str(permission_code))
        return EnterprisePrincipal(
            user_id=account["id"],
            tenant_id=account["tenant_id"],
            issuer=account["issuer"],
            subject=account["subject"],
            username=account["username"],
            email=account["email"],
            tenant_status=account["tenant_status"],
            tenant_roles=frozenset(tenant_roles),
            tenant_permissions=frozenset(tenant_permissions),
            project_roles=MappingProxyType(
                {project_id: frozenset(roles) for project_id, roles in project_roles.items()}
            ),
            project_permissions=MappingProxyType(
                {
                    project_id: frozenset(permissions)
                    for project_id, permissions in project_permissions.items()
                }
            ),
        )

    def get_tenant(self, principal: EnterprisePrincipal) -> Row:
        with self.tenant_transaction(principal.tenant_id) as connection:
            row = connection.execute(
                """
                SELECT id, slug, display_name, status, created_at, updated_at, version
                FROM iam.tenants WHERE id = %s
                """,
                (str(principal.tenant_id),),
            ).fetchone()
        if row is None:
            raise EnterpriseNotFoundError("tenant not found")
        return row

    @staticmethod
    def _cursor_uuid(cursor: str | None) -> UUID | None:
        if cursor is None:
            return None
        try:
            return UUID(cursor)
        except ValueError as exc:
            raise EnterpriseValidationError("cursor is invalid") from exc

    def list_organizations(
        self, principal: EnterprisePrincipal, *, page_size: int, cursor: str | None
    ) -> tuple[list[Row], str | None]:
        cursor_id = self._cursor_uuid(cursor)
        with self.tenant_transaction(principal.tenant_id) as connection:
            if "project.read" in principal.tenant_permissions:
                rows = connection.execute(
                    """
                    SELECT id, tenant_id, slug, display_name, status,
                           created_at, updated_at, version
                    FROM iam.organizations
                    WHERE tenant_id = %s AND (%s::uuid IS NULL OR id > %s::uuid)
                    ORDER BY id LIMIT %s
                    """,
                    (
                        str(principal.tenant_id),
                        str(cursor_id) if cursor_id else None,
                        str(cursor_id) if cursor_id else None,
                        page_size + 1,
                    ),
                ).fetchall()
            else:
                project_ids = [
                    project_id
                    for project_id, permissions in principal.project_permissions.items()
                    if "project.read" in permissions
                ]
                rows = connection.execute(
                    """
                    SELECT DISTINCT o.id, o.tenant_id, o.slug, o.display_name, o.status,
                                    o.created_at, o.updated_at, o.version
                    FROM iam.organizations AS o
                    JOIN iam.projects AS p
                      ON p.tenant_id = o.tenant_id AND p.organization_id = o.id
                    WHERE o.tenant_id = %s AND p.id = ANY(%s::uuid[])
                      AND (%s::uuid IS NULL OR o.id > %s::uuid)
                    ORDER BY o.id LIMIT %s
                    """,
                    (
                        str(principal.tenant_id),
                        project_ids,
                        str(cursor_id) if cursor_id else None,
                        str(cursor_id) if cursor_id else None,
                        page_size + 1,
                    ),
                ).fetchall()
        return self._slice_page(rows, page_size)

    def list_projects(
        self, principal: EnterprisePrincipal, *, page_size: int, cursor: str | None
    ) -> tuple[list[Row], str | None]:
        cursor_id = self._cursor_uuid(cursor)
        all_projects = "project.read" in principal.tenant_permissions
        project_ids = [
            project_id
            for project_id, permissions in principal.project_permissions.items()
            if "project.read" in permissions
        ]
        with self.tenant_transaction(principal.tenant_id) as connection:
            rows = connection.execute(
                """
                SELECT id, tenant_id, organization_id, slug, display_name, status,
                       created_at, updated_at, version
                FROM iam.projects
                WHERE tenant_id = %s
                  AND (%s OR id = ANY(%s::uuid[]))
                  AND (%s::uuid IS NULL OR id > %s::uuid)
                ORDER BY id LIMIT %s
                """,
                (
                    str(principal.tenant_id),
                    all_projects,
                    project_ids,
                    str(cursor_id) if cursor_id else None,
                    str(cursor_id) if cursor_id else None,
                    page_size + 1,
                ),
            ).fetchall()
        return self._slice_page(rows, page_size)

    def list_users(
        self, principal: EnterprisePrincipal, *, page_size: int, cursor: str | None
    ) -> tuple[list[Row], str | None]:
        cursor_id = self._cursor_uuid(cursor)
        with self.tenant_transaction(principal.tenant_id) as connection:
            rows = connection.execute(
                """
                SELECT id, tenant_id, issuer, subject, username, email, active,
                       created_at, updated_at, version
                FROM iam.users
                WHERE tenant_id = %s AND (%s::uuid IS NULL OR id > %s::uuid)
                ORDER BY id LIMIT %s
                """,
                (
                    str(principal.tenant_id),
                    str(cursor_id) if cursor_id else None,
                    str(cursor_id) if cursor_id else None,
                    page_size + 1,
                ),
            ).fetchall()
        return self._slice_page(rows, page_size)

    def list_roles(
        self, principal: EnterprisePrincipal, *, page_size: int, cursor: str | None
    ) -> tuple[list[Row], str | None]:
        cursor_id = self._cursor_uuid(cursor)
        with self.tenant_transaction(principal.tenant_id) as connection:
            rows = connection.execute(
                """
                SELECT r.id, r.tenant_id, r.code, r.display_name, r.description,
                       r.scope_type, r.system_managed, r.created_at, r.updated_at, r.version,
                       COALESCE(array_agg(p.code ORDER BY p.code)
                           FILTER (WHERE p.code IS NOT NULL), ARRAY[]::varchar[]) AS permissions
                FROM iam.roles AS r
                LEFT JOIN iam.role_permissions AS rp
                  ON rp.tenant_id = r.tenant_id AND rp.role_id = r.id
                LEFT JOIN iam.permissions AS p
                  ON p.tenant_id = rp.tenant_id AND p.id = rp.permission_id
                WHERE r.tenant_id = %s AND (%s::uuid IS NULL OR r.id > %s::uuid)
                GROUP BY r.id
                ORDER BY r.id LIMIT %s
                """,
                (
                    str(principal.tenant_id),
                    str(cursor_id) if cursor_id else None,
                    str(cursor_id) if cursor_id else None,
                    page_size + 1,
                ),
            ).fetchall()
        return self._slice_page(rows, page_size)

    @staticmethod
    def _slice_page(rows: list[Row], page_size: int) -> tuple[list[Row], str | None]:
        has_more = len(rows) > page_size
        items = rows[:page_size]
        next_cursor = str(items[-1]["id"]) if has_more and items else None
        return items, next_cursor

    @staticmethod
    def _validate_idempotency_key(key: str) -> None:
        if not 16 <= len(key) <= 200 or any(
            character not in string.printable or character in "\r\n\t\x0b\x0c" for character in key
        ):
            raise EnterpriseValidationError(
                "Idempotency-Key must contain 16 to 200 printable ASCII characters"
            )

    def _idempotent(
        self,
        connection: TenantConnection,
        *,
        tenant_id: UUID,
        project_id: UUID | None,
        operation: str,
        key: str,
        request: Mapping[str, Any],
        work: Callable[[], Row],
    ) -> IdempotentResult:
        self._validate_idempotency_key(key)
        digest = _request_digest(request)
        lock_key = f"{tenant_id}:{project_id or ''}:{operation}:{key}"
        connection.execute("SELECT pg_advisory_xact_lock(hashtextextended(%s, 0))", (lock_key,))
        existing = connection.execute(
            """
            SELECT id, request_sha256, status, response_body, locked_until, expires_at
            FROM control.idempotency_records
            WHERE tenant_id = %s AND operation = %s AND idempotency_key = %s
              AND project_id IS NOT DISTINCT FROM %s::uuid
            FOR UPDATE
            """,
            (str(tenant_id), operation, key, str(project_id) if project_id else None),
        ).fetchone()
        if existing is not None:
            if existing["expires_at"] <= datetime.now(UTC):
                record_id = existing["id"]
                connection.execute(
                    """
                    UPDATE control.idempotency_records
                    SET request_sha256 = %s, status = 'PROCESSING', response_status = NULL,
                        response_body = NULL, resource_type = NULL, resource_id = NULL,
                        locked_until = CURRENT_TIMESTAMP + INTERVAL '30 seconds',
                        expires_at = CURRENT_TIMESTAMP + INTERVAL '24 hours',
                        updated_at = CURRENT_TIMESTAMP, version = version + 1
                    WHERE id = %s
                    """,
                    (digest, record_id),
                )
            elif existing["request_sha256"] != digest:
                raise EnterpriseConflictError(
                    "Idempotency-Key was already used for a different request",
                    code="idempotency_key_reused",
                )
            elif existing["status"] == "COMPLETED" and existing["response_body"] is not None:
                return IdempotentResult(dict(existing["response_body"]), True)
            elif existing["status"] == "PROCESSING" and (
                existing["locked_until"] is None or existing["locked_until"] > datetime.now(UTC)
            ):
                raise RequestInProgressError()
            else:
                record_id = existing["id"]
                connection.execute(
                    """
                    UPDATE control.idempotency_records
                    SET status = 'PROCESSING',
                        locked_until = CURRENT_TIMESTAMP + INTERVAL '30 seconds',
                        updated_at = CURRENT_TIMESTAMP, version = version + 1
                    WHERE id = %s
                    """,
                    (record_id,),
                )
        else:
            record_id = uuid4()
            connection.execute(
                """
                INSERT INTO control.idempotency_records (
                    id, tenant_id, project_id, operation, idempotency_key,
                    request_sha256, status, locked_until, expires_at
                ) VALUES (
                    %s, %s, %s, %s, %s, %s, 'PROCESSING',
                    CURRENT_TIMESTAMP + INTERVAL '30 seconds',
                    CURRENT_TIMESTAMP + INTERVAL '24 hours'
                )
                """,
                (
                    record_id,
                    str(tenant_id),
                    str(project_id) if project_id else None,
                    operation,
                    key,
                    digest,
                ),
            )
        body = _json_copy(work())
        connection.execute(
            """
            UPDATE control.idempotency_records
            SET status = 'COMPLETED', response_status = 200, response_body = %s,
                resource_id = CASE
                    WHEN %s ~ '^[0-9a-f-]{36}$' THEN %s::uuid ELSE NULL END,
                locked_until = NULL, updated_at = CURRENT_TIMESTAMP, version = version + 1
            WHERE id = %s
            """,
            (Jsonb(body), str(body.get("id", "")), str(body.get("id", "")) or None, record_id),
        )
        return IdempotentResult(body, False)

    def create_organization(
        self,
        principal: EnterprisePrincipal,
        *,
        slug: str,
        display_name: str,
        idempotency_key: str,
        request_id: str,
        trace_id: str,
    ) -> IdempotentResult:
        request = {"slug": slug, "display_name": display_name}
        with self.tenant_transaction(principal.tenant_id) as connection:

            def work() -> Row:
                resource_id = uuid4()
                row = connection.execute(
                    """
                    INSERT INTO iam.organizations (id, tenant_id, slug, display_name)
                    VALUES (%s, %s, %s, %s)
                    RETURNING id, tenant_id, slug, display_name, status,
                              created_at, updated_at, version
                    """,
                    (resource_id, str(principal.tenant_id), slug, display_name),
                ).fetchone()
                if row is None:  # pragma: no cover - INSERT RETURNING invariant
                    raise EnterpriseUnavailableError()
                self._append_audit(
                    connection,
                    principal=principal,
                    project_id=None,
                    action="organization.created",
                    resource_type="organization",
                    resource_id=str(resource_id),
                    outcome="SUCCEEDED",
                    risk_level="R1",
                    request_id=request_id,
                    trace_id=trace_id,
                    details={"slug": slug},
                )
                return row

            try:
                return self._idempotent(
                    connection,
                    tenant_id=principal.tenant_id,
                    project_id=None,
                    operation="organization.create",
                    key=idempotency_key,
                    request=request,
                    work=work,
                )
            except (UniqueViolation, CheckViolation) as exc:
                raise EnterpriseConflictError() from exc

    def create_project(
        self,
        principal: EnterprisePrincipal,
        *,
        organization_id: UUID | None,
        slug: str,
        display_name: str,
        idempotency_key: str,
        request_id: str,
        trace_id: str,
    ) -> IdempotentResult:
        request = {
            "organization_id": organization_id,
            "slug": slug,
            "display_name": display_name,
        }
        with self.tenant_transaction(principal.tenant_id) as connection:

            def work() -> Row:
                resource_id = uuid4()
                row = connection.execute(
                    """
                    INSERT INTO iam.projects (
                        id, tenant_id, organization_id, slug, display_name
                    ) VALUES (%s, %s, %s, %s, %s)
                    RETURNING id, tenant_id, organization_id, slug, display_name, status,
                              created_at, updated_at, version
                    """,
                    (
                        resource_id,
                        str(principal.tenant_id),
                        str(organization_id) if organization_id else None,
                        slug,
                        display_name,
                    ),
                ).fetchone()
                if row is None:  # pragma: no cover
                    raise EnterpriseUnavailableError()
                self._append_audit(
                    connection,
                    principal=principal,
                    project_id=resource_id,
                    action="project.created",
                    resource_type="project",
                    resource_id=str(resource_id),
                    outcome="SUCCEEDED",
                    risk_level="R1",
                    request_id=request_id,
                    trace_id=trace_id,
                    details={"slug": slug, "organization_id": organization_id},
                )
                return row

            try:
                return self._idempotent(
                    connection,
                    tenant_id=principal.tenant_id,
                    project_id=None,
                    operation="project.create",
                    key=idempotency_key,
                    request=request,
                    work=work,
                )
            except (UniqueViolation, ForeignKeyViolation, CheckViolation) as exc:
                raise EnterpriseConflictError() from exc

    def provision_user(
        self,
        principal: EnterprisePrincipal,
        *,
        issuer: str,
        subject: str,
        username: str,
        email: str | None,
        idempotency_key: str,
        request_id: str,
        trace_id: str,
    ) -> IdempotentResult:
        request = {"issuer": issuer, "subject": subject, "username": username, "email": email}
        with self.tenant_transaction(principal.tenant_id) as connection:

            def work() -> Row:
                user_id = uuid4()
                row = connection.execute(
                    """
                    INSERT INTO iam.users (
                        id, tenant_id, issuer, subject, username, email
                    ) VALUES (%s, %s, %s, %s, %s, %s)
                    RETURNING id, tenant_id, issuer, subject, username, email, active,
                              created_at, updated_at, version
                    """,
                    (user_id, str(principal.tenant_id), issuer, subject, username, email),
                ).fetchone()
                if row is None:  # pragma: no cover
                    raise EnterpriseUnavailableError()
                self._append_audit(
                    connection,
                    principal=principal,
                    project_id=None,
                    action="membership.provisioned",
                    resource_type="user",
                    resource_id=str(user_id),
                    outcome="SUCCEEDED",
                    risk_level="R2",
                    request_id=request_id,
                    trace_id=trace_id,
                    details={"issuer": issuer, "username": username},
                )
                return row

            try:
                return self._idempotent(
                    connection,
                    tenant_id=principal.tenant_id,
                    project_id=None,
                    operation="membership.provision",
                    key=idempotency_key,
                    request=request,
                    work=work,
                )
            except (UniqueViolation, CheckViolation) as exc:
                raise EnterpriseConflictError() from exc

    def grant_role(
        self,
        principal: EnterprisePrincipal,
        *,
        user_id: UUID,
        role_code: str,
        project_id: UUID | None,
        reason: str,
        expires_at: datetime | None,
        idempotency_key: str,
        request_id: str,
        trace_id: str,
    ) -> IdempotentResult:
        if user_id == principal.user_id:
            raise EnterpriseValidationError("self-granting a role is forbidden")
        if role_code == "platform_admin":
            raise EnterpriseValidationError("platform_admin can only be assigned out of band")
        request = {
            "user_id": user_id,
            "role_code": role_code,
            "project_id": project_id,
            "reason": reason,
            "expires_at": expires_at,
        }
        with self.tenant_transaction(principal.tenant_id) as connection:
            role = connection.execute(
                "SELECT id, code, scope_type FROM iam.roles WHERE tenant_id = %s AND code = %s",
                (str(principal.tenant_id), role_code),
            ).fetchone()
            if role is None:
                raise EnterpriseNotFoundError("role not found")
            if role["scope_type"] == "TENANT" and project_id is not None:
                raise EnterpriseValidationError("role scope does not match project_id")
            if role["scope_type"] == "PROJECT" and project_id is None:
                raise EnterpriseValidationError("role scope does not match project_id")
            if expires_at is not None and _utc(expires_at) <= datetime.now(UTC):
                raise EnterpriseValidationError("expires_at must be in the future")

            def work() -> Row:
                assignment_id = uuid4()
                row = connection.execute(
                    """
                    INSERT INTO iam.user_roles (
                        id, tenant_id, project_id, user_id, role_id, granted_by,
                        reason, starts_at, expires_at
                    ) VALUES (
                        %s, %s, %s, %s, %s, %s, %s, CURRENT_TIMESTAMP, %s
                    )
                    RETURNING id, tenant_id, project_id, user_id, role_id, granted_by,
                              reason, starts_at, expires_at, revoked_at, revoked_by,
                              revocation_reason, created_at, updated_at, version
                    """,
                    (
                        assignment_id,
                        str(principal.tenant_id),
                        str(project_id) if project_id else None,
                        str(user_id),
                        role["id"],
                        str(principal.user_id),
                        reason,
                        expires_at,
                    ),
                ).fetchone()
                if row is None:  # pragma: no cover
                    raise EnterpriseUnavailableError()
                row["role_code"] = role_code
                self._append_audit(
                    connection,
                    principal=principal,
                    project_id=project_id,
                    action="role_assignment.granted",
                    resource_type="role_assignment",
                    resource_id=str(assignment_id),
                    outcome="SUCCEEDED",
                    risk_level="R2",
                    request_id=request_id,
                    trace_id=trace_id,
                    details={
                        "target_user_id": user_id,
                        "role_code": role_code,
                        "reason": reason,
                    },
                )
                return row

            try:
                return self._idempotent(
                    connection,
                    tenant_id=principal.tenant_id,
                    project_id=project_id,
                    operation="role_assignment.grant",
                    key=idempotency_key,
                    request=request,
                    work=work,
                )
            except (UniqueViolation, ForeignKeyViolation, CheckViolation) as exc:
                raise EnterpriseConflictError() from exc

    def revoke_role(
        self,
        principal: EnterprisePrincipal,
        *,
        assignment_id: UUID,
        reason: str,
        idempotency_key: str,
        request_id: str,
        trace_id: str,
    ) -> IdempotentResult:
        request = {"assignment_id": assignment_id, "reason": reason}
        with self.tenant_transaction(principal.tenant_id) as connection:
            assignment = connection.execute(
                """
                SELECT ur.*, r.code AS role_code, r.scope_type
                FROM iam.user_roles AS ur
                JOIN iam.roles AS r
                  ON r.tenant_id = ur.tenant_id AND r.id = ur.role_id
                WHERE ur.tenant_id = %s AND ur.id = %s
                """,
                (str(principal.tenant_id), str(assignment_id)),
            ).fetchone()
            if assignment is None:
                raise EnterpriseNotFoundError("role assignment not found")
            if assignment["role_code"] == "platform_admin":
                raise EnterpriseValidationError("platform_admin can only be revoked out of band")

            def work() -> Row:
                row = connection.execute(
                    """
                    UPDATE iam.user_roles
                    SET revoked_at = CURRENT_TIMESTAMP, revoked_by = %s,
                        revocation_reason = %s, updated_at = CURRENT_TIMESTAMP,
                        version = version + 1
                    WHERE tenant_id = %s AND id = %s AND revoked_at IS NULL
                    RETURNING id, tenant_id, project_id, user_id, role_id, granted_by,
                              reason, starts_at, expires_at, revoked_at, revoked_by,
                              revocation_reason, created_at, updated_at, version
                    """,
                    (
                        str(principal.user_id),
                        reason,
                        str(principal.tenant_id),
                        str(assignment_id),
                    ),
                ).fetchone()
                if row is None:
                    raise EnterpriseConflictError(
                        "role assignment is already revoked", code="assignment_already_revoked"
                    )
                row["role_code"] = assignment["role_code"]
                self._append_audit(
                    connection,
                    principal=principal,
                    project_id=assignment["project_id"],
                    action="role_assignment.revoked",
                    resource_type="role_assignment",
                    resource_id=str(assignment_id),
                    outcome="SUCCEEDED",
                    risk_level="R2",
                    request_id=request_id,
                    trace_id=trace_id,
                    details={
                        "target_user_id": assignment["user_id"],
                        "role_code": assignment["role_code"],
                        "reason": reason,
                    },
                )
                return row

            return self._idempotent(
                connection,
                tenant_id=principal.tenant_id,
                project_id=assignment["project_id"],
                operation="role_assignment.revoke",
                key=idempotency_key,
                request=request,
                work=work,
            )

    def role_assignment_scope(
        self, principal: EnterprisePrincipal, assignment_id: UUID
    ) -> UUID | None:
        with self.tenant_transaction(principal.tenant_id) as connection:
            row = connection.execute(
                "SELECT project_id FROM iam.user_roles WHERE tenant_id = %s AND id = %s",
                (str(principal.tenant_id), str(assignment_id)),
            ).fetchone()
        if row is None:
            raise EnterpriseNotFoundError("role assignment not found")
        return row["project_id"]

    @staticmethod
    def _validate_config(config_key: str, value: Any) -> None:
        lowered = config_key.lower()
        if any(term in lowered for term in FORBIDDEN_CONFIG_TERMS):
            raise EnterpriseValidationError("secret-bearing configuration is not accepted")
        validator = CONFIG_VALIDATORS.get(config_key)
        if validator is None:
            raise EnterpriseValidationError("config_key is not in the managed schema")
        try:
            encoded = json.dumps(value, sort_keys=True, separators=(",", ":"))
        except (TypeError, ValueError) as exc:
            raise EnterpriseValidationError("config value must be valid JSON") from exc
        if len(encoded.encode()) > 65_536 or not validator(value):
            raise EnterpriseValidationError("config value does not match the managed schema")

    def get_effective_config(
        self,
        principal: EnterprisePrincipal,
        *,
        project_id: UUID | None,
        user_id: UUID | None,
    ) -> dict[str, Any]:
        effective_user = user_id or principal.user_id
        with self.tenant_transaction(principal.tenant_id) as connection:
            rows = connection.execute(
                """
                SELECT config_key, config_value, scope_type, project_id, user_id
                FROM control.config_entries
                WHERE tenant_id = %s AND (
                    scope_type = 'TENANT'
                    OR (scope_type = 'PROJECT' AND project_id = %s)
                    OR (scope_type = 'USER' AND user_id = %s
                        AND (project_id IS NULL OR project_id = %s))
                )
                ORDER BY CASE
                    WHEN scope_type = 'TENANT' THEN 1
                    WHEN scope_type = 'PROJECT' THEN 2
                    WHEN scope_type = 'USER' AND project_id IS NULL THEN 3
                    ELSE 4 END
                """,
                (
                    str(principal.tenant_id),
                    str(project_id) if project_id else None,
                    str(effective_user),
                    str(project_id) if project_id else None,
                ),
            ).fetchall()
        values: dict[str, Any] = {}
        sources: dict[str, str] = {}
        for row in rows:
            values[row["config_key"]] = row["config_value"]
            sources[row["config_key"]] = row["scope_type"]
        return {"values": values, "sources": sources}

    def update_config(
        self,
        principal: EnterprisePrincipal,
        *,
        config_key: str,
        scope_type: str,
        project_id: UUID | None,
        user_id: UUID | None,
        value: Any,
        expected_version: int | None,
        idempotency_key: str,
        request_id: str,
        trace_id: str,
    ) -> IdempotentResult:
        self._validate_config(config_key, value)
        request = {
            "config_key": config_key,
            "scope_type": scope_type,
            "project_id": project_id,
            "user_id": user_id,
            "value": value,
            "expected_version": expected_version,
        }
        with self.tenant_transaction(principal.tenant_id) as connection:

            def work() -> Row:
                lock_key = (
                    f"config:{principal.tenant_id}:{project_id or ''}:{user_id or ''}:{config_key}"
                )
                connection.execute(
                    "SELECT pg_advisory_xact_lock(hashtextextended(%s, 0))", (lock_key,)
                )
                current = connection.execute(
                    """
                    SELECT id, version FROM control.config_entries
                    WHERE tenant_id = %s AND scope_type = %s AND config_key = %s
                      AND project_id IS NOT DISTINCT FROM %s::uuid
                      AND user_id IS NOT DISTINCT FROM %s::uuid
                    FOR UPDATE
                    """,
                    (
                        str(principal.tenant_id),
                        scope_type,
                        config_key,
                        str(project_id) if project_id else None,
                        str(user_id) if user_id else None,
                    ),
                ).fetchone()
                if current is None:
                    if expected_version is not None:
                        raise EnterpriseConflictError(
                            "config entry does not exist at expected_version",
                            code="version_conflict",
                        )
                    row = connection.execute(
                        """
                        INSERT INTO control.config_entries (
                            id, tenant_id, project_id, user_id, scope_type, config_key,
                            config_value, created_by, updated_by
                        ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                        RETURNING *
                        """,
                        (
                            uuid4(),
                            str(principal.tenant_id),
                            str(project_id) if project_id else None,
                            str(user_id) if user_id else None,
                            scope_type,
                            config_key,
                            Jsonb(value),
                            str(principal.user_id),
                            str(principal.user_id),
                        ),
                    ).fetchone()
                else:
                    if expected_version is None or current["version"] != expected_version:
                        raise EnterpriseConflictError(
                            "expected_version does not match current configuration",
                            code="version_conflict",
                        )
                    row = connection.execute(
                        """
                        UPDATE control.config_entries
                        SET config_value = %s, updated_by = %s,
                            updated_at = CURRENT_TIMESTAMP, version = version + 1
                        WHERE id = %s AND version = %s
                        RETURNING *
                        """,
                        (
                            Jsonb(value),
                            str(principal.user_id),
                            current["id"],
                            expected_version,
                        ),
                    ).fetchone()
                if row is None:
                    raise EnterpriseConflictError(code="version_conflict")
                self._append_audit(
                    connection,
                    principal=principal,
                    project_id=project_id,
                    action="configuration.updated",
                    resource_type="config_entry",
                    resource_id=str(row["id"]),
                    outcome="SUCCEEDED",
                    risk_level="R2",
                    request_id=request_id,
                    trace_id=trace_id,
                    details={
                        "config_key": config_key,
                        "scope_type": scope_type,
                        "target_user_id": user_id,
                        "version": row["version"],
                    },
                )
                return row

            try:
                return self._idempotent(
                    connection,
                    tenant_id=principal.tenant_id,
                    project_id=project_id,
                    operation="configuration.update",
                    key=idempotency_key,
                    request=request,
                    work=work,
                )
            except (UniqueViolation, ForeignKeyViolation, CheckViolation) as exc:
                raise EnterpriseConflictError() from exc

    @staticmethod
    def _audit_canonical(
        *,
        event_id: UUID,
        tenant_id: UUID,
        project_id: UUID | None,
        actor_type: str,
        actor_user_id: UUID | None,
        action: str,
        resource_type: str,
        resource_id: str,
        outcome: str,
        risk_level: str,
        trace_id: str,
        request_id: str,
        details: Mapping[str, Any],
        occurred_at: datetime,
    ) -> bytes:
        payload = {
            "event_id": str(event_id),
            "tenant_id": str(tenant_id),
            "project_id": str(project_id) if project_id else None,
            "actor_type": actor_type,
            "actor_user_id": str(actor_user_id) if actor_user_id else None,
            "action": action,
            "resource_type": resource_type,
            "resource_id": resource_id,
            "outcome": outcome,
            "risk_level": risk_level,
            "trace_id": trace_id,
            "request_id": request_id,
            "details": details,
            "occurred_at": _timestamp(occurred_at),
        }
        return json.dumps(
            payload, default=_json_default, sort_keys=True, separators=(",", ":")
        ).encode()

    def _append_audit(
        self,
        connection: TenantConnection,
        *,
        principal: EnterprisePrincipal,
        project_id: UUID | None,
        action: str,
        resource_type: str,
        resource_id: str,
        outcome: str,
        risk_level: str,
        request_id: str,
        trace_id: str,
        details: Mapping[str, Any],
    ) -> Row:
        event_id = uuid4()
        occurred_at = datetime.now(UTC)
        head = connection.execute(
            """
            SELECT h.last_event_id, h.last_hash, h.event_count, e.entry_hash AS actual_hash
            FROM audit.chain_heads AS h
            JOIN audit.events AS e
              ON e.tenant_id = h.tenant_id AND e.id = h.last_event_id
            WHERE h.tenant_id = %s
            FOR UPDATE OF h
            """,
            (str(principal.tenant_id),),
        ).fetchone()
        if head is None:
            orphan_count = connection.execute(
                "SELECT count(*) AS count FROM audit.events WHERE tenant_id = %s",
                (str(principal.tenant_id),),
            ).fetchone()
            if orphan_count is None or int(orphan_count["count"]) != 0:
                raise EnterpriseUnavailableError("audit chain integrity check failed")
            previous_hash = bytes(32)
            event_count = 1
        else:
            previous_hash = bytes(head["last_hash"])
            if previous_hash != bytes(head["actual_hash"]):
                raise EnterpriseUnavailableError("audit chain integrity check failed")
            event_count = int(head["event_count"]) + 1
        canonical = self._audit_canonical(
            event_id=event_id,
            tenant_id=principal.tenant_id,
            project_id=project_id,
            actor_type="USER",
            actor_user_id=principal.user_id,
            action=action,
            resource_type=resource_type,
            resource_id=resource_id,
            outcome=outcome,
            risk_level=risk_level,
            trace_id=trace_id,
            request_id=request_id,
            details=details,
            occurred_at=occurred_at,
        )
        entry_hash = hashlib.sha256(previous_hash + canonical).digest()
        row = connection.execute(
            """
            INSERT INTO audit.events (
                event_id, tenant_id, project_id, actor_type, actor_user_id,
                action, resource_type, resource_id, outcome, risk_level,
                trace_id, request_id, details, previous_hash, entry_hash, occurred_at
            ) VALUES (
                %s, %s, %s, 'USER', %s, %s, %s, %s, %s, %s,
                %s, %s, %s, %s, %s, %s
            ) RETURNING *
            """,
            (
                event_id,
                str(principal.tenant_id),
                str(project_id) if project_id else None,
                str(principal.user_id),
                action,
                resource_type,
                resource_id,
                outcome,
                risk_level,
                trace_id,
                request_id,
                Jsonb(_json_copy(details)),
                previous_hash,
                entry_hash,
                occurred_at,
            ),
        ).fetchone()
        if row is None:  # pragma: no cover
            raise EnterpriseUnavailableError()
        if head is None:
            connection.execute(
                """
                INSERT INTO audit.chain_heads (
                    tenant_id, last_event_id, last_hash, event_count
                ) VALUES (%s, %s, %s, %s)
                """,
                (str(principal.tenant_id), row["id"], entry_hash, event_count),
            )
        else:
            connection.execute(
                """
                UPDATE audit.chain_heads
                SET last_event_id = %s, last_hash = %s, event_count = %s,
                    updated_at = CURRENT_TIMESTAMP, version = version + 1
                WHERE tenant_id = %s
                """,
                (row["id"], entry_hash, event_count, str(principal.tenant_id)),
            )
        return row

    def audit_denial(
        self,
        principal: EnterprisePrincipal,
        *,
        permission: str,
        project_id: UUID | None,
        request_id: str,
        trace_id: str,
        resource: str,
    ) -> None:
        with self.tenant_transaction(principal.tenant_id) as connection:
            self._append_audit(
                connection,
                principal=principal,
                project_id=project_id,
                action="authorization.denied",
                resource_type="permission",
                resource_id=permission,
                outcome="DENIED",
                risk_level="R2",
                request_id=request_id,
                trace_id=trace_id,
                details={"permission": permission, "resource": resource},
            )

    def list_audit_events(
        self,
        principal: EnterprisePrincipal,
        *,
        page_size: int,
        cursor: str | None,
        project_id: UUID | None,
    ) -> tuple[list[Row], str | None]:
        try:
            cursor_id = int(cursor) if cursor is not None else None
        except ValueError as exc:
            raise EnterpriseValidationError("cursor is invalid") from exc
        with self.tenant_transaction(principal.tenant_id) as connection:
            rows = connection.execute(
                """
                SELECT id, event_id, tenant_id, project_id, actor_type, actor_user_id,
                       action, resource_type, resource_id, outcome, risk_level,
                       trace_id, request_id, details, previous_hash, entry_hash, occurred_at
                FROM audit.events
                WHERE tenant_id = %s
                  AND (%s::uuid IS NULL OR project_id = %s::uuid)
                  AND (%s::bigint IS NULL OR id < %s::bigint)
                ORDER BY id DESC LIMIT %s
                """,
                (
                    str(principal.tenant_id),
                    str(project_id) if project_id else None,
                    str(project_id) if project_id else None,
                    cursor_id,
                    cursor_id,
                    page_size + 1,
                ),
            ).fetchall()
        has_more = len(rows) > page_size
        items = rows[:page_size]
        for row in items:
            row["previous_hash"] = bytes(row["previous_hash"]).hex()
            row["entry_hash"] = bytes(row["entry_hash"]).hex()
        return items, str(items[-1]["id"]) if has_more and items else None

    def bootstrap_tenant(
        self,
        *,
        tenant_id: UUID,
        tenant_slug: str,
        tenant_name: str,
        issuer: str,
        subject: str,
        username: str,
        email: str | None,
        bootstrap_role: str = "tenant_admin",
    ) -> tuple[UUID, UUID]:
        if bootstrap_role not in {"tenant_admin", "platform_admin"}:
            raise EnterpriseValidationError("bootstrap role is not permitted")
        user_id = uuid4()
        with self.tenant_transaction(tenant_id) as connection:
            try:
                connection.execute(
                    """
                    INSERT INTO iam.tenants (id, slug, display_name)
                    VALUES (%s, %s, %s)
                    """,
                    (str(tenant_id), tenant_slug, tenant_name),
                )
                connection.execute(
                    """
                    INSERT INTO iam.users (
                        id, tenant_id, issuer, subject, username, email
                    ) VALUES (%s, %s, %s, %s, %s, %s)
                    """,
                    (str(user_id), str(tenant_id), issuer, subject, username, email),
                )
                permission_ids: dict[str, UUID] = {}
                for code in sorted(PERMISSION_CODES):
                    permission_id = uuid4()
                    resource_type, action = code.split(".", 1)
                    connection.execute(
                        """
                        INSERT INTO iam.permissions (
                            id, tenant_id, code, description, resource_type, action
                        ) VALUES (%s, %s, %s, %s, %s, %s)
                        """,
                        (
                            permission_id,
                            str(tenant_id),
                            code,
                            f"Allows {code}",
                            resource_type,
                            action,
                        ),
                    )
                    permission_ids[code] = permission_id
                role_ids: dict[str, UUID] = {}
                for definition in ROLE_DEFINITIONS:
                    role_id = uuid4()
                    connection.execute(
                        """
                        INSERT INTO iam.roles (
                            id, tenant_id, code, display_name, description,
                            scope_type, system_managed
                        ) VALUES (%s, %s, %s, %s, %s, %s, true)
                        """,
                        (
                            role_id,
                            str(tenant_id),
                            definition.code,
                            definition.display_name,
                            definition.description,
                            definition.scope_type,
                        ),
                    )
                    role_ids[definition.code] = role_id
                    for permission in sorted(definition.permissions):
                        connection.execute(
                            """
                            INSERT INTO iam.role_permissions (
                                tenant_id, role_id, permission_id
                            ) VALUES (%s, %s, %s)
                            """,
                            (str(tenant_id), role_id, permission_ids[permission]),
                        )
                assignment_id = uuid4()
                connection.execute(
                    """
                    INSERT INTO iam.user_roles (
                        id, tenant_id, user_id, role_id, granted_by, reason
                    ) VALUES (%s, %s, %s, %s, %s, %s)
                    """,
                    (
                        assignment_id,
                        str(tenant_id),
                        str(user_id),
                        role_ids[bootstrap_role],
                        str(user_id),
                        "one-time tenant bootstrap",
                    ),
                )
                definition = ROLE_BY_CODE[bootstrap_role]
                bootstrap_principal = EnterprisePrincipal(
                    user_id=user_id,
                    tenant_id=tenant_id,
                    issuer=issuer,
                    subject=subject,
                    username=username,
                    email=email,
                    tenant_status="ACTIVE",
                    tenant_roles=frozenset({bootstrap_role}),
                    tenant_permissions=definition.permissions,
                    project_roles=MappingProxyType({}),
                    project_permissions=MappingProxyType({}),
                )
                self._append_audit(
                    connection,
                    principal=bootstrap_principal,
                    project_id=None,
                    action="tenant.bootstrap.completed",
                    resource_type="tenant",
                    resource_id=str(tenant_id),
                    outcome="SUCCEEDED",
                    risk_level="R3",
                    request_id=str(uuid4()),
                    trace_id=uuid4().hex,
                    details={
                        "bootstrap_role": bootstrap_role,
                        "role_assignment_id": assignment_id,
                    },
                )
            except (UniqueViolation, ForeignKeyViolation, CheckViolation) as exc:
                raise EnterpriseConflictError(
                    "tenant bootstrap conflicts with existing data"
                ) from exc
        return user_id, assignment_id

    @staticmethod
    def role_definition(role_code: str) -> Any:
        return ROLE_BY_CODE.get(role_code)
