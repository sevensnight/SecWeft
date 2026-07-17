#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import sys
from datetime import UTC, datetime
from pathlib import Path
from uuid import UUID, uuid4

import psycopg
from psycopg import sql
from psycopg.errors import CheckViolation, InsufficientPrivilege, ObjectNotInPrerequisiteState

PROJECT_ROOT = Path(__file__).resolve().parents[2]
SOURCE_ROOT = PROJECT_ROOT / "apps" / "control-plane" / "src"
if str(SOURCE_ROOT) not in sys.path:
    sys.path.insert(0, str(SOURCE_ROOT))

from vulnlab.enterprise.errors import EnterpriseConflictError  # noqa: E402
from vulnlab.enterprise.models import OidcIdentity  # noqa: E402
from vulnlab.enterprise.repository import EnterpriseRepository  # noqa: E402


def _require_environment(name: str) -> str:
    value = os.getenv(name)
    if not value:
        raise RuntimeError(f"{name} is required")
    return value


def _apply_migrations(admin_dsn: str) -> None:
    migrations = PROJECT_ROOT / "infrastructure" / "migrations"
    with psycopg.connect(admin_dsn, autocommit=True) as connection:
        baseline = connection.execute("SELECT to_regclass('iam.tenants')").fetchone()
        if baseline is not None and baseline[0] is None:
            connection.execute(
                (migrations / "0001_p0_enterprise_baseline.up.sql").read_text(encoding="utf-8")
            )
        p1 = connection.execute("SELECT to_regclass('iam.organizations')").fetchone()
        if p1 is not None and p1[0] is None:
            connection.execute(
                (migrations / "0002_p1_identity_tenancy_rbac.up.sql").read_text(encoding="utf-8")
            )
        scope_enforcement = connection.execute(
            "SELECT to_regprocedure('iam.enforce_user_role_scope()')"
        ).fetchone()
        if scope_enforcement is not None and scope_enforcement[0] is None:
            connection.execute(
                (migrations / "0003_p1_role_scope_enforcement.up.sql").read_text(encoding="utf-8")
            )
        delete_privilege = connection.execute(
            "SELECT has_table_privilege('vulnlab_app', 'iam.projects', 'DELETE')"
        ).fetchone()
        if delete_privilege is not None and delete_privilege[0] is True:
            connection.execute(
                (migrations / "0004_p1_application_least_privilege.up.sql").read_text(
                    encoding="utf-8"
                )
            )


def _enable_application_login(admin_dsn: str, password: str) -> None:
    with psycopg.connect(admin_dsn, autocommit=True) as connection:
        connection.execute(
            sql.SQL("ALTER ROLE vulnlab_app LOGIN PASSWORD {}").format(sql.Literal(password))
        )


def _identity(tenant_id: UUID, subject: str, username: str) -> OidcIdentity:
    return OidcIdentity(
        issuer="https://identity.example.test/realms/vulnlab",
        subject=subject,
        tenant_id=tenant_id,
        username=username,
        email=f"{username}@example.test",
    )


def _correlation() -> tuple[str, str]:
    return str(uuid4()), uuid4().hex


def validate() -> dict[str, object]:
    admin_dsn = _require_environment("P1_POSTGRES_ADMIN_DSN")
    app_dsn = _require_environment("P1_POSTGRES_APP_DSN")
    app_password = _require_environment("P1_POSTGRES_APP_PASSWORD")
    _apply_migrations(admin_dsn)
    _enable_application_login(admin_dsn, app_password)

    suffix = uuid4().hex[:10]
    tenant_a = uuid4()
    tenant_b = uuid4()
    subject_a = f"admin-a-{suffix}"
    subject_b = f"admin-b-{suffix}"
    repository = EnterpriseRepository(app_dsn, min_size=1, max_size=3, timeout_seconds=10)
    checks: dict[str, bool] = {}
    try:
        admin_a, _ = repository.bootstrap_tenant(
            tenant_id=tenant_a,
            tenant_slug=f"tenant-a-{suffix}",
            tenant_name="P1 acceptance tenant A",
            issuer="https://identity.example.test/realms/vulnlab",
            subject=subject_a,
            username=f"admin-a-{suffix}",
            email=f"admin-a-{suffix}@example.test",
        )
        repository.bootstrap_tenant(
            tenant_id=tenant_b,
            tenant_slug=f"tenant-b-{suffix}",
            tenant_name="P1 acceptance tenant B",
            issuer="https://identity.example.test/realms/vulnlab",
            subject=subject_b,
            username=f"admin-b-{suffix}",
            email=f"admin-b-{suffix}@example.test",
        )
        principal_a = repository.resolve_principal(
            _identity(tenant_a, subject_a, f"admin-a-{suffix}")
        )
        checks["bootstrap_identity"] = principal_a.user_id == admin_a
        checks["fixed_role_permissions"] = principal_a.can("role.assign") and not principal_a.can(
            "task.execute"
        )

        with repository.tenant_transaction(tenant_a) as connection:
            visible_tenants = connection.execute(
                "SELECT id FROM iam.tenants ORDER BY id"
            ).fetchall()
            cross_tenant = connection.execute(
                "SELECT id FROM iam.tenants WHERE id = %s", (str(tenant_b),)
            ).fetchone()
        checks["rls_single_tenant"] = [row["id"] for row in visible_tenants] == [tenant_a]
        checks["rls_cross_tenant_hidden"] = cross_tenant is None
        with psycopg.connect(app_dsn, autocommit=True) as application_connection:
            application_connection.execute(
                "SELECT set_config('app.tenant_id', %s, false)", (str(tenant_a),)
            )
            try:
                application_connection.execute("DELETE FROM iam.projects WHERE false")
            except InsufficientPrivilege:
                checks["application_role_cannot_delete_business_data"] = True
            else:
                checks["application_role_cannot_delete_business_data"] = False

        request_id, trace_id = _correlation()
        first_user = repository.provision_user(
            principal_a,
            issuer=principal_a.issuer,
            subject=f"operator-{suffix}",
            username=f"operator-{suffix}",
            email=f"operator-{suffix}@example.test",
            idempotency_key=f"provision-user-{suffix}-0001",
            request_id=request_id,
            trace_id=trace_id,
        )
        replay = repository.provision_user(
            principal_a,
            issuer=principal_a.issuer,
            subject=f"operator-{suffix}",
            username=f"operator-{suffix}",
            email=f"operator-{suffix}@example.test",
            idempotency_key=f"provision-user-{suffix}-0001",
            request_id=request_id,
            trace_id=trace_id,
        )
        checks["idempotent_replay"] = replay.replayed and replay.body["id"] == first_user.body["id"]
        try:
            repository.provision_user(
                principal_a,
                issuer=principal_a.issuer,
                subject=f"different-{suffix}",
                username=f"different-{suffix}",
                email=None,
                idempotency_key=f"provision-user-{suffix}-0001",
                request_id=request_id,
                trace_id=trace_id,
            )
        except EnterpriseConflictError as exc:
            checks["idempotency_key_reuse_rejected"] = exc.code == "idempotency_key_reused"
        else:
            checks["idempotency_key_reuse_rejected"] = False
        with repository.tenant_transaction(tenant_a) as connection:
            connection.execute(
                """
                UPDATE control.idempotency_records
                SET created_at = CURRENT_TIMESTAMP - INTERVAL '2 days',
                    expires_at = CURRENT_TIMESTAMP - INTERVAL '1 second'
                WHERE tenant_id = %s AND operation = 'membership.provision'
                  AND idempotency_key = %s
                """,
                (str(tenant_a), f"provision-user-{suffix}-0001"),
            )
        request_id, trace_id = _correlation()
        expired_reuse = repository.provision_user(
            principal_a,
            issuer=principal_a.issuer,
            subject=f"expired-window-{suffix}",
            username=f"expired-window-{suffix}",
            email=None,
            idempotency_key=f"provision-user-{suffix}-0001",
            request_id=request_id,
            trace_id=trace_id,
        )
        checks["expired_idempotency_reclaimed"] = not expired_reuse.replayed

        request_id, trace_id = _correlation()
        project = repository.create_project(
            principal_a,
            organization_id=None,
            slug=f"project-{suffix}",
            display_name="P1 acceptance project",
            idempotency_key=f"create-project-{suffix}-0001",
            request_id=request_id,
            trace_id=trace_id,
        )
        project_id = UUID(project.body["id"])
        target_user_id = UUID(first_user.body["id"])
        with repository.tenant_transaction(tenant_a) as connection:
            tenant_role = connection.execute(
                "SELECT id FROM iam.roles WHERE tenant_id = %s AND code = 'tenant_admin'",
                (str(tenant_a),),
            ).fetchone()
            if tenant_role is None:
                raise RuntimeError("tenant_admin role is missing")
            try:
                connection.execute(
                    """
                    INSERT INTO iam.user_roles (
                        id, tenant_id, project_id, user_id, role_id, granted_by, reason
                    ) VALUES (%s, %s, %s, %s, %s, %s, %s)
                    """,
                    (
                        uuid4(),
                        str(tenant_a),
                        str(project_id),
                        str(target_user_id),
                        tenant_role["id"],
                        str(principal_a.user_id),
                        "must be rejected by database scope trigger",
                    ),
                )
            except CheckViolation:
                checks["database_role_scope_enforced"] = True
            else:
                checks["database_role_scope_enforced"] = False
        request_id, trace_id = _correlation()
        assignment = repository.grant_role(
            principal_a,
            user_id=target_user_id,
            role_code="task_operator",
            project_id=project_id,
            reason="P1 immediate revocation acceptance",
            expires_at=None,
            idempotency_key=f"grant-role-{suffix}-0001",
            request_id=request_id,
            trace_id=trace_id,
        )
        operator_identity = _identity(tenant_a, f"operator-{suffix}", f"operator-{suffix}")
        operator_before = repository.resolve_principal(operator_identity)
        checks["project_role_granted"] = operator_before.can("task.execute", project_id)
        request_id, trace_id = _correlation()
        repository.revoke_role(
            principal_a,
            assignment_id=UUID(assignment.body["id"]),
            reason="P1 revocation boundary verified",
            idempotency_key=f"revoke-role-{suffix}-0001",
            request_id=request_id,
            trace_id=trace_id,
        )
        operator_after = repository.resolve_principal(operator_identity)
        checks["role_revocation_immediate"] = not operator_after.can("task.execute", project_id)

        request_id, trace_id = _correlation()
        tenant_config = repository.update_config(
            principal_a,
            config_key="ui.locale",
            scope_type="TENANT",
            project_id=None,
            user_id=None,
            value="en-US",
            expected_version=None,
            idempotency_key=f"config-tenant-{suffix}-0001",
            request_id=request_id,
            trace_id=trace_id,
        )
        request_id, trace_id = _correlation()
        repository.update_config(
            principal_a,
            config_key="ui.locale",
            scope_type="PROJECT",
            project_id=project_id,
            user_id=None,
            value="zh-CN",
            expected_version=None,
            idempotency_key=f"config-project-{suffix}-0001",
            request_id=request_id,
            trace_id=trace_id,
        )
        effective = repository.get_effective_config(
            principal_a, project_id=project_id, user_id=target_user_id
        )
        checks["config_hierarchy"] = (
            tenant_config.body["version"] == 1
            and effective["values"]["ui.locale"] == "zh-CN"
            and effective["sources"]["ui.locale"] == "PROJECT"
        )

        audit_rows, _ = repository.list_audit_events(
            principal_a, page_size=100, cursor=None, project_id=None
        )
        checks["audit_events_written"] = len(audit_rows) >= 5
        audit_event_id = audit_rows[0]["id"]
        with psycopg.connect(admin_dsn, autocommit=True) as admin_connection:
            try:
                admin_connection.execute(
                    "UPDATE audit.events SET action = 'tampered' WHERE id = %s",
                    (audit_event_id,),
                )
            except ObjectNotInPrerequisiteState:
                checks["audit_trigger_append_only"] = True
            else:
                checks["audit_trigger_append_only"] = False
        with repository.tenant_transaction(tenant_a) as connection:
            try:
                connection.execute("DELETE FROM audit.events WHERE id = %s", (audit_event_id,))
            except (InsufficientPrivilege, ObjectNotInPrerequisiteState):
                checks["audit_app_role_cannot_mutate"] = True
            else:
                checks["audit_app_role_cannot_mutate"] = False
    finally:
        repository.close()

    return {
        "valid": all(checks.values()),
        "checked_at": datetime.now(UTC).isoformat(),
        "checks": checks,
        "tenant_count": 2,
    }


def main() -> int:
    result = validate()
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["valid"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
