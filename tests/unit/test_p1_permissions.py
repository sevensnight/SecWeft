from __future__ import annotations

from types import MappingProxyType
from uuid import uuid4

from vulnlab.enterprise.models import EnterprisePrincipal
from vulnlab.enterprise.permissions import PERMISSION_CODES, ROLE_BY_CODE, ROLE_DEFINITIONS


def test_eight_fixed_roles_have_explicit_known_permissions() -> None:
    assert set(ROLE_BY_CODE) == {
        "platform_admin",
        "tenant_admin",
        "project_admin",
        "security_researcher",
        "task_operator",
        "approver",
        "auditor",
        "readonly_user",
    }
    assert all(role.permissions <= PERMISSION_CODES for role in ROLE_DEFINITIONS)
    assert all(
        "*" not in permission for role in ROLE_DEFINITIONS for permission in role.permissions
    )


def test_role_allow_and_deny_matrix_preserves_separation_of_duties() -> None:
    expected = {
        "platform_admin": ("tenant.suspend", "task.execute"),
        "tenant_admin": ("membership.invite", "approval.decide"),
        "project_admin": ("task.submit", "task.execute"),
        "security_researcher": ("validation_plan.draft", "validation_plan.approve"),
        "task_operator": ("task.execute", "approval.decide"),
        "approver": ("approval.decide", "task.execute"),
        "auditor": ("audit.export", "role.assign"),
        "readonly_user": ("task.read", "task.create"),
    }
    for role_code, (allowed, denied) in expected.items():
        permissions = ROLE_BY_CODE[role_code].permissions
        assert allowed in permissions, role_code
        assert denied not in permissions, role_code


def test_cross_scope_control_roles_are_explicitly_tenant_or_project_scoped() -> None:
    assert ROLE_BY_CODE["approver"].scope_type == "BOTH"
    assert ROLE_BY_CODE["auditor"].scope_type == "BOTH"
    assert ROLE_BY_CODE["tenant_admin"].scope_type == "TENANT"
    assert ROLE_BY_CODE["task_operator"].scope_type == "PROJECT"


def test_principal_unions_tenant_and_selected_project_permissions_only() -> None:
    tenant_id = uuid4()
    user_id = uuid4()
    first_project = uuid4()
    second_project = uuid4()
    principal = EnterprisePrincipal(
        user_id=user_id,
        tenant_id=tenant_id,
        issuer="https://identity.example.test",
        subject="subject",
        username="user",
        email=None,
        tenant_status="ACTIVE",
        tenant_roles=frozenset({"tenant_admin"}),
        tenant_permissions=frozenset({"project.read"}),
        project_roles=MappingProxyType({first_project: frozenset({"task_operator"})}),
        project_permissions=MappingProxyType(
            {first_project: frozenset({"task.execute", "task.read"})}
        ),
    )

    assert principal.can("project.read", first_project)
    assert principal.can("project.read", second_project)
    assert principal.can("task.execute", first_project)
    assert not principal.can("task.execute", second_project)
    assert not principal.can("*")
    assert principal.authorized_project_ids == frozenset({first_project})
