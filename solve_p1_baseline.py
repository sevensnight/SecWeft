#!/usr/bin/env python3
"""Deterministic acceptance runner for the Module 2 P1 enterprise baseline.

The default run is read-only. The full option adds local lint, type, test, and
build gates. PostgreSQL, Keycloak, and browser integration checks are opt-in
because they require explicitly supplied isolated test services.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import time
from collections.abc import Callable
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent
SOURCE_ROOT = ROOT / "apps" / "control-plane" / "src"
for source in (ROOT, SOURCE_ROOT):
    if str(source) not in sys.path:
        sys.path.insert(0, str(source))
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

from vulnlab.enterprise.permissions import ROLE_BY_CODE  # noqa: E402

from tools.contracts import check_migrations, openapi_snapshot  # noqa: E402


@dataclass(frozen=True)
class CheckResult:
    name: str
    status: str
    duration_ms: int
    details: dict[str, Any]


REQUIRED_PATHS = (
    "apps/control-plane/src/vulnlab/api/enterprise_dependencies.py",
    "apps/control-plane/src/vulnlab/api/routers/enterprise_iam.py",
    "apps/control-plane/src/vulnlab/enterprise/auth.py",
    "apps/control-plane/src/vulnlab/enterprise/models.py",
    "apps/control-plane/src/vulnlab/enterprise/permissions.py",
    "apps/control-plane/src/vulnlab/enterprise/repository.py",
    "apps/control-plane/src/vulnlab/enterprise/services.py",
    "apps/control-plane/src/vulnlab/observability.py",
    "apps/web-console/src/auth/AuthBoundary.tsx",
    "apps/web-console/src/auth/oidc.ts",
    "apps/web-console/src/modules/identity/pages/EnterpriseAccessPage.tsx",
    "infrastructure/keycloak/realm-vulnlab-development.json",
    "infrastructure/migrations/0002_p1_identity_tenancy_rbac.up.sql",
    "infrastructure/migrations/0002_p1_identity_tenancy_rbac.down.sql",
    "infrastructure/migrations/0003_p1_role_scope_enforcement.up.sql",
    "infrastructure/migrations/0003_p1_role_scope_enforcement.down.sql",
    "infrastructure/migrations/0004_p1_application_least_privilege.up.sql",
    "infrastructure/migrations/0004_p1_application_least_privilege.down.sql",
    "infrastructure/postgres/migrate.sh",
    "tests/integration/test_p1_enterprise_api.py",
    "tests/unit/test_p1_oidc.py",
    "tests/unit/test_p1_observability.py",
    "tests/unit/test_p1_permissions.py",
    "tests/unit/test_p1_settings.py",
    "tools/p1/bootstrap_tenant.py",
    "tools/p1/validate_enterprise_postgres.py",
    "tools/p1/validate_keycloak_oidc.mjs",
    "tools/p1/validate_oidc_browser_entry.mjs",
    "docs/testing/p1-acceptance.md",
    "docs/P1_ACCEPTANCE_REPORT.md",
    "solution_module2_p1.md",
)


def _timed(name: str, function: Callable[[], tuple[str, dict[str, Any]]]) -> CheckResult:
    started = time.perf_counter()
    try:
        status, details = function()
    except Exception as exc:
        status, details = "FAIL", {"errors": [f"{type(exc).__name__}: {exc}"]}
    return CheckResult(
        name=name,
        status=status,
        duration_ms=round((time.perf_counter() - started) * 1000),
        details=details,
    )


def _layout_check() -> tuple[str, dict[str, Any]]:
    missing = [path for path in REQUIRED_PATHS if not (ROOT / path).is_file()]
    return ("PASS" if not missing else "FAIL"), {
        "required_file_count": len(REQUIRED_PATHS),
        "missing": missing,
    }


def _auth_defaults_check() -> tuple[str, dict[str, Any]]:
    settings = (ROOT / "apps/control-plane/src/vulnlab/config.py").read_text(encoding="utf-8")
    env_example = (ROOT / ".env.example").read_text(encoding="utf-8")
    invariants = {
        "compatibility_is_explicit_example_default": bool(
            re.search(r"(?m)^VULNLAB_AUTH_MODE=compatibility\s*$", env_example)
        ),
        "production_requires_oidc": "Production requires VULNLAB_AUTH_MODE=oidc" in settings,
        "production_requires_explicit_master_key": (
            "Production requires an explicit unique VULNLAB_MASTER_KEY" in settings
        ),
        "oidc_algorithm_is_not_configurable": "VULNLAB_OIDC_ALGORITHM" not in settings,
        "database_url_is_postgresql_only": 'startswith("postgresql://")' in settings,
        "mfa_acr_enforcement_extension_is_configurable": (
            "VULNLAB_OIDC_REQUIRED_ACR" in settings and "required_acr" in settings
        ),
    }
    failed = sorted(name for name, valid in invariants.items() if not valid)
    return ("PASS" if not failed else "FAIL"), {"invariants": invariants, "errors": failed}


def _role_catalog_check() -> tuple[str, dict[str, Any]]:
    expected = {
        "platform_admin",
        "tenant_admin",
        "project_admin",
        "security_researcher",
        "task_operator",
        "approver",
        "auditor",
        "readonly_user",
    }
    invariants = {
        "exact_fixed_role_set": set(ROLE_BY_CODE) == expected,
        "no_wildcard_permissions": all(
            "*" not in permission
            for role in ROLE_BY_CODE.values()
            for permission in role.permissions
        ),
        "platform_admin_cannot_execute_tasks": (
            "task.execute" not in ROLE_BY_CODE["platform_admin"].permissions
        ),
        "approver_and_auditor_support_bounded_dual_scope": (
            ROLE_BY_CODE["approver"].scope_type == "BOTH"
            and ROLE_BY_CODE["auditor"].scope_type == "BOTH"
        ),
    }
    failed = sorted(name for name, valid in invariants.items() if not valid)
    return ("PASS" if not failed else "FAIL"), {"invariants": invariants, "errors": failed}


def _keycloak_realm_check() -> tuple[str, dict[str, Any]]:
    realm = json.loads(
        (ROOT / "infrastructure/keycloak/realm-vulnlab-development.json").read_text(
            encoding="utf-8"
        )
    )
    clients = {client["clientId"]: client for client in realm["clients"]}
    web = clients["vulnlab-web-console"]
    api = clients["vulnlab-control-plane"]
    mappers = {mapper["name"]: mapper for mapper in web["protocolMappers"]}
    provider = realm["components"]["org.keycloak.userprofile.UserProfileProvider"][0]
    profile = json.loads(provider["config"]["kc.user.profile.config"][0])
    tenant_attribute = next(
        attribute for attribute in profile["attributes"] if attribute["name"] == "tenant_id"
    )
    invariants = {
        "no_checked_in_users": realm.get("users") == [],
        "authorization_code_pkce_only": (
            web["standardFlowEnabled"]
            and not web["implicitFlowEnabled"]
            and not web["directAccessGrantsEnabled"]
            and web["attributes"]["pkce.code.challenge.method"] == "S256"
        ),
        "api_is_bearer_only": api["bearerOnly"] is True,
        "audience_mapper_present": (
            mappers["control-plane-audience"]["config"]["included.client.audience"]
            == "vulnlab-control-plane"
        ),
        "tenant_mapper_present": (mappers["tenant-id"]["config"]["claim.name"] == "tenant_id"),
        "tenant_attribute_is_managed_and_admin_editable": (
            tenant_attribute["multivalued"] is False
            and tenant_attribute["permissions"]["edit"] == ["admin"]
        ),
        "access_tokens_are_short_lived": realm["accessTokenLifespan"] <= 300,
        "refresh_tokens_rotate": (
            realm["revokeRefreshToken"] is True and realm["refreshTokenMaxReuse"] == 0
        ),
        "login_and_admin_events_enabled": (
            realm["eventsEnabled"] is True and realm["adminEventsEnabled"] is True
        ),
        "brute_force_protection_enabled": realm["bruteForceProtected"] is True,
    }
    failed = sorted(name for name, valid in invariants.items() if not valid)
    return ("PASS" if not failed else "FAIL"), {"invariants": invariants, "errors": failed}


def _contract_check() -> tuple[str, dict[str, Any]]:
    value = openapi_snapshot.check(runtime=True)
    return ("PASS" if value["valid"] else "FAIL"), value


def _migration_check() -> tuple[str, dict[str, Any]]:
    value = check_migrations.check()
    return ("PASS" if value["valid"] else "FAIL"), value


def _run_command(
    name: str,
    command: list[str],
    *,
    optional_tool: str | None = None,
) -> CheckResult:
    def execute() -> tuple[str, dict[str, Any]]:
        resolved = shutil.which(optional_tool) if optional_tool else command[0]
        if optional_tool and not resolved:
            return "SKIP", {"reason": f"{optional_tool} is not installed", "command": command}
        executable = list(command)
        if optional_tool and resolved:
            executable[0] = resolved
            if Path(resolved).suffix.lower() in {".bat", ".cmd"}:
                executable = [
                    os.environ.get("COMSPEC", "cmd.exe"),
                    "/d",
                    "/s",
                    "/c",
                    resolved,
                    *command[1:],
                ]
        completed = subprocess.run(
            executable,
            cwd=ROOT,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            check=False,
        )
        output = "\n".join(
            part.strip() for part in (completed.stdout, completed.stderr) if part.strip()
        )
        return ("PASS" if completed.returncode == 0 else "FAIL"), {
            "command": command,
            "returncode": completed.returncode,
            "output": output[-8000:],
        }

    return _timed(name, execute)


def run(*, full: bool, postgres: bool, keycloak: bool, browser: bool) -> dict[str, Any]:
    started = time.perf_counter()
    results = [
        _timed("p1_repository_layout", _layout_check),
        _timed("production_auth_fail_closed", _auth_defaults_check),
        _timed("fixed_role_catalog", _role_catalog_check),
        _timed("keycloak_realm_security", _keycloak_realm_check),
        _timed("openapi_contract_and_runtime_projection", _contract_check),
        _timed("postgres_migration_static_invariants", _migration_check),
        _run_command(
            "docker_compose_static_config",
            [
                "docker",
                "compose",
                "--env-file",
                "infrastructure/docker-compose/.env.platform.example",
                "-f",
                "infrastructure/docker-compose/platform.yml",
                "--profile",
                "identity",
                "config",
                "--quiet",
            ],
            optional_tool="docker",
        ),
    ]
    if full:
        results.extend(
            [
                _run_command(
                    "python_format",
                    [sys.executable, "-m", "ruff", "format", "--check", "."],
                ),
                _run_command("python_lint", [sys.executable, "-m", "ruff", "check", "."]),
                _run_command(
                    "python_typecheck",
                    [sys.executable, "-m", "mypy", "apps/control-plane/src/vulnlab"],
                ),
                _run_command(
                    "python_tests",
                    [sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider"],
                ),
                _run_command("workspace_lint", ["pnpm", "lint"], optional_tool="pnpm"),
                _run_command("workspace_typecheck", ["pnpm", "typecheck"], optional_tool="pnpm"),
                _run_command("workspace_tests", ["pnpm", "test"], optional_tool="pnpm"),
                _run_command("workspace_build", ["pnpm", "build"], optional_tool="pnpm"),
            ]
        )
    if postgres:
        results.append(
            _run_command(
                "postgresql_rls_and_repository_integration",
                [sys.executable, "tools/p1/validate_enterprise_postgres.py"],
            )
        )
    if keycloak:
        results.append(
            _run_command(
                "keycloak_authorization_code_pkce",
                ["node", "tools/p1/validate_keycloak_oidc.mjs"],
                optional_tool="node",
            )
        )
    if browser:
        results.append(
            _run_command(
                "browser_oidc_discovery_csp_and_pkce_entry",
                ["node", "tools/p1/validate_oidc_browser_entry.mjs"],
                optional_tool="node",
            )
        )
    counts = {
        status: sum(result.status == status for result in results)
        for status in ("PASS", "FAIL", "SKIP")
    }
    return {
        "phase": "P1",
        "scope": "identity-tenancy-rbac-configuration-audit",
        "valid": counts["FAIL"] == 0,
        "mode": "full" if full else "baseline",
        "duration_ms": round((time.perf_counter() - started) * 1000),
        "summary": {
            "passed": counts["PASS"],
            "failed": counts["FAIL"],
            "skipped": counts["SKIP"],
        },
        "checks": [asdict(result) for result in results],
        "safety": {
            "starts_containers": False,
            "executes_vulnerability_validation": False,
            "postgres_check_requires_isolated_test_database": postgres,
            "keycloak_check_creates_and_deletes_temporary_user": keycloak,
            "browser_check_launches_headless_chromium": browser,
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate the Module 2 P1 enterprise baseline")
    parser.add_argument("--full", action="store_true", help="run local quality and build gates")
    parser.add_argument(
        "--postgres",
        action="store_true",
        help="run the mutating PostgreSQL check against explicit P1_POSTGRES_* test variables",
    )
    parser.add_argument(
        "--keycloak",
        action="store_true",
        help="run Code+PKCE against explicit P1_KEYCLOAK_* test variables",
    )
    parser.add_argument(
        "--browser",
        action="store_true",
        help="verify browser OIDC discovery, gateway CSP, and the PKCE authorization request",
    )
    parser.add_argument("--output", type=Path, help="optionally write the UTF-8 JSON result")
    args = parser.parse_args()
    result = run(
        full=args.full,
        postgres=args.postgres,
        keycloak=args.keycloak,
        browser=args.browser,
    )
    rendered = json.dumps(result, ensure_ascii=False, indent=2) + "\n"
    if args.output:
        output = args.output if args.output.is_absolute() else ROOT / args.output
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(rendered, encoding="utf-8", newline="\n")
    print(rendered, end="")
    return 0 if result["valid"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
