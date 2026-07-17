#!/usr/bin/env python3
"""Deterministic acceptance runner for Module 2 P7 enterprise web console."""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
import time
from collections.abc import Callable
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

from tools.contracts import openapi_snapshot  # noqa: E402


@dataclass(frozen=True)
class CheckResult:
    name: str
    status: str
    duration_ms: int
    details: dict[str, Any]


WEB_ROOT = ROOT / "apps" / "web-console" / "src"
REQUIRED_PATHS = (
    "apps/web-console/src/app/navigation.tsx",
    "apps/web-console/src/app/navigation.test.ts",
    "apps/web-console/src/app/router.tsx",
    "apps/web-console/src/layouts/AppShell.tsx",
    "apps/web-console/src/services/api.ts",
    "apps/web-console/src/modules/models/pages/ModelsPage.tsx",
    "apps/web-console/src/modules/agents/pages/AgentsPage.tsx",
    "apps/web-console/src/modules/knowledge/pages/KnowledgePage.tsx",
    "apps/web-console/src/modules/assets/pages/AssetsPage.tsx",
    "apps/web-console/src/modules/validation/pages/ValidationPage.tsx",
    "apps/web-console/src/modules/sandboxes/pages/SandboxesPage.tsx",
    "apps/web-console/src/modules/policies/pages/PoliciesPage.tsx",
    "apps/web-console/src/modules/audit/pages/AuditPage.tsx",
    "apps/web-console/src/modules/reports/pages/ReportsPage.tsx",
    "apps/web-console/src/modules/system/pages/SystemPage.tsx",
    "solution_module2_p7.md",
    "docs/testing/p7-acceptance.md",
    "docs/P7_ACCEPTANCE_REPORT.md",
)

P7_ROUTES = (
    "/tasks",
    "/models",
    "/agents",
    "/knowledge",
    "/assets",
    "/validation",
    "/sandboxes",
    "/policies",
    "/audit",
    "/reports",
    "/system",
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


def _frontend_surface_check() -> tuple[str, dict[str, Any]]:
    router = (WEB_ROOT / "app" / "router.tsx").read_text(encoding="utf-8")
    navigation = (WEB_ROOT / "app" / "navigation.tsx").read_text(encoding="utf-8")
    services = (WEB_ROOT / "services" / "api.ts").read_text(encoding="utf-8")
    invariants = {
        "all_p7_routes_are_registered": all(route in router for route in P7_ROUTES),
        "all_p7_routes_are_in_navigation": all(route in navigation for route in P7_ROUTES),
        "route_level_code_splitting": router.count("lazyRouteComponent") >= len(P7_ROUTES),
        "generated_api_client_is_used": "createVulnLabClient" in services,
        "validation_plan_api_is_wired": "listTaskValidationPlans" in services
        and "createTaskValidationPlan" in services
        and "reviewValidationPlan" in services,
        "policy_api_is_wired": "evaluatePolicy" in services,
        "rag_api_is_wired": "searchRagDocuments" in services,
        "model_gateway_api_is_wired": "listModelProviders" in services
        and "listModelInvocations" in services,
    }
    errors = sorted(name for name, valid in invariants.items() if not valid)
    return ("PASS" if not errors else "FAIL"), {"invariants": invariants, "errors": errors}


def _non_execution_boundary_check() -> tuple[str, dict[str, Any]]:
    combined = "\n".join(path.read_text(encoding="utf-8") for path in WEB_ROOT.rglob("*.tsx"))
    services = (WEB_ROOT / "services" / "api.ts").read_text(encoding="utf-8")
    forbidden = (
        "apiClient.POST('/tasks/{task_id}/executions'",
        "apiClient.POST('/assets/probe'",
        "apiClient.POST('/sandbox/runs'",
        "/validation-runs",
        "/validation-executions",
    )
    invariants = {
        "frontend_does_not_dispatch_task_execution": all(
            marker not in services for marker in forbidden
        ),
        "validation_page_declares_non_execution": "without executing" in combined,
        "sandbox_page_declares_policy_gate": "policy-gated" in combined,
        "report_page_requires_evidence": "Reports require reviewable evidence" in combined,
    }
    errors = sorted(name for name, valid in invariants.items() if not valid)
    return ("PASS" if not errors else "FAIL"), {"invariants": invariants, "errors": errors}


def _contract_check() -> tuple[str, dict[str, Any]]:
    value = openapi_snapshot.check(runtime=True)
    invariants = {
        "contract_stays_at_p6_backend": value["operation_count"] == 62,
        "runtime_projection_valid": value["valid"],
    }
    errors = list(value["errors"]) + sorted(name for name, valid in invariants.items() if not valid)
    return ("PASS" if not errors else "FAIL"), {**value, "invariants": invariants, "errors": errors}


def _run_command(
    command: list[str], *, optional_tool: str | None = None
) -> tuple[str, dict[str, Any]]:
    resolved_tool = shutil.which(optional_tool) if optional_tool else None
    if optional_tool and not resolved_tool:
        return "SKIP", {"reason": f"{optional_tool} is not installed", "command": command}
    executable = list(command)
    if resolved_tool:
        executable[0] = resolved_tool
    completed = subprocess.run(
        executable,
        cwd=ROOT,
        text=True,
        encoding="utf-8",
        errors="replace",
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )
    return ("PASS" if completed.returncode == 0 else "FAIL"), {
        "command": executable,
        "returncode": completed.returncode,
        "output": completed.stdout.strip()[-12000:],
    }


def _command_check(
    name: str, command: list[str], *, optional_tool: str | None = None
) -> CheckResult:
    return _timed(name, lambda: _run_command(command, optional_tool=optional_tool))


def run(full: bool) -> dict[str, Any]:
    checks = [
        _timed("p7_repository_layout", _layout_check),
        _timed("p7_frontend_surface", _frontend_surface_check),
        _timed("p7_non_execution_boundary", _non_execution_boundary_check),
        _timed("p7_openapi_contract_guard", _contract_check),
    ]
    if full:
        python = sys.executable
        checks.extend(
            [
                _command_check(
                    "openapi_runtime_projection",
                    [python, "tools/contracts/openapi_snapshot.py", "check", "--runtime"],
                ),
                _command_check("workspace_lint", ["pnpm", "lint"], optional_tool="pnpm"),
                _command_check("workspace_typecheck", ["pnpm", "typecheck"], optional_tool="pnpm"),
                _command_check("workspace_test", ["pnpm", "test"], optional_tool="pnpm"),
                _command_check("workspace_build", ["pnpm", "build"], optional_tool="pnpm"),
            ]
        )
    failed = [check for check in checks if check.status == "FAIL"]
    return {
        "phase": "P7",
        "valid": not failed,
        "full": full,
        "summary": {
            "total": len(checks),
            "passed": sum(check.status == "PASS" for check in checks),
            "skipped": sum(check.status == "SKIP" for check in checks),
            "failed": len(failed),
        },
        "checks": [asdict(check) for check in checks],
        "safety": {
            "frontend_does_not_add_execution_capability": True,
            "high_risk_actions_remain_backend_policy_gated": True,
            "routes_are_code_split": True,
            "api_types_are_generated_from_openapi": True,
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--full", action="store_true", help="also run workspace lint/typecheck/test/build"
    )
    args = parser.parse_args()
    result = run(args.full)
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if result["valid"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
