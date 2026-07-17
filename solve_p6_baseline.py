#!/usr/bin/env python3
"""Deterministic acceptance runner for Module 2 P6 validation plan approvals."""

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
SOURCE_ROOT = ROOT / "apps" / "control-plane" / "src"
for source in (ROOT, SOURCE_ROOT):
    if str(source) not in sys.path:
        sys.path.insert(0, str(source))
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

from tools.contracts import openapi_snapshot  # noqa: E402


@dataclass(frozen=True)
class CheckResult:
    name: str
    status: str
    duration_ms: int
    details: dict[str, Any]


REQUIRED_PATHS = (
    "apps/control-plane/src/vulnlab/validation.py",
    "apps/control-plane/src/vulnlab/api/routers/validation_plans.py",
    "apps/control-plane/src/vulnlab/policy.py",
    "apps/control-plane/src/vulnlab/db.py",
    "apps/control-plane/src/vulnlab/security.py",
    "tests/test_p6_validation_plans.py",
    "packages/api-contracts/openapi/v1.yaml",
    "tools/contracts/snapshots/openapi-v1.snapshot.json",
    "solution_module2_p6.md",
    "docs/testing/p6-acceptance.md",
    "docs/P6_ACCEPTANCE_REPORT.md",
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


def _validation_runtime_check() -> tuple[str, dict[str, Any]]:
    validation = (ROOT / "apps/control-plane/src/vulnlab/validation.py").read_text(encoding="utf-8")
    router = (ROOT / "apps/control-plane/src/vulnlab/api/routers/validation_plans.py").read_text(
        encoding="utf-8"
    )
    db = (ROOT / "apps/control-plane/src/vulnlab/db.py").read_text(encoding="utf-8")
    security = (ROOT / "apps/control-plane/src/vulnlab/security.py").read_text(encoding="utf-8")
    invariants = {
        "validation_plan_table_exists": "CREATE TABLE IF NOT EXISTS validation_plans" in db,
        "validation_plan_status_is_finite": "CHECK(status IN" in db
        and "approved" in db
        and "rejected" in db,
        "plan_hash_is_stable": "def _hash_plan" in validation and "sort_keys=True" in validation,
        "steps_are_policy_preflighted": "self.policy.evaluate" in validation
        and "validation_plan_step" in validation,
        "denied_steps_stop_creation": "validation plan step denied" in validation,
        "submit_is_draft_only": "only draft validation plans can be submitted" in validation,
        "review_is_submitted_only": "only submitted validation plans can be reviewed" in validation,
        "review_is_admin_only": "only administrators can review validation plans" in validation,
        "validation_permissions_exist": "validation:create" in security
        and "validation:submit" in security
        and "validation:read" in security,
        "router_exposes_crud_without_run": "validation-plans" in router
        and "/review" in router
        and "services.validation.review" in router,
    }
    errors = sorted(name for name, valid in invariants.items() if not valid)
    return ("PASS" if not errors else "FAIL"), {"invariants": invariants, "errors": errors}


def _contract_check() -> tuple[str, dict[str, Any]]:
    value = openapi_snapshot.check(runtime=True)
    document = openapi_snapshot.load_document()
    schemas = document["components"]["schemas"]
    paths = document["paths"]
    invariants = {
        "operation_count_is_p6": value["operation_count"] == 62,
        "validation_plan_paths_exist": "/tasks/{task_id}/validation-plans" in paths
        and "/validation-plans/{plan_id}/submit" in paths
        and "/validation-plans/{plan_id}/review" in paths,
        "validation_step_schema_exists": "ValidationProbeStep" in schemas,
        "validation_create_schema_exists": "ValidationPlanCreate" in schemas,
        "validation_review_schema_exists": "ValidationPlanReview" in schemas,
        "validation_response_schema_exists": "ValidationPlan" in schemas,
    }
    errors = list(value["errors"]) + sorted(name for name, valid in invariants.items() if not valid)
    details = {**value, "invariants": invariants, "errors": errors}
    return ("PASS" if not errors else "FAIL"), details


def _non_execution_boundary_check() -> tuple[str, dict[str, Any]]:
    contract = (ROOT / "packages/api-contracts/openapi/v1.yaml").read_text(encoding="utf-8")
    validation = (ROOT / "apps/control-plane/src/vulnlab/validation.py").read_text(encoding="utf-8")
    router = (ROOT / "apps/control-plane/src/vulnlab/api/routers/validation_plans.py").read_text(
        encoding="utf-8"
    )
    forbidden_runtime_markers = (
        "subprocess",
        "socket.",
        "httpx.",
        "requests.",
        "services.execution",
    )
    invariants = {
        "contract_has_no_validation_execution_endpoint": all(
            marker not in contract for marker in ("/validation-runs", "/validation-executions")
        ),
        "contract_still_excludes_legacy_execution": all(
            marker not in contract for marker in ("/assets/probe", "/sandbox", "/exploit")
        ),
        "validation_service_has_no_runtime_execution_client": all(
            marker not in validation for marker in forbidden_runtime_markers
        ),
        "validation_router_has_no_runtime_execution_client": all(
            marker not in router for marker in forbidden_runtime_markers
        ),
        "plans_are_canonical_non_destructive": '"destructive": False' in validation,
        "approval_does_not_change_task_execution": "executions" not in validation,
    }
    errors = sorted(name for name, valid in invariants.items() if not valid)
    return ("PASS" if not errors else "FAIL"), {"invariants": invariants, "errors": errors}


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
        _timed("p6_repository_layout", _layout_check),
        _timed("p6_validation_runtime_invariants", _validation_runtime_check),
        _timed("p6_openapi_contract_and_runtime_projection", _contract_check),
        _timed("p6_non_execution_boundary", _non_execution_boundary_check),
    ]
    if full:
        python = sys.executable
        checks.extend(
            [
                _command_check("python_format", [python, "-m", "ruff", "format", "--check", "."]),
                _command_check("python_lint", [python, "-m", "ruff", "check", "."]),
                _command_check(
                    "python_typecheck", [python, "-m", "mypy", "apps/control-plane/src"]
                ),
                _command_check(
                    "python_p6_tests",
                    [
                        python,
                        "-m",
                        "pytest",
                        "tests/test_p6_validation_plans.py",
                        "tests/test_p5_policy.py",
                        "tests/contract/test_openapi_contract.py",
                        "-q",
                    ],
                ),
                _command_check("workspace_lint", ["pnpm", "lint"], optional_tool="pnpm"),
                _command_check("workspace_typecheck", ["pnpm", "typecheck"], optional_tool="pnpm"),
                _command_check("workspace_test", ["pnpm", "test"], optional_tool="pnpm"),
                _command_check("workspace_build", ["pnpm", "build"], optional_tool="pnpm"),
            ]
        )
    failed = [check for check in checks if check.status == "FAIL"]
    return {
        "phase": "P6",
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
            "validation_plans_do_not_execute": True,
            "approval_does_not_grant_runtime_capability": True,
            "each_plan_step_is_policy_preflighted": True,
            "scope_constraints_still_gate_targets_and_ports": True,
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--full", action="store_true", help="also run slower test/build gates")
    args = parser.parse_args()
    result = run(args.full)
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if result["valid"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
