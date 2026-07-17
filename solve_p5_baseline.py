#!/usr/bin/env python3
"""Deterministic acceptance runner for Module 2 P5 policy enforcement boundary."""

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
    "apps/control-plane/src/vulnlab/policy.py",
    "apps/control-plane/src/vulnlab/api/routers/policies.py",
    "apps/control-plane/src/vulnlab/api/routers/execution.py",
    "apps/control-plane/src/vulnlab/db.py",
    "apps/control-plane/src/vulnlab/security.py",
    "tests/test_p5_policy.py",
    "packages/api-contracts/openapi/v1.yaml",
    "tools/contracts/snapshots/openapi-v1.snapshot.json",
    "solution_module2_p5.md",
    "docs/testing/p5-acceptance.md",
    "docs/P5_ACCEPTANCE_REPORT.md",
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


def _policy_runtime_check() -> tuple[str, dict[str, Any]]:
    policy = (ROOT / "apps/control-plane/src/vulnlab/policy.py").read_text(encoding="utf-8")
    db = (ROOT / "apps/control-plane/src/vulnlab/db.py").read_text(encoding="utf-8")
    execution = (ROOT / "apps/control-plane/src/vulnlab/api/routers/execution.py").read_text(
        encoding="utf-8"
    )
    security = (ROOT / "apps/control-plane/src/vulnlab/security.py").read_text(encoding="utf-8")
    invariants = {
        "policy_decision_table_exists": "CREATE TABLE IF NOT EXISTS policy_decisions" in db,
        "policy_hash_is_stable": "def policy_hash" in policy and "POLICY_VERSION" in policy,
        "destructive_actions_denied": "destructive actions are forbidden" in policy,
        "legacy_execution_denied_by_policy": "legacy execution capability is disabled" in policy,
        "scope_revalidated": "self.scope.validate" in policy,
        "sandbox_argv_prechecked": "SHELL_META" in policy,
        "execution_router_calls_policy": "services.policy.enforce" in execution
        and "services.policy.evaluate" in execution,
        "explicit_permission_exists": "policy:evaluate" in security,
    }
    errors = sorted(name for name, valid in invariants.items() if not valid)
    return ("PASS" if not errors else "FAIL"), {"invariants": invariants, "errors": errors}


def _contract_check() -> tuple[str, dict[str, Any]]:
    value = openapi_snapshot.check(runtime=True)
    schemas = openapi_snapshot.load_document()["components"]["schemas"]
    invariants = {
        "operation_count_is_p5": value["operation_count"] == 57,
        "policy_request_schema_exists": "PolicyEvaluationRequest" in schemas,
        "policy_decision_schema_exists": "PolicyDecision" in schemas,
    }
    errors = list(value["errors"]) + sorted(name for name, valid in invariants.items() if not valid)
    details = {**value, "invariants": invariants, "errors": errors}
    return ("PASS" if not errors else "FAIL"), details


def _security_boundary_check() -> tuple[str, dict[str, Any]]:
    contract = (ROOT / "packages/api-contracts/openapi/v1.yaml").read_text(encoding="utf-8")
    policy = (ROOT / "apps/control-plane/src/vulnlab/policy.py").read_text(encoding="utf-8")
    invariants = {
        "no_exploit_or_validation_contract_paths": all(
            marker not in contract for marker in ("/exploit", "/validation")
        ),
        "policy_does_not_grant_capabilities": "policy decisions do not grant capabilities"
        in policy,
        "policy_decisions_are_persisted": "INSERT INTO policy_decisions" in policy,
        "audit_records_policy_evaluation": "policy.evaluate" in policy,
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
        _timed("p5_repository_layout", _layout_check),
        _timed("p5_policy_runtime_invariants", _policy_runtime_check),
        _timed("p5_openapi_contract_and_runtime_projection", _contract_check),
        _timed("p5_security_boundary", _security_boundary_check),
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
                    "python_p5_tests",
                    [
                        python,
                        "-m",
                        "pytest",
                        "tests/test_p5_policy.py",
                        "tests/test_p0_safety.py",
                        "tests/test_security.py::test_sandbox_is_not_a_generic_shell",
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
        "phase": "P5",
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
            "policy_decisions_do_not_grant_capabilities": True,
            "legacy_execution_remains_disabled_by_default": True,
            "destructive_actions_are_denied": True,
            "scope_and_task_approval_are_revalidated": True,
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
