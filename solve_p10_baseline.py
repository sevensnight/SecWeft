#!/usr/bin/env python3
"""Deterministic acceptance runner for Module 2 P10 remediation verification and case management."""

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

from tools.contracts import check_migrations, openapi_snapshot  # noqa: E402


@dataclass(frozen=True)
class CheckResult:
    name: str
    status: str
    duration_ms: int
    details: dict[str, Any]


REQUIRED_FILES = (
    "apps/control-plane/src/vulnlab/case_management.py",
    "apps/control-plane/src/vulnlab/api/routers/cases.py",
    "tests/test_p10_case_lifecycle.py",
    "solve_p10_baseline.py",
    "docs/architecture/p10-case-lifecycle.md",
    "docs/architecture/p10-remediation-model.md",
    "docs/testing/p10-validation-matrix.md",
    "docs/security/p10-human-decision-boundaries.md",
    "docs/acceptance/p10-acceptance-report.md",
    "infrastructure/migrations/0010_p10_case_lifecycle.up.sql",
    "infrastructure/migrations/0010_p10_case_lifecycle.down.sql",
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
    missing = [path for path in REQUIRED_FILES if not (ROOT / path).is_file()]
    return ("PASS" if not missing else "FAIL"), {
        "required_file_count": len(REQUIRED_FILES),
        "missing": missing,
    }


def _contract_check() -> tuple[str, dict[str, Any]]:
    value = openapi_snapshot.check(runtime=True)
    paths = openapi_snapshot.load_document()["paths"]
    required_paths = {
        "/vulnerability-cases",
        "/vulnerability-cases/{case_id}",
        "/vulnerability-cases/{case_id}/findings",
        "/vulnerability-cases/{case_id}/remediation-proposals",
        "/remediation-proposals/{proposal_id}/decisions",
        "/remediation-decisions/{decision_id}/implementations",
        "/vulnerability-cases/{case_id}/retests",
        "/retests/{retest_id}",
        "/retests/{retest_id}/comparison",
        "/vulnerability-cases/{case_id}/disposition",
        "/vulnerability-cases/{case_id}/close",
        "/vulnerability-cases/{case_id}/reports",
    }
    invariants = {
        "operation_count_is_p10": value["operation_count"] == 89,
        "all_p10_paths_exist": required_paths <= set(paths),
        "p9_validation_execution_paths_remain": "/validation-plans/{plan_id}/executions" in paths,
        "dangerous_paths_still_absent": all(
            marker not in path.lower()
            for path in paths
            for marker in ("/sandbox", "/assets/probe", "/exploit", "/validation-runs")
        ),
    }
    errors = list(value["errors"]) + sorted(name for name, valid in invariants.items() if not valid)
    return ("PASS" if not errors else "FAIL"), {**value, "invariants": invariants, "errors": errors}


def _migration_check() -> tuple[str, dict[str, Any]]:
    value = check_migrations.check()
    invariants = {
        "p10_migration_present": "0010_p10_case_lifecycle" in value["pairs"],
        "case_tables_are_tenant_safe": value["valid"],
    }
    errors = list(value["errors"]) + sorted(name for name, valid in invariants.items() if not valid)
    return ("PASS" if not errors else "FAIL"), {**value, "invariants": invariants, "errors": errors}


def _security_static_check() -> tuple[str, dict[str, Any]]:
    service = (ROOT / "apps/control-plane/src/vulnlab/case_management.py").read_text(
        encoding="utf-8"
    )
    validation_service = (
        ROOT / "apps/control-plane/src/vulnlab/validation_execution.py"
    ).read_text(encoding="utf-8")
    router = (ROOT / "apps/control-plane/src/vulnlab/api/routers/cases.py").read_text(
        encoding="utf-8"
    )
    tests = (ROOT / "tests/test_p10_case_lifecycle.py").read_text(encoding="utf-8")
    invariants = {
        "case_state_machine_defined": "CASE_ALLOWED_TRANSITIONS" in service
        and "DRAFT" in service
        and "CLOSED" in service,
        "retest_reuses_p9_execution_service": "self.validation_execution.create" in service
        and "validation.retest" in service,
        "comparison_requires_evidence_sha": "evidence_sha256" in service
        and "_execution_evidence_sha" in service,
        "ai_proposal_cannot_auto_approve": "automated remediation decisions cannot approve proposals"
        in service,
        "separation_of_duties_high_risk": "separation of duties" in service,
        "no_arbitrary_shell_added": "shell=True" not in service and "subprocess" not in service,
        "p9_templates_unchanged": all(
            marker in validation_service
            for marker in (
                '"http.response"',
                '"sbom.dependency-version"',
                '"local.training-lab"',
            )
        )
        and "shell.arbitrary" not in validation_service,
        "write_apis_accept_idempotency": "Idempotency-Key" in router,
        "negative_tests_cover_human_boundaries": "p10-ai-auto-approve" in tests
        and "p10-invalid-remediated" in tests,
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
    python = sys.executable
    checks = [
        _timed("p10_repository_layout", _layout_check),
        _timed("p10_openapi_contract_guard", _contract_check),
        _timed("p10_migration_guard", _migration_check),
        _timed("p10_security_static_guard", _security_static_check),
        _command_check(
            "p10_backend_case_lifecycle_tests",
            [python, "-m", "pytest", "tests/test_p10_case_lifecycle.py", "-q"],
        ),
        _command_check(
            "p10_contract_tests",
            [python, "-m", "pytest", "tests/contract/test_openapi_contract.py", "-q"],
        ),
        _command_check(
            "p10_migration_tests",
            [python, "-m", "pytest", "tests/contract/test_postgres_migrations.py", "-q"],
        ),
        _command_check(
            "p10_web_typecheck",
            ["pnpm", "--filter", "@vulnlab/web-console", "typecheck"],
            optional_tool="pnpm",
        ),
    ]
    if full:
        checks.extend(
            [
                _command_check(
                    "p9_baseline_compatibility",
                    [python, "solve_p9_baseline.py"],
                ),
                _command_check(
                    "python_compile",
                    [
                        python,
                        "-m",
                        "compileall",
                        "-q",
                        "apps/control-plane/src",
                        "solve_p10_baseline.py",
                    ],
                ),
                _command_check("python_format", [python, "-m", "ruff", "format", "--check", "."]),
                _command_check("python_lint", [python, "-m", "ruff", "check", "."]),
                _command_check("python_tests", [python, "-m", "pytest", "-q"]),
                _command_check("workspace_typecheck", ["pnpm", "typecheck"], optional_tool="pnpm"),
                _command_check("workspace_test", ["pnpm", "test"], optional_tool="pnpm"),
                _command_check("workspace_build", ["pnpm", "build"], optional_tool="pnpm"),
            ]
        )
    failed = [check for check in checks if check.status == "FAIL"]
    return {
        "phase": "P10",
        "valid": not failed,
        "full": full,
        "summary": {
            "total": len(checks),
            "passed": sum(check.status == "PASS" for check in checks),
            "skipped": sum(check.status == "SKIP" for check in checks),
            "failed": len(failed),
        },
        "checks": [asdict(check) for check in checks],
        "not_executed": {
            "new_validation_templates": "Not applicable; P10 intentionally adds no validation templates.",
            "arbitrary_poc_execution": "Not applicable; P10 does not add arbitrary PoC upload or shell execution.",
            "linux_runtime_network_authority": "Covered by P9-H runtime path, not expanded by P10.",
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--full", action="store_true", help="also run broader compatibility gates")
    args = parser.parse_args()
    result = run(args.full)
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if result["valid"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
