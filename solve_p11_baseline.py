#!/usr/bin/env python3
"""Deterministic acceptance runner for Module 2 P11 AI evaluation governance."""

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
    "apps/control-plane/src/vulnlab/evaluation_governance.py",
    "apps/control-plane/src/vulnlab/api/routers/evaluations.py",
    "apps/web-console/src/services/evaluations.ts",
    "apps/web-console/src/modules/evaluations/pages/EvaluationsPage.tsx",
    "apps/web-console/src/modules/evaluations/pages/EvaluationRunDetailPage.tsx",
    "tests/test_p11_evaluation_governance.py",
    "solve_p11_baseline.py",
    "docs/architecture/p11-evaluation-platform.md",
    "docs/architecture/p11-metric-model.md",
    "docs/testing/p11-evaluation-matrix.md",
    "docs/security/p11-promotion-boundaries.md",
    "docs/operations/p11-evaluation-runbook.md",
    "docs/acceptance/p11-acceptance-report.md",
    "infrastructure/migrations/0011_p11_evaluation_governance.up.sql",
    "infrastructure/migrations/0011_p11_evaluation_governance.down.sql",
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
        "/evaluation-suites",
        "/evaluation-suites/{suite_id}",
        "/evaluation-datasets",
        "/evaluation-datasets/{dataset_id}",
        "/evaluation-datasets/{dataset_id}/cases",
        "/evaluation-runs",
        "/evaluation-runs/{run_id}",
        "/evaluation-runs/{run_id}/cancel",
        "/evaluation-runs/{run_id}/results",
        "/evaluation-runs/{run_id}/metrics",
        "/evaluation-runs/{run_id}/failures",
        "/evaluation-comparisons",
        "/evaluation-comparisons/{comparison_id}",
        "/evaluation-runs/{run_id}/reviews",
        "/evaluation-runs/{run_id}/promotion-decisions",
    }
    schemas = openapi_snapshot.load_document()["components"]["schemas"]
    required_schemas = {
        "EvaluationSuiteCreate",
        "EvaluationSuiteResponse",
        "EvaluationDatasetCreate",
        "EvaluationDatasetDetailResponse",
        "EvaluationCaseCreate",
        "EvaluationCaseResponse",
        "EvaluationRunCreate",
        "EvaluationRunDetailResponse",
        "EvaluationComparisonResponse",
        "EvaluationReviewCreate",
        "PromotionDecisionCreate",
    }
    invariants = {
        "operation_count_is_p11": value["operation_count"] == 106,
        "all_p11_paths_exist": required_paths <= set(paths),
        "all_p11_schemas_exist": required_schemas <= set(schemas),
        "p10_case_paths_remain": "/vulnerability-cases/{case_id}/reports" in paths,
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
        "p11_migration_present": "0011_p11_evaluation_governance" in value["pairs"],
        "evaluation_tables_are_tenant_safe": value["valid"],
    }
    errors = list(value["errors"]) + sorted(name for name, valid in invariants.items() if not valid)
    return ("PASS" if not errors else "FAIL"), {**value, "invariants": invariants, "errors": errors}


def _security_static_check() -> tuple[str, dict[str, Any]]:
    service = (ROOT / "apps/control-plane/src/vulnlab/evaluation_governance.py").read_text(
        encoding="utf-8"
    )
    schemas = (ROOT / "apps/control-plane/src/vulnlab/schemas.py").read_text(encoding="utf-8")
    validation_service = (
        ROOT / "apps/control-plane/src/vulnlab/validation_execution.py"
    ).read_text(encoding="utf-8")
    tests = (ROOT / "tests/test_p11_evaluation_governance.py").read_text(encoding="utf-8")
    invariants = {
        "configuration_snapshots_are_hashed": "configuration_hash" in service
        and "snapshot_hash" in service
        and "config_hash" in service,
        "ground_truth_is_explicit": "evaluation case must define explicit ground truth" in schemas
        and "ground_truth_hash" in service,
        "llm_judge_not_sole_scoring": "restricted LLM judge cannot be the only scoring method"
        in schemas,
        "gates_block_promotion": "gate failure blocks promotion" in service,
        "creator_cannot_self_promote": "creator cannot independently approve" in service,
        "human_only_statuses_defined": "HUMAN_ONLY_STATUSES" in service
        and "APPROVED" in service
        and "PROMOTED" in service,
        "no_arbitrary_shell_added": all(
            marker not in service
            for marker in (
                "import subprocess",
                "from subprocess",
                "subprocess.",
                "shell=True",
                "os.system(",
                "os.popen(",
            )
        ),
        "p9_templates_unchanged": all(
            marker in validation_service
            for marker in (
                '"http.response"',
                '"sbom.dependency-version"',
                '"local.training-lab"',
            )
        )
        and "shell.arbitrary" not in validation_service,
        "negative_tests_cover_promotion_and_ground_truth": "p11-blocked-promote" in tests
        and "GROUND_TRUTH_MISSING" in tests,
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
        _timed("p11_repository_layout", _layout_check),
        _timed("p11_openapi_contract_guard", _contract_check),
        _timed("p11_migration_guard", _migration_check),
        _timed("p11_security_static_guard", _security_static_check),
        _command_check(
            "p11_backend_evaluation_governance_tests",
            [python, "-m", "pytest", "tests/test_p11_evaluation_governance.py", "-q"],
        ),
        _command_check(
            "p11_contract_tests",
            [python, "-m", "pytest", "tests/contract/test_openapi_contract.py", "-q"],
        ),
        _command_check(
            "p11_migration_tests",
            [python, "-m", "pytest", "tests/contract/test_postgres_migrations.py", "-q"],
        ),
        _command_check(
            "p11_web_typecheck",
            ["pnpm", "--filter", "@vulnlab/web-console", "typecheck"],
            optional_tool="pnpm",
        ),
    ]
    if full:
        checks.extend(
            [
                _command_check("p10_baseline_compatibility", [python, "solve_p10_baseline.py"]),
                _command_check("p9_baseline_compatibility", [python, "solve_p9_baseline.py"]),
                _command_check(
                    "python_compile",
                    [
                        python,
                        "-m",
                        "compileall",
                        "-q",
                        "apps/control-plane/src",
                        "solve_p11_baseline.py",
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
        "phase": "P11",
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
            "new_validation_templates": "Not applicable; P11 intentionally adds no validation templates.",
            "arbitrary_poc_execution": "Not applicable; P11 does not add arbitrary PoC upload or shell execution.",
            "new_scanning_tools": "Not applicable; P11 adds evaluation governance only.",
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
