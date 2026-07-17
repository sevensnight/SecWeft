#!/usr/bin/env python3
"""Deterministic acceptance runner for Module 2 P9 controlled validation execution plane."""

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


REQUIRED_FILES = (
    "apps/control-plane/src/vulnlab/validation_execution.py",
    "apps/control-plane/src/vulnlab/api/routers/validation_executions.py",
    "apps/validation-worker/main.py",
    "apps/validation-worker/README.md",
    "tests/test_p9_validation_executions.py",
    "docs/architecture/p9-execution-plane.md",
    "docs/security/sandbox-threat-model.md",
    "docs/testing/p9-validation-matrix.md",
    "infrastructure/migrations/0007_p9_validation_execution_plane.up.sql",
    "infrastructure/migrations/0007_p9_validation_execution_plane.down.sql",
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
        "/validation-plans/{plan_id}/executions",
        "/validation-executions",
        "/validation-executions/{execution_id}",
        "/validation-executions/{execution_id}/cancel",
        "/validation-executions/{execution_id}/retry",
        "/validation-executions/{execution_id}/events",
        "/validation-executions/{execution_id}/events/stream",
        "/validation-executions/{execution_id}/evidence",
        "/validation-executions/{execution_id}/reviews",
        "/validation-templates",
        "/validation-templates/{template_id}",
    }
    invariants = {
        "operation_count_is_p9": value["operation_count"] == 73,
        "all_p9_paths_exist": required_paths <= set(paths),
        "dangerous_paths_still_absent": all(
            marker not in path.lower()
            for path in paths
            for marker in ("/sandbox", "/assets/probe", "/exploit", "/validation-runs")
        ),
    }
    errors = list(value["errors"]) + sorted(name for name, valid in invariants.items() if not valid)
    return ("PASS" if not errors else "FAIL"), {**value, "invariants": invariants, "errors": errors}


def _security_static_check() -> tuple[str, dict[str, Any]]:
    service = (ROOT / "apps/control-plane/src/vulnlab/validation_execution.py").read_text(
        encoding="utf-8"
    )
    router = (
        ROOT / "apps/control-plane/src/vulnlab/api/routers/validation_executions.py"
    ).read_text(encoding="utf-8")
    tests = (ROOT / "tests/test_p9_validation_executions.py").read_text(encoding="utf-8")
    sandbox_doc = (ROOT / "docs/security/sandbox-threat-model.md").read_text(encoding="utf-8")
    invariants = {
        "registered_fixed_templates_only": all(
            marker in service
            for marker in (
                '"http.response"',
                '"sbom.dependency-version"',
                '"local.training-lab"',
            )
        )
        and "shell.arbitrary" not in service,
        "no_subprocess_shell": "shell=True" not in service and "subprocess" not in service,
        "policy_rechecked_by_worker": "self._authorize_create(principal" in service
        and "validation.execute" in service,
        "approval_rechecked_by_worker": "APPROVAL_REVOKED" in service
        and 'plan_row["status"] != "approved"' in service,
        "scope_violation_status_exists": "SCOPE_INVALID" in service,
        "idempotency_key_required": "Idempotency-Key is required" in service,
        "worker_is_durable_queue_backed": "validation_queue_messages" in service
        and "run_worker_once" in service,
        "api_requires_execute_permission": 'require("validation:execute")' in router,
        "arbitrary_shell_negative_test": "argv" in tests and "shell.arbitrary" in tests,
        "sandbox_threat_model_lists_required_flags": "--cap-drop ALL" in sandbox_doc
        and "--security-opt no-new-privileges:true" in sandbox_doc,
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
        _timed("p9_repository_layout", _layout_check),
        _timed("p9_openapi_contract_guard", _contract_check),
        _timed("p9_security_static_guard", _security_static_check),
        _command_check(
            "p9_backend_tests",
            [python, "-m", "pytest", "tests/test_p9_validation_executions.py", "-q"],
        ),
        _command_check(
            "p9_contract_tests",
            [python, "-m", "pytest", "tests/contract/test_openapi_contract.py", "-q"],
        ),
        _command_check(
            "p9_web_typecheck",
            ["pnpm", "--filter", "@vulnlab/web-console", "typecheck"],
            optional_tool="pnpm",
        ),
    ]
    if full:
        checks.extend(
            [
                _command_check(
                    "python_compile",
                    [
                        python,
                        "-m",
                        "compileall",
                        "-q",
                        "apps/control-plane/src",
                        "apps/validation-worker",
                        "solve_p9_baseline.py",
                    ],
                ),
                _command_check("python_format", [python, "-m", "ruff", "format", "--check", "."]),
                _command_check("python_lint", [python, "-m", "ruff", "check", "."]),
                _command_check("python_tests", [python, "-m", "pytest", "-q"]),
                _command_check("workspace_typecheck", ["pnpm", "typecheck"], optional_tool="pnpm"),
                _command_check("workspace_test", ["pnpm", "test"], optional_tool="pnpm"),
            ]
        )
    failed = [check for check in checks if check.status == "FAIL"]
    return {
        "phase": "P9",
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
            "nats_jetstream_runtime": "Protocol documented; local adapter uses durable SQLite queue.",
            "docker_runtime_sandbox": "Sandbox threat model and metadata implemented; daemon/image runtime not exercised by default.",
            "minio_runtime_upload": "Evidence metadata/hash and local-compatible artifact are persisted; true MinIO upload not exercised by default.",
            "internet_egress_runtime_block": "Requires Docker/network policy runtime test.",
            "resource_limit_runtime_kill": "Requires Docker runtime test.",
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--full", action="store_true", help="also run broader local quality gates")
    args = parser.parse_args()
    result = run(args.full)
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if result["valid"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
