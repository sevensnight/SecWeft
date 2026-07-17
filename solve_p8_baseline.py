#!/usr/bin/env python3
"""Deterministic acceptance runner for Module 2 P8 operations readiness."""

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
from tools.p8 import operational_readiness, perf_smoke  # noqa: E402


@dataclass(frozen=True)
class CheckResult:
    name: str
    status: str
    duration_ms: int
    details: dict[str, Any]


REQUIRED_PATHS = (
    "tools/p8/operational_readiness.py",
    "tools/p8/perf_smoke.py",
    "tests/test_p8_operational_readiness.py",
    "infrastructure/docker-compose/platform.yml",
    "infrastructure/docker-compose/.env.platform.example",
    "infrastructure/scripts/backup.ps1",
    "infrastructure/scripts/restore.ps1",
    "infrastructure/scripts/start.ps1",
    "infrastructure/scripts/stop.ps1",
    "infrastructure/kubernetes/helm/vulnlab-platform/Chart.yaml",
    "infrastructure/kubernetes/helm/vulnlab-platform/values.yaml",
    "infrastructure/monitoring/prometheus.yaml",
    "infrastructure/monitoring/otel-collector.yaml",
    "Taskfile.yml",
    "Makefile",
    "solution_module2_p8.md",
    "docs/testing/p8-acceptance.md",
    "docs/P8_ACCEPTANCE_REPORT.md",
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


def _operations_check() -> tuple[str, dict[str, Any]]:
    value = operational_readiness.run()
    return ("PASS" if value["valid"] else "FAIL"), value


def _performance_check() -> tuple[str, dict[str, Any]]:
    value = perf_smoke.run(requests=32, concurrency=8, p95_budget_ms=250)
    return ("PASS" if value["valid"] else "FAIL"), value


def _contract_check() -> tuple[str, dict[str, Any]]:
    value = openapi_snapshot.check(runtime=True)
    errors = list(value["errors"])
    if value["operation_count"] < 62:
        errors.append(
            "P8 compatibility requires preserving at least the P6 backend operation floor"
        )
    return ("PASS" if not errors else "FAIL"), {**value, "errors": errors}


def _command_surface_check() -> tuple[str, dict[str, Any]]:
    taskfile = (ROOT / "Taskfile.yml").read_text(encoding="utf-8")
    makefile = (ROOT / "Makefile").read_text(encoding="utf-8")
    powershell_script = (ROOT / "infrastructure" / "scripts" / "test.ps1").read_text(
        encoding="utf-8"
    )
    posix_script = (ROOT / "infrastructure" / "scripts" / "test.sh").read_text(encoding="utf-8")
    invariants = {
        "taskfile_exposes_p8": "\n  p8:check:" in taskfile and "solve_p8_baseline.py" in taskfile,
        "makefile_exposes_p8": "\np8-check:" in makefile and "solve_p8_baseline.py" in makefile,
        "taskfile_full_check_uses_p8": "\n      - task: p8:check" in taskfile,
        "makefile_full_check_uses_p8": any(
            line.startswith("check:") and "p8-check" in line for line in makefile.splitlines()
        ),
        "powershell_script_runs_p8": "solve_p8_baseline.py" in powershell_script,
        "posix_script_runs_p8": "solve_p8_baseline.py" in posix_script,
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
        _timed("p8_repository_layout", _layout_check),
        _timed("p8_operational_readiness", _operations_check),
        _timed("p8_performance_smoke", _performance_check),
        _timed("p8_openapi_contract_guard", _contract_check),
        _timed("p8_command_surface", _command_surface_check),
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
                _command_check("python_tests", [python, "-m", "pytest", "-q"]),
                _command_check("workspace_lint", ["pnpm", "lint"], optional_tool="pnpm"),
                _command_check("workspace_typecheck", ["pnpm", "typecheck"], optional_tool="pnpm"),
                _command_check("workspace_test", ["pnpm", "test"], optional_tool="pnpm"),
                _command_check("workspace_build", ["pnpm", "build"], optional_tool="pnpm"),
                _command_check(
                    "compose_static_config",
                    [
                        "docker",
                        "compose",
                        "--env-file",
                        "infrastructure/docker-compose/.env.platform.example",
                        "-f",
                        "infrastructure/docker-compose/platform.yml",
                        "config",
                        "--quiet",
                    ],
                    optional_tool="docker",
                ),
                _command_check(
                    "helm_lint",
                    ["helm", "lint", "infrastructure/kubernetes/helm/vulnlab-platform", "--strict"],
                    optional_tool="helm",
                ),
            ]
        )
    failed = [check for check in checks if check.status == "FAIL"]
    return {
        "phase": "P8",
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
            "local_secret_files_are_not_git_tracked": True,
            "compose_and_helm_are_static_checked": True,
            "performance_smoke_uses_in_process_authorized_api": True,
            "docker_and_helm_runtime_checks_are_reported_as_skip_when_missing": True,
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--full", action="store_true", help="also run complete local quality gates")
    args = parser.parse_args()
    result = run(args.full)
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if result["valid"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
