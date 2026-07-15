#!/usr/bin/env python3
"""Deterministic P0 architecture/engineering baseline acceptance runner.

The default run is read-only and does not start containers, execute tasks, probe
assets, or contact model providers. ``--full`` additionally runs repository test,
lint, type-check, and build commands that are available on the current machine.
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
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

from tools.contracts import check_migrations, json_schema_check, openapi_snapshot  # noqa: E402


@dataclass(frozen=True)
class CheckResult:
    name: str
    status: str
    duration_ms: int
    details: dict[str, Any]


REQUIRED_PATHS = (
    "package.json",
    "pnpm-lock.yaml",
    "pnpm-workspace.yaml",
    "turbo.json",
    "pyproject.toml",
    "requirements.lock",
    "requirements-dev.lock",
    ".env.example",
    "docker-compose.yml",
    "Taskfile.yml",
    "apps/control-plane/src/vulnlab/app.py",
    "apps/web-console/package.json",
    "apps/web-console/src/main.tsx",
    "apps/api-gateway/Caddyfile",
    "packages/api-contracts/openapi/v1.yaml",
    "packages/api-contracts/events/task-event.v1.schema.json",
    "packages/api-contracts/protocol/domain-protocol.v1.schema.json",
    "packages/api-client/package.json",
    "packages/shared-types/package.json",
    "packages/ui-components/package.json",
    "docs/architecture/00-current-state-assessment.md",
    "docs/architecture/01-requirements-capability-matrix.md",
    "docs/architecture/02-system-context-and-service-boundaries.md",
    "docs/architecture/03-data-flows.md",
    "docs/architecture/04-domain-model-and-er.md",
    "docs/architecture/05-task-state-machine.md",
    "docs/architecture/06-milestones.md",
    "docs/architecture/07-risk-register.md",
    "docs/security/rbac-permission-matrix.md",
    "docs/security/policy-and-approval-flow.md",
    "docs/api/conventions.md",
    "docs/api/compatibility.md",
    "docs/deployment/local-development.md",
    "docs/deployment/docker-compose.md",
    "docs/engineering/coding-standards.md",
    "docs/engineering/git-workflow.md",
    "docs/testing/strategy.md",
    "docs/testing/p0-acceptance.md",
    ".github/workflows/ci.yml",
    "infrastructure/docker-compose/platform.yml",
    "infrastructure/monitoring/otel-collector.yaml",
    "infrastructure/monitoring/prometheus.yaml",
    "infrastructure/migrations/0001_p0_enterprise_baseline.up.sql",
    "infrastructure/migrations/0001_p0_enterprise_baseline.down.sql",
)


def _timed(name: str, function: Callable[[], tuple[str, dict[str, Any]]]) -> CheckResult:
    started = time.perf_counter()
    try:
        status, details = function()
    except Exception as exc:  # the runner must report every gate, not abort at the first one
        status = "FAIL"
        details = {"errors": [f"{type(exc).__name__}: {exc}"]}
    duration_ms = round((time.perf_counter() - started) * 1000)
    return CheckResult(name=name, status=status, duration_ms=duration_ms, details=details)


def _layout_check() -> tuple[str, dict[str, Any]]:
    missing = [path for path in REQUIRED_PATHS if not (ROOT / path).is_file()]
    return ("PASS" if not missing else "FAIL"), {
        "required_file_count": len(REQUIRED_PATHS),
        "missing": missing,
    }


def _safe_defaults_check() -> tuple[str, dict[str, Any]]:
    env_example = (ROOT / ".env.example").read_text(encoding="utf-8")
    settings = (ROOT / "apps/control-plane/src/vulnlab/config.py").read_text(encoding="utf-8")
    compose = (ROOT / "docker-compose.yml").read_text(encoding="utf-8")
    invariants = {
        "example_legacy_execution_disabled": bool(
            re.search(r"(?m)^VULNLAB_LEGACY_EXECUTION_ENABLED=false\s*$", env_example)
        ),
        "example_execution_is_dry_run": bool(
            re.search(r"(?m)^VULNLAB_EXECUTION_MODE=dry_run\s*$", env_example)
        ),
        "settings_legacy_execution_default_false": bool(
            re.search(r"legacy_execution_enabled:\s*bool\s*=\s*False\b", settings)
        ),
        "compose_legacy_execution_default_false": "${VULNLAB_LEGACY_EXECUTION_ENABLED:-false}"
        in compose,
        "compose_execution_default_dry_run": "${VULNLAB_EXECUTION_MODE:-dry_run}" in compose,
    }
    failed = sorted(name for name, valid in invariants.items() if not valid)
    return ("PASS" if not failed else "FAIL"), {"invariants": invariants, "errors": failed}


def _git_baseline_check() -> tuple[str, dict[str, Any]]:
    if not (ROOT / ".git").is_dir():
        return "FAIL", {"errors": ["Git repository is not initialized"]}
    branch = subprocess.run(
        ["git", "branch", "--show-current"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=False,
    )
    head = subprocess.run(
        ["git", "rev-parse", "--verify", "HEAD"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=False,
    )
    valid = branch.returncode == 0 and branch.stdout.strip() == "main" and head.returncode == 0
    return ("PASS" if valid else "FAIL"), {
        "branch": branch.stdout.strip(),
        "has_baseline_commit": head.returncode == 0,
        "errors": [] if valid else ["expected main branch with a baseline commit"],
    }


def _contract_check() -> tuple[str, dict[str, Any]]:
    value = openapi_snapshot.check(runtime=True)
    return ("PASS" if value["valid"] else "FAIL"), value


def _schema_check() -> tuple[str, dict[str, Any]]:
    value = json_schema_check.check()
    return ("PASS" if value["valid"] else "FAIL"), value


def _migration_check() -> tuple[str, dict[str, Any]]:
    value = check_migrations.check()
    return ("PASS" if value["valid"] else "FAIL"), value


def _run_command(name: str, command: list[str], *, optional_tool: str | None = None) -> CheckResult:
    def execute() -> tuple[str, dict[str, Any]]:
        resolved_tool = shutil.which(optional_tool) if optional_tool is not None else None
        if optional_tool is not None and resolved_tool is None:
            return "SKIP", {"reason": f"{optional_tool} is not installed", "command": command}
        executable_command = list(command)
        if resolved_tool is not None:
            executable_command[0] = resolved_tool
            if Path(resolved_tool).suffix.lower() in {".bat", ".cmd"}:
                executable_command = [
                    os.environ.get("COMSPEC", "cmd.exe"),
                    "/d",
                    "/s",
                    "/c",
                    resolved_tool,
                    *command[1:],
                ]
        completed = subprocess.run(
            executable_command,
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
            "resolved_command": executable_command,
            "returncode": completed.returncode,
            "output": output[-8000:],
        }

    return _timed(name, execute)


def _compose_check() -> CheckResult:
    return _run_command(
        "docker_compose_static_config",
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
    )


def run(*, full: bool) -> dict[str, Any]:
    started = time.perf_counter()
    results = [
        _timed("repository_layout", _layout_check),
        _timed("git_baseline", _git_baseline_check),
        _timed("safe_execution_defaults", _safe_defaults_check),
        _timed("openapi_contract_and_runtime_projection", _contract_check),
        _timed("json_schema_contracts", _schema_check),
        _timed("postgres_migration_static_invariants", _migration_check),
        _compose_check(),
    ]
    if full:
        results.extend(
            [
                _run_command(
                    "python_test_suite",
                    [sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider"],
                ),
                _run_command(
                    "python_lint",
                    [
                        sys.executable,
                        "-m",
                        "ruff",
                        "check",
                        "apps/control-plane/src",
                        "tests",
                        "tools",
                        "solve_module2.py",
                        "solve_p0_baseline.py",
                    ],
                ),
                _run_command(
                    "python_typecheck",
                    [sys.executable, "-m", "mypy", "apps/control-plane/src/vulnlab"],
                ),
                _run_command("frontend_lint", ["pnpm", "run", "lint"], optional_tool="pnpm"),
                _run_command(
                    "frontend_typecheck", ["pnpm", "run", "typecheck"], optional_tool="pnpm"
                ),
                _run_command("frontend_test", ["pnpm", "run", "test"], optional_tool="pnpm"),
                _run_command("frontend_build", ["pnpm", "run", "build"], optional_tool="pnpm"),
            ]
        )
    counts = {
        status: sum(result.status == status for result in results)
        for status in ("PASS", "FAIL", "SKIP")
    }
    return {
        "phase": "P0",
        "scope": "architecture-and-engineering-baseline",
        "valid": counts["FAIL"] == 0,
        "mode": "full" if full else "baseline",
        "duration_ms": round((time.perf_counter() - started) * 1000),
        "summary": {"passed": counts["PASS"], "failed": counts["FAIL"], "skipped": counts["SKIP"]},
        "checks": [asdict(result) for result in results],
        "safety": {
            "mutates_runtime": False,
            "starts_containers": False,
            "executes_vulnerability_validation": False,
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate the Module 2 P0 enterprise baseline")
    parser.add_argument(
        "--full",
        action="store_true",
        help="also run the complete Python and pnpm lint/typecheck/test/build pipelines",
    )
    parser.add_argument(
        "--output", type=Path, help="optionally write the UTF-8 JSON result to this path"
    )
    args = parser.parse_args()

    result = run(full=args.full)
    rendered = json.dumps(result, ensure_ascii=False, indent=2) + "\n"
    if args.output is not None:
        output = args.output if args.output.is_absolute() else ROOT / args.output
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(rendered, encoding="utf-8", newline="\n")
    print(rendered, end="")
    return 0 if result["valid"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
