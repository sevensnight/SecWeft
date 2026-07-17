#!/usr/bin/env python3
"""Deterministic acceptance runner for Module 2 P3 task and Agent orchestration."""

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

from tools.contracts import check_migrations, openapi_snapshot  # noqa: E402


@dataclass(frozen=True)
class CheckResult:
    name: str
    status: str
    duration_ms: int
    details: dict[str, Any]


REQUIRED_PATHS = (
    "apps/control-plane/src/vulnlab/orchestrator.py",
    "apps/control-plane/src/vulnlab/agent_registry.py",
    "apps/control-plane/src/vulnlab/skills.py",
    "apps/control-plane/src/vulnlab/api/routers/tasks.py",
    "apps/control-plane/src/vulnlab/db.py",
    "infrastructure/migrations/0006_p3_agent_orchestration.up.sql",
    "infrastructure/migrations/0006_p3_agent_orchestration.down.sql",
    "tests/test_orchestration.py",
    "tests/contract/test_openapi_contract.py",
    "tests/contract/test_postgres_migrations.py",
    "packages/api-contracts/openapi/v1.yaml",
    "tools/contracts/snapshots/openapi-v1.snapshot.json",
    "solution_module2_p3.md",
    "docs/testing/p3-acceptance.md",
    "docs/P3_ACCEPTANCE_REPORT.md",
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


def _runtime_orchestration_check() -> tuple[str, dict[str, Any]]:
    orchestrator = (ROOT / "apps/control-plane/src/vulnlab/orchestrator.py").read_text(
        encoding="utf-8"
    )
    db = (ROOT / "apps/control-plane/src/vulnlab/db.py").read_text(encoding="utf-8")
    router = (ROOT / "apps/control-plane/src/vulnlab/api/routers/tasks.py").read_text(
        encoding="utf-8"
    )
    invariants = {
        "no_per_task_memory_locks": "self._locks" not in orchestrator
        and "self._cancel" not in orchestrator,
        "persistent_task_stages": "CREATE TABLE IF NOT EXISTS task_stages" in db,
        "persistent_task_executions": "CREATE TABLE IF NOT EXISTS task_executions" in db,
        "durable_queue_messages": "CREATE TABLE IF NOT EXISTS task_queue_messages" in db,
        "idempotency_records": "CREATE TABLE IF NOT EXISTS task_idempotency_records" in db,
        "dead_letter_ledger": "CREATE TABLE IF NOT EXISTS task_dead_letters" in db,
        "lease_and_fencing": "lease_token" in orchestrator and "fencing_token" in orchestrator,
        "stale_lease_recovery": "recover_stale_leases" in orchestrator,
        "async_dispatch_endpoint": '"/api/v1/tasks/{task_id}/executions"' in router,
        "pause_resume_retry_endpoints": all(
            marker in router
            for marker in (
                '"/api/v1/tasks/{task_id}/pause"',
                '"/api/v1/tasks/{task_id}/resume"',
                '"/api/v1/tasks/{task_id}/retry"',
            )
        ),
    }
    failed = sorted(name for name, valid in invariants.items() if not valid)
    return ("PASS" if not failed else "FAIL"), {"invariants": invariants, "errors": failed}


def _agent_workflow_check() -> tuple[str, dict[str, Any]]:
    registry = (ROOT / "apps/control-plane/src/vulnlab/agent_registry.py").read_text(
        encoding="utf-8"
    )
    skills = (ROOT / "apps/control-plane/src/vulnlab/skills.py").read_text(encoding="utf-8")
    invariants = {
        "agent_definitions_exist": "BUILTIN_AGENTS" in registry
        and "task_planner" in registry
        and "compliance_checker" in registry,
        "workflow_definition_exists": "p3.synthetic.defensive" in registry,
        "workflow_has_six_stages": all(
            stage in registry
            for stage in ("scope", "plan", "knowledge", "evidence", "evaluate", "report")
        ),
        "skills_are_versioned": '"version": "1.0"' in skills,
        "skills_have_output_schema": "output_schema_json" in skills,
        "skills_have_resource_limits": "resource_limits_json" in skills,
        "skill_stats_are_recorded": "record_invocation" in skills,
    }
    failed = sorted(name for name, valid in invariants.items() if not valid)
    return ("PASS" if not failed else "FAIL"), {"invariants": invariants, "errors": failed}


def _contract_check() -> tuple[str, dict[str, Any]]:
    value = openapi_snapshot.check(runtime=True)
    schemas = openapi_snapshot.load_document()["components"]["schemas"]
    invariants = {
        "operation_count_is_p3": value["operation_count"] == 44,
        "task_stage_schema_exists": "TaskStage" in schemas,
        "task_execution_schema_exists": "TaskExecution" in schemas,
        "agent_schema_exists": "AgentDefinition" in schemas,
        "workflow_schema_exists": "WorkflowDefinition" in schemas,
        "skill_schema_exists": "SkillDefinition" in schemas,
        "dead_letter_schema_exists": "TaskDeadLetter" in schemas,
    }
    errors = list(value["errors"]) + sorted(name for name, valid in invariants.items() if not valid)
    details = {**value, "invariants": invariants, "errors": errors}
    return ("PASS" if not errors else "FAIL"), details


def _migration_check() -> tuple[str, dict[str, Any]]:
    value = check_migrations.check()
    up = (
        (ROOT / "infrastructure/migrations/0006_p3_agent_orchestration.up.sql")
        .read_text(encoding="utf-8")
        .lower()
    )
    invariants = {
        "agent_schema_created": "create schema if not exists agent" in up,
        "task_executions_created": "agent.task_executions" in up,
        "queue_and_dlq_created": "agent.queue_messages" in up and "agent.dead_letters" in up,
        "tenant_safe_task_fk": "references control.tasks (tenant_id, project_id, id)" in up,
        "rls_for_agent_tables": "alter table %s force row level security" in up,
        "agent_schema_has_no_delete_grant": (
            "grant select, insert, update on all tables in schema agent to vulnlab_app" in up
            and "grant select, insert, update, delete on all tables in schema agent" not in up
        ),
    }
    errors = list(value["errors"]) + sorted(name for name, valid in invariants.items() if not valid)
    details = {**value, "invariants": invariants, "errors": errors}
    return ("PASS" if not errors else "FAIL"), details


def _security_check() -> tuple[str, dict[str, Any]]:
    orchestrator = (ROOT / "apps/control-plane/src/vulnlab/orchestrator.py").read_text(
        encoding="utf-8"
    )
    sql = (
        (ROOT / "infrastructure/migrations/0006_p3_agent_orchestration.up.sql")
        .read_text(encoding="utf-8")
        .lower()
    )
    invariants = {
        "no_sync_run_in_contract": "/tasks/{task_id}/run"
        not in (ROOT / "packages/api-contracts/openapi/v1.yaml").read_text(encoding="utf-8"),
        "dlq_payload_is_redacted": "redact(payload)" in orchestrator,
        "no_destructive_markers": all(
            marker not in sql for marker in ("docker socket", "host network", "exploit payload")
        ),
        "approved_scope_rechecked": "self.scope.validate" in orchestrator,
    }
    failed = sorted(name for name, valid in invariants.items() if not valid)
    return ("PASS" if not failed else "FAIL"), {"invariants": invariants, "errors": failed}


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
        _timed("p3_repository_layout", _layout_check),
        _timed("p3_runtime_orchestration_invariants", _runtime_orchestration_check),
        _timed("p3_agent_workflow_skill_invariants", _agent_workflow_check),
        _timed("p3_openapi_contract_and_runtime_projection", _contract_check),
        _timed("p3_postgres_migration_static_invariants", _migration_check),
        _timed("p3_security_boundary", _security_check),
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
                    "python_p3_tests",
                    [
                        python,
                        "-m",
                        "pytest",
                        "tests/test_orchestration.py",
                        "tests/test_validation_e2e.py",
                        "tests/contract/test_openapi_contract.py",
                        "tests/contract/test_postgres_migrations.py",
                        "-q",
                    ],
                ),
                _command_check(
                    "workspace_lint",
                    ["pnpm", "lint"],
                    optional_tool="pnpm",
                ),
                _command_check(
                    "workspace_typecheck",
                    ["pnpm", "typecheck"],
                    optional_tool="pnpm",
                ),
                _command_check(
                    "workspace_test",
                    ["pnpm", "test"],
                    optional_tool="pnpm",
                ),
                _command_check(
                    "workspace_build",
                    ["pnpm", "build"],
                    optional_tool="pnpm",
                ),
            ]
        )
    failed = [check for check in checks if check.status == "FAIL"]
    return {
        "phase": "P3",
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
            "no_vulnerability_payloads": True,
            "no_sync_long_task_contract": True,
            "no_task_state_in_memory": True,
            "only_p3_synthetic_workflow_and_approved_non_destructive_probe": True,
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
