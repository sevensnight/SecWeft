#!/usr/bin/env python3
"""Deterministic acceptance runner for P12 HA, scaling, and DR controls."""

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


@dataclass(frozen=True, slots=True)
class CheckResult:
    name: str
    status: str
    duration_ms: int
    details: dict[str, Any]


REQUIRED_FILES = (
    "apps/control-plane/src/vulnlab/operational_resilience.py",
    "apps/control-plane/src/vulnlab/api/routers/system.py",
    "apps/web-console/src/modules/system/pages/SystemPage.tsx",
    "tests/test_p12_operational_resilience.py",
    "solve_p12_baseline.py",
    "solve_p12_scale.py",
    "solve_p12_disaster_recovery.py",
    "solve_p12_chaos.py",
    "docs/architecture/p12-ha-and-scaling.md",
    "docs/architecture/p12-capacity-model.md",
    "docs/testing/p12-performance-matrix.md",
    "docs/testing/p12-chaos-matrix.md",
    "docs/operations/p12-backup-restore-runbook.md",
    "docs/operations/p12-disaster-recovery-runbook.md",
    "docs/security/p12-availability-boundaries.md",
    "docs/acceptance/p12-acceptance-report.md",
    "infrastructure/migrations/0012_p12_operational_resilience.up.sql",
    "infrastructure/migrations/0012_p12_operational_resilience.down.sql",
    "infrastructure/kubernetes/helm/vulnlab-platform/templates/deployment-validation-worker.yaml",
    "infrastructure/kubernetes/helm/vulnlab-platform/templates/cronjob-backup.yaml",
    "infrastructure/kubernetes/helm/vulnlab-platform/templates/job-restore.yaml",
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
    document = openapi_snapshot.load_document()
    paths = document["paths"]
    schemas = document["components"]["schemas"]
    create_execution_responses = paths["/validation-plans/{plan_id}/executions"]["post"][
        "responses"
    ]
    invariants = {
        "operation_count_is_p12": value["operation_count"] == 108,
        "system_resilience_path_exists": "/system/resilience" in paths,
        "evidence_consistency_path_exists": "/system/resilience/evidence-consistency/check"
        in paths,
        "p12_schemas_exist": {
            "SystemResilienceResponse",
            "EvidenceConsistencyCheckRequest",
            "EvidenceConsistencyReportResponse",
        }
        <= set(schemas),
        "execution_create_declares_backpressure": {"429", "503"} <= set(create_execution_responses),
        "p11_evaluation_paths_remain": "/evaluation-runs/{run_id}/promotion-decisions" in paths,
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
        "p12_migration_present": "0012_p12_operational_resilience" in value["pairs"],
        "all_migrations_remain_valid": value["valid"],
    }
    errors = list(value["errors"]) + sorted(name for name, valid in invariants.items() if not valid)
    return ("PASS" if not errors else "FAIL"), {**value, "invariants": invariants, "errors": errors}


def _security_static_check() -> tuple[str, dict[str, Any]]:
    service = (ROOT / "apps/control-plane/src/vulnlab/operational_resilience.py").read_text(
        encoding="utf-8"
    )
    validation = (ROOT / "apps/control-plane/src/vulnlab/validation_execution.py").read_text(
        encoding="utf-8"
    )
    config = (ROOT / "apps/control-plane/src/vulnlab/config.py").read_text(encoding="utf-8")
    evidence_store = (
        ROOT / "apps/control-plane/src/vulnlab/validation_evidence_store.py"
    ).read_text(encoding="utf-8")
    chart_text = "\n".join(
        path.read_text(encoding="utf-8")
        for path in (ROOT / "infrastructure/kubernetes/helm/vulnlab-platform/templates").glob(
            "*.yaml"
        )
    )
    invariants = {
        "no_arbitrary_shell_in_operational_service": all(
            marker not in service
            for marker in ("import subprocess", "from subprocess", "shell=True", "os.system(")
        ),
        "priority_does_not_bypass_security": "_authorize_create" in validation
        and "capacity_decision" in validation
        and validation.index("_authorize_create") < validation.index("capacity_decision"),
        "production_static_fallback_forbidden": "Production requires VULNLAB_REPOSITORY_BACKEND=postgres"
        in config
        and "Production requires VULNLAB_VALIDATION_QUEUE_BACKEND=nats" in config
        and "Production requires VULNLAB_VALIDATION_SANDBOX_BACKEND=docker" in config
        and "Production requires VULNLAB_EVIDENCE_STORE_BACKEND=minio" in config,
        "evidence_checker_does_not_delete_by_default": "delete_object" not in evidence_store
        and "remove_object" not in evidence_store
        and "unlink()" not in service,
        "p9_templates_unchanged": all(
            marker in validation
            for marker in (
                '"http.response"',
                '"sbom.dependency-version"',
                '"local.training-lab"',
            )
        )
        and "shell.arbitrary" not in validation,
        "helm_does_not_mount_docker_socket": "/var/run/docker.sock" not in chart_text
        and "hostNetwork: true" not in chart_text,
        "restore_job_disabled_by_default": "restore:\n  enabled: false"
        in (ROOT / "infrastructure/kubernetes/helm/vulnlab-platform/values.yaml").read_text(
            encoding="utf-8"
        ),
    }
    errors = sorted(name for name, valid in invariants.items() if not valid)
    return ("PASS" if not errors else "FAIL"), {"invariants": invariants, "errors": errors}


def _helm_static_check() -> tuple[str, dict[str, Any]]:
    values = (ROOT / "infrastructure/kubernetes/helm/vulnlab-platform/values.yaml").read_text(
        encoding="utf-8"
    )
    helm = shutil.which("helm")
    if helm is None:
        return "FAIL", {"errors": ["helm is not installed"]}
    command = [
        helm,
        "template",
        "p12",
        "infrastructure/kubernetes/helm/vulnlab-platform",
        "--namespace",
        "vulnlab",
        "--set",
        "global.imagePullPolicy=Never",
    ]
    completed = subprocess.run(
        command,
        cwd=ROOT,
        text=True,
        encoding="utf-8",
        errors="replace",
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
        timeout=120,
    )
    rendered_text = completed.stdout
    invariants = {
        "control_plane_three_replicas_or_hpa": "replicaCount: 3" in values
        and "minReplicas: 3" in values,
        "worker_deployment_rendered": "kind: Deployment" in rendered_text
        and "validation-worker" in rendered_text,
        "control_plane_hpa_rendered": "kind: HorizontalPodAutoscaler" in rendered_text
        and "control-plane" in rendered_text,
        "pdb_rendered": "kind: PodDisruptionBudget" in rendered_text,
        "backup_cronjob_rendered": "kind: CronJob" in rendered_text
        and "solve_p12_disaster_recovery.py" in rendered_text,
        "readiness_liveness_split": "path: /ready" in rendered_text
        and "path: /live" in rendered_text,
        "rolling_update_enabled": "type: RollingUpdate" in rendered_text,
        "topology_spread_enabled": "topologySpreadConstraints" in rendered_text,
    }
    errors = sorted(name for name, valid in invariants.items() if not valid)
    if completed.returncode != 0:
        errors.append("helm_template_failed")
    return ("PASS" if completed.returncode == 0 and not errors else "FAIL"), {
        "command": command,
        "returncode": completed.returncode,
        "invariants": invariants,
        "errors": errors,
        "output_tail": rendered_text[-4000:],
    }


def _run_command(command: list[str], *, timeout_seconds: float = 600) -> tuple[str, dict[str, Any]]:
    resolved = shutil.which(command[0])
    if resolved is None:
        return "FAIL", {"command": command, "errors": [f"{command[0]} is not installed"]}
    executable = [resolved, *command[1:]]
    completed = subprocess.run(
        executable,
        cwd=ROOT,
        text=True,
        encoding="utf-8",
        errors="replace",
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
        timeout=timeout_seconds,
    )
    return ("PASS" if completed.returncode == 0 else "FAIL"), {
        "command": executable,
        "returncode": completed.returncode,
        "output": completed.stdout.strip()[-12000:],
    }


def _command_check(name: str, command: list[str], *, timeout_seconds: float = 600) -> CheckResult:
    return _timed(name, lambda: _run_command(command, timeout_seconds=timeout_seconds))


def run(full: bool) -> dict[str, Any]:
    python = sys.executable
    checks = [
        _timed("p12_repository_layout", _layout_check),
        _timed("p12_openapi_contract_guard", _contract_check),
        _timed("p12_migration_guard", _migration_check),
        _timed("p12_security_static_guard", _security_static_check),
        _timed("p12_helm_static_guard", _helm_static_check),
        _command_check(
            "p12_operational_resilience_tests",
            [python, "-m", "pytest", "tests/test_p12_operational_resilience.py", "-q"],
        ),
        _command_check(
            "p12_contract_tests",
            [python, "-m", "pytest", "tests/contract/test_openapi_contract.py", "-q"],
        ),
        _command_check(
            "p12_migration_tests",
            [python, "-m", "pytest", "tests/contract/test_postgres_migrations.py", "-q"],
        ),
        _command_check(
            "p12_web_typecheck",
            ["pnpm", "--filter", "@vulnlab/web-console", "typecheck"],
        ),
    ]
    if full:
        checks.extend(
            [
                _command_check("p11_baseline_compatibility", [python, "solve_p11_baseline.py"]),
                _command_check(
                    "python_compile",
                    [
                        python,
                        "-m",
                        "compileall",
                        "-q",
                        "apps/control-plane/src",
                        "solve_p12_baseline.py",
                        "solve_p12_scale.py",
                        "solve_p12_disaster_recovery.py",
                        "solve_p12_chaos.py",
                    ],
                ),
                _command_check("python_format", [python, "-m", "ruff", "format", "--check", "."]),
                _command_check("python_lint", [python, "-m", "ruff", "check", "."]),
                _command_check(
                    "python_typecheck", [python, "-m", "mypy", "apps/control-plane/src"]
                ),
                _command_check("python_tests", [python, "-m", "pytest", "-q"], timeout_seconds=900),
                _command_check("workspace_typecheck", ["pnpm", "typecheck"], timeout_seconds=600),
                _command_check("workspace_test", ["pnpm", "test"], timeout_seconds=600),
                _command_check("workspace_build", ["pnpm", "build"], timeout_seconds=900),
            ]
        )
    summary = {
        "passed": sum(1 for check in checks if check.status == "PASS"),
        "failed": sum(1 for check in checks if check.status == "FAIL"),
        "skipped": sum(1 for check in checks if check.status == "SKIP"),
    }
    return {
        "phase": "P12",
        "version": "2.12.0-p12",
        "valid": summary["failed"] == 0 and summary["skipped"] == 0,
        "summary": summary,
        "checks": [asdict(check) for check in checks],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--full", action="store_true", help="run full P0-P12 compatibility checks")
    args = parser.parse_args()
    result = run(full=args.full)
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if result["valid"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
