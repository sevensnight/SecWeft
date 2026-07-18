#!/usr/bin/env python3
"""Deterministic acceptance runner for P13 release governance and supply-chain security."""

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
    "apps/control-plane/src/vulnlab/release_governance.py",
    "apps/control-plane/src/vulnlab/api/routers/releases.py",
    "apps/web-console/src/modules/releases/pages/ReleasesPage.tsx",
    "apps/web-console/src/modules/releases/pages/ReleaseCandidateDetailPage.tsx",
    "apps/web-console/src/services/releases.ts",
    "tests/test_p13_release_governance.py",
    "solve_p13_baseline.py",
    "docs/architecture/p13-release-governance.md",
    "docs/architecture/p13-supply-chain-security.md",
    "docs/testing/p13-release-matrix.md",
    "docs/security/p13-signing-and-promotion-boundaries.md",
    "docs/operations/p13-release-runbook.md",
    "docs/operations/p13-rollback-runbook.md",
    "docs/acceptance/p13-acceptance-report.md",
    "infrastructure/migrations/0013_p13_release_governance.up.sql",
    "infrastructure/migrations/0013_p13_release_governance.down.sql",
)

P13_PATHS = {
    "/release-artifacts",
    "/release-artifacts/{artifact_id}",
    "/release-candidates",
    "/release-candidates/{candidate_id}",
    "/release-candidates/{candidate_id}/evaluate",
    "/release-candidates/{candidate_id}/gates",
    "/release-candidates/{candidate_id}/approvals",
    "/release-candidates/{candidate_id}/exceptions",
    "/release-candidates/{candidate_id}/promotions",
    "/release-candidates/{candidate_id}/compliance-package",
    "/deployments/{deployment_id}",
    "/deployments/{deployment_id}/rollback",
    "/deployments/{deployment_id}/drift",
}

P13_SCHEMAS = {
    "ReleaseArtifactCreate",
    "ReleaseArtifactResponse",
    "ReleaseArtifactDetailResponse",
    "ReleaseCandidateCreate",
    "ReleaseCandidateResponse",
    "ReleaseCandidateDetailResponse",
    "ReleaseGateEvaluationRequest",
    "ReleaseGateResultResponse",
    "ReleaseApprovalCreate",
    "ReleaseApprovalResponse",
    "ReleaseExceptionCreate",
    "ReleaseExceptionResponse",
    "EnvironmentPromotionCreate",
    "EnvironmentPromotionResultResponse",
    "DeploymentRecordResponse",
    "RollbackCreate",
    "RollbackRecordResponse",
    "DriftDetectionResultResponse",
    "CompliancePackageResponse",
}

POLICY_ACTIONS = {
    "release.artifact.register",
    "release.candidate.create",
    "release.gate.evaluate",
    "release.exception.request",
    "release.exception.approve",
    "release.approve",
    "release.promote.development",
    "release.promote.integration",
    "release.promote.staging",
    "release.promote.production",
    "release.rollback",
    "release.drift.review",
    "release.compliance.generate",
}


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
    invariants = {
        "operation_count_is_p13": value["operation_count"] == 123,
        "p13_paths_exist": set(paths) >= P13_PATHS,
        "p13_schemas_exist": set(schemas) >= P13_SCHEMAS,
        "release_posts_are_idempotent": all(
            "#/components/parameters/IdempotencyKey"
            in {
                item.get("$ref")
                for item in paths[path][method].get("parameters", [])
                if isinstance(item, dict)
            }
            for path, method in (
                ("/release-artifacts", "post"),
                ("/release-candidates", "post"),
                ("/release-candidates/{candidate_id}/evaluate", "post"),
                ("/release-candidates/{candidate_id}/approvals", "post"),
                ("/release-candidates/{candidate_id}/exceptions", "post"),
                ("/release-candidates/{candidate_id}/promotions", "post"),
                ("/release-candidates/{candidate_id}/compliance-package", "post"),
                ("/deployments/{deployment_id}/rollback", "post"),
            )
        ),
        "dangerous_paths_still_absent": all(
            marker not in path.lower()
            for path in paths
            for marker in ("/exploit", "/poc", "/shell", "/validation-runs")
        ),
    }
    errors = list(value["errors"]) + sorted(name for name, valid in invariants.items() if not valid)
    return ("PASS" if not errors else "FAIL"), {**value, "invariants": invariants, "errors": errors}


def _migration_check() -> tuple[str, dict[str, Any]]:
    value = check_migrations.check()
    migration_text = (
        ROOT / "infrastructure/migrations/0013_p13_release_governance.up.sql"
    ).read_text(encoding="utf-8")
    invariants = {
        "p13_migration_present": "0013_p13_release_governance" in value["pairs"],
        "all_migrations_remain_valid": value["valid"],
        "release_schema_uses_rls": "ENABLE ROW LEVEL SECURITY" in migration_text
        and "FORCE ROW LEVEL SECURITY" in migration_text,
        "application_role_has_no_delete_grant": "DELETE ON ALL TABLES IN SCHEMA release"
        not in migration_text,
        "jsonb_constraints_present": "jsonb_typeof" in migration_text,
    }
    errors = list(value["errors"]) + sorted(name for name, valid in invariants.items() if not valid)
    return ("PASS" if not errors else "FAIL"), {**value, "invariants": invariants, "errors": errors}


def _security_static_check() -> tuple[str, dict[str, Any]]:
    release_service = (ROOT / "apps/control-plane/src/vulnlab/release_governance.py").read_text(
        encoding="utf-8"
    )
    schemas = (ROOT / "apps/control-plane/src/vulnlab/schemas.py").read_text(encoding="utf-8")
    policy = (ROOT / "apps/control-plane/src/vulnlab/policy.py").read_text(encoding="utf-8")
    validation = (ROOT / "apps/control-plane/src/vulnlab/validation_execution.py").read_text(
        encoding="utf-8"
    )
    workflow = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
    actions_present = all(action in schemas and action in policy for action in POLICY_ACTIONS)
    invariants = {
        "no_arbitrary_shell_in_release_service": all(
            marker not in release_service
            for marker in ("import subprocess", "from subprocess", "shell=True", "os.system(")
        ),
        "immutable_digest_validation_present": "@sha256:" in schemas
        and "mutable tags cannot be used as deployment identity" in schemas,
        "production_runtime_gate_present": "production requires P12 authoritative runtime acceptance"
        in release_service
        and "RUNTIME_ACCEPTED" in release_service,
        "production_approval_separation_present": (
            "release candidate creator cannot approve production promotion" in release_service
        ),
        "exception_expiry_and_critical_sod_present": "expires_at <= datetime.now(UTC)"
        in release_service
        and "critical gate exceptions require separation of duties" in release_service,
        "release_policy_actions_present": actions_present,
        "p9_templates_unchanged": all(
            marker in validation
            for marker in (
                '"http.response"',
                '"sbom.dependency-version"',
                '"local.training-lab"',
            )
        )
        and "shell.arbitrary" not in validation,
        "p12r_authoritative_workflow_is_confirmed_and_guarded": "RUN_P12_ISOLATED_RUNTIME"
        in workflow
        and "P12_RUNTIME_ACCEPTANCE" in workflow
        and "kind create cluster" in workflow
        and "work/p12r/private" in workflow
        and "work/p12r/artifacts/**" in workflow,
    }
    errors = sorted(name for name, valid in invariants.items() if not valid)
    return ("PASS" if not errors else "FAIL"), {"invariants": invariants, "errors": errors}


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
        _timed("p13_layout", _layout_check),
        _timed("p13_openapi_contract", _contract_check),
        _timed("p13_database_migration", _migration_check),
        _timed("p13_security_static", _security_static_check),
        _command_check(
            "p13_release_governance_tests",
            [python, "-m", "pytest", "-q", "tests/test_p13_release_governance.py"],
        ),
    ]
    if full:
        checks.extend(
            [
                _command_check(
                    "p12_full_baseline",
                    [python, "solve_p12_baseline.py", "--full"],
                    timeout_seconds=1800,
                ),
                _command_check(
                    "pytest_full", [python, "-m", "pytest", "-q", "-rs"], timeout_seconds=1800
                ),
                _command_check(
                    "mypy", [python, "-m", "mypy", "apps/control-plane/src"], timeout_seconds=1200
                ),
                _command_check("pnpm_typecheck", ["pnpm", "typecheck"], timeout_seconds=1200),
                _command_check("pnpm_test", ["pnpm", "test"], timeout_seconds=1200),
                _command_check("pnpm_build", ["pnpm", "build"], timeout_seconds=1200),
            ]
        )
    summary = {
        "passed": sum(1 for check in checks if check.status == "PASS"),
        "failed": sum(1 for check in checks if check.status == "FAIL"),
        "skipped": sum(1 for check in checks if check.status == "SKIP"),
    }
    return {
        "phase": "P13-release-governance",
        "version": "2.13.0-p13",
        "valid": summary["failed"] == 0 and summary["skipped"] == 0,
        "summary": summary,
        "checks": [asdict(check) for check in checks],
        "runtime": False,
        "runtime_not_claimed": True,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--full", action="store_true", help="run full P0-P13 compatibility gates")
    parser.add_argument("--json", action="store_true", help="emit machine-readable JSON")
    args = parser.parse_args()
    result = run(full=args.full)
    if args.json:
        print(json.dumps(result, ensure_ascii=False, indent=2))
    else:
        print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if result["valid"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
