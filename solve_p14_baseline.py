#!/usr/bin/env python3
"""Deterministic acceptance runner for P14 enterprise delivery readiness."""

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
    "apps/control-plane/src/vulnlab/enterprise_acceptance.py",
    "apps/control-plane/src/vulnlab/api/routers/acceptance.py",
    "apps/web-console/src/services/acceptance.ts",
    "apps/web-console/src/modules/system/pages/SystemPage.tsx",
    "tests/test_p14_enterprise_acceptance.py",
    "solve_p14_baseline.py",
    "solve_p14_e2e.py",
    "solve_p14_upgrade.py",
    "solve_p14_delivery.py",
    "infrastructure/migrations/0014_p14_enterprise_acceptance_delivery.up.sql",
    "infrastructure/migrations/0014_p14_enterprise_acceptance_delivery.down.sql",
    "docs/architecture/p14-enterprise-delivery.md",
    "docs/testing/p14-e2e-matrix.md",
    "docs/testing/p14-upgrade-matrix.md",
    "docs/security/p14-data-governance.md",
    "docs/security/p14-secret-lifecycle.md",
    "docs/compliance/control-mapping.md",
    "docs/operations/installation-guide.md",
    "docs/operations/upgrade-guide.md",
    "docs/operations/rollback-guide.md",
    "docs/operations/tenant-offboarding.md",
    "docs/acceptance/p14-final-acceptance-report.md",
    "docs/acceptance/requirements-traceability-matrix.md",
    "docs/release/known-limitations.md",
)

P14_PATHS = {
    "/acceptance/requirements",
    "/acceptance/status",
    "/acceptance/runs",
    "/acceptance/runs/{run_id}",
    "/delivery-packages",
    "/delivery-packages/{package_id}",
    "/compliance/controls",
    "/compliance/evidence-packages",
    "/data-governance/export",
    "/data-governance/deletion-requests",
    "/data-governance/legal-holds",
    "/readiness/production",
}

P14_SCHEMAS = {
    "RequirementTraceabilityItem",
    "ProductionGateResponse",
    "AcceptanceStatusResponse",
    "ProductionReadinessResponse",
    "AcceptanceRunCreate",
    "AcceptanceRunResponse",
    "DeliveryPackageCreate",
    "DeliveryPackageResponse",
    "ComplianceControlResponse",
    "ComplianceEvidencePackageCreate",
    "ComplianceEvidencePackageResponse",
    "DataExportCreate",
    "DataExportResponse",
    "DataDeletionRequestCreate",
    "DataDeletionRequestResponse",
    "LegalHoldCreate",
    "LegalHoldResponse",
}

P14_POLICY_ACTIONS = {
    "acceptance.run",
    "acceptance.review",
    "delivery.generate",
    "delivery.download",
    "compliance.map",
    "compliance.generate",
    "data.export",
    "data.delete.request",
    "data.delete.approve",
    "legal-hold.create",
    "legal-hold.release",
    "secret.rotate",
    "production-readiness.review",
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
        "operation_count_is_p14_or_later": value["operation_count"] >= 135,
        "p14_paths_exist": set(paths) >= P14_PATHS,
        "p14_schemas_exist": set(schemas) >= P14_SCHEMAS,
        "p14_posts_are_idempotent": all(
            "#/components/parameters/IdempotencyKey"
            in {
                item.get("$ref")
                for item in paths[path][method].get("parameters", [])
                if isinstance(item, dict)
            }
            for path, method in (
                ("/acceptance/runs", "post"),
                ("/delivery-packages", "post"),
                ("/compliance/evidence-packages", "post"),
                ("/data-governance/export", "post"),
                ("/data-governance/deletion-requests", "post"),
                ("/data-governance/legal-holds", "post"),
            )
        ),
        "dangerous_paths_absent": all(
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
        ROOT / "infrastructure/migrations/0014_p14_enterprise_acceptance_delivery.up.sql"
    ).read_text(encoding="utf-8")
    invariants = {
        "p14_migration_present": "0014_p14_enterprise_acceptance_delivery" in value["pairs"],
        "all_migrations_remain_valid": value["valid"],
        "delivery_schema_uses_rls": "ENABLE ROW LEVEL SECURITY" in migration_text
        and "FORCE ROW LEVEL SECURITY" in migration_text,
        "application_role_has_no_delete_grant": "DELETE ON ALL TABLES IN SCHEMA delivery"
        not in migration_text,
        "jsonb_constraints_present": "jsonb_typeof" in migration_text,
        "self_approval_blocked": "ck_delivery_delete_no_self_approval" in migration_text,
    }
    errors = list(value["errors"]) + sorted(name for name, valid in invariants.items() if not valid)
    return ("PASS" if not errors else "FAIL"), {**value, "invariants": invariants, "errors": errors}


def _security_static_check() -> tuple[str, dict[str, Any]]:
    service = (ROOT / "apps/control-plane/src/vulnlab/enterprise_acceptance.py").read_text(
        encoding="utf-8"
    )
    schemas = (ROOT / "apps/control-plane/src/vulnlab/schemas.py").read_text(encoding="utf-8")
    policy = (ROOT / "apps/control-plane/src/vulnlab/policy.py").read_text(encoding="utf-8")
    validation = (ROOT / "apps/control-plane/src/vulnlab/validation_execution.py").read_text(
        encoding="utf-8"
    )
    invariants = {
        "p14_policy_actions_present": all(
            action in schemas and action in policy for action in P14_POLICY_ACTIONS
        ),
        "production_ready_fail_closed": "runtime_not_claimed" in service
        and "production_ready" in service
        and "No verified GitHub isolated runtime run artifacts" in service,
        "formal_delivery_requires_readiness": "formal delivery package requires production_ready=true"
        in service,
        "compliance_not_certification": "Control mapping is not certification." in service,
        "delivery_secret_scan_present": "SENSITIVE_DELIVERY_MARKERS" in service,
        "no_platform_arbitrary_command": all(
            marker not in service
            for marker in ("import subprocess", "from subprocess", "shell=True", "os.system(")
        ),
        "p9_templates_unchanged": all(
            marker in validation
            for marker in ('"http.response"', '"sbom.dependency-version"', '"local.training-lab"')
        )
        and "shell.arbitrary" not in validation,
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
        _timed("p14_layout", _layout_check),
        _timed("p14_openapi_contract", _contract_check),
        _timed("p14_database_migration", _migration_check),
        _timed("p14_security_static", _security_static_check),
        _command_check(
            "p14_enterprise_acceptance_tests",
            [
                python,
                "-m",
                "pytest",
                "-q",
                "tests/test_p14_enterprise_acceptance.py",
                "tests/contract/test_openapi_contract.py",
                "tests/contract/test_postgres_migrations.py",
            ],
        ),
    ]
    if full:
        checks.extend(
            [
                _command_check(
                    "p13_full_baseline",
                    [python, "solve_p13_baseline.py", "--full", "--json"],
                    timeout_seconds=1800,
                ),
                _command_check(
                    "p14_e2e", [python, "solve_p14_e2e.py", "--json"], timeout_seconds=900
                ),
                _command_check(
                    "p14_upgrade", [python, "solve_p14_upgrade.py", "--json"], timeout_seconds=600
                ),
                _command_check(
                    "p14_delivery", [python, "solve_p14_delivery.py", "--json"], timeout_seconds=600
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
        "phase": "P14-enterprise-acceptance-delivery",
        "version": "2.14.0-p14",
        "valid": summary["failed"] == 0 and summary["skipped"] == 0,
        "summary": summary,
        "sections": {
            "requirement_traceability": True,
            "final_e2e": True,
            "upgrade_rollback": True,
            "data_governance": True,
            "secret_lifecycle": True,
            "delivery_package": True,
            "compliance_mapping": True,
            "production_readiness": "fail_closed_without_authoritative_runtime",
        },
        "checks": [asdict(check) for check in checks],
        "runtime": False,
        "runtime_not_claimed": True,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--full", action="store_true", help="run full P0-P14 compatibility gates")
    parser.add_argument("--json", action="store_true", help="emit machine-readable JSON")
    args = parser.parse_args()
    result = run(full=args.full)
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if result["valid"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
