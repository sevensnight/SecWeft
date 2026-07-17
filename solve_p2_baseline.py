#!/usr/bin/env python3
"""Deterministic acceptance runner for Module 2 P2 model gateway."""

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
    "apps/control-plane/src/vulnlab/model_gateway.py",
    "apps/control-plane/src/vulnlab/api/routers/models.py",
    "apps/control-plane/src/vulnlab/schemas.py",
    "infrastructure/migrations/0005_p2_model_gateway.up.sql",
    "infrastructure/migrations/0005_p2_model_gateway.down.sql",
    "tests/test_api.py",
    "tests/contract/test_openapi_contract.py",
    "tests/contract/test_postgres_migrations.py",
    "packages/api-contracts/openapi/v1.yaml",
    "tools/contracts/snapshots/openapi-v1.snapshot.json",
    "solution_module2_p2.md",
    "docs/testing/p2-acceptance.md",
    "docs/P2_ACCEPTANCE_REPORT.md",
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


def _runtime_gateway_check() -> tuple[str, dict[str, Any]]:
    gateway = (ROOT / "apps/control-plane/src/vulnlab/model_gateway.py").read_text(encoding="utf-8")
    router = (ROOT / "apps/control-plane/src/vulnlab/api/routers/models.py").read_text(
        encoding="utf-8"
    )
    db = (ROOT / "apps/control-plane/src/vulnlab/db.py").read_text(encoding="utf-8")
    provider_projection = gateway.split("def _row_to_provider", 1)[1].split(
        "class ProviderStore", 1
    )[0]
    ledger_block = db.split("CREATE TABLE IF NOT EXISTS model_invocations", 1)[1].split(
        "CREATE TABLE IF NOT EXISTS scopes", 1
    )[0]
    invariants = {
        "credential_ref_is_metadata_only": "credential://provider/" in gateway,
        "provider_secret_is_not_returned": (
            '"has_api_key"' in provider_projection
            and '"credential_ref"' in provider_projection
            and '"api_key"' not in provider_projection
        ),
        "usage_and_cost_are_returned": '"usage"' in gateway and '"cost_usd"' in gateway,
        "token_quota_is_enforced": "_consume_token_quota" in gateway,
        "circuit_breaker_is_visible": "circuit_open" in gateway and "/providers/health" in router,
        "structured_output_is_validated": "json_object" in gateway
        and "json.loads(content)" in gateway,
        "tool_protocol_uses_allow_list": '"allowed_tools"' in gateway
        and "tool_protocol" in gateway,
        "streaming_sse_endpoint_exists": "/api/v1/models/stream" in router,
        "ledger_excludes_prompt_and_response_text": (
            "CREATE TABLE IF NOT EXISTS model_invocations" in db
            and "request_hash TEXT NOT NULL" in ledger_block
            and "content TEXT" not in ledger_block
        ),
    }
    failed = sorted(name for name, valid in invariants.items() if not valid)
    return ("PASS" if not failed else "FAIL"), {"invariants": invariants, "errors": failed}


def _contract_check() -> tuple[str, dict[str, Any]]:
    value = openapi_snapshot.check(runtime=True)
    schemas = openapi_snapshot.load_document()["components"]["schemas"]
    invariants = {
        "operation_count_preserves_p2_floor": value["operation_count"] >= 28,
        "model_provider_schema_exists": "ModelProvider" in schemas,
        "model_completion_schema_exists": "ModelCompletion" in schemas,
        "model_invocation_schema_exists": "ModelInvocation" in schemas,
    }
    errors = list(value["errors"]) + sorted(name for name, valid in invariants.items() if not valid)
    details = {**value, "invariants": invariants, "errors": errors}
    return ("PASS" if not errors else "FAIL"), details


def _migration_check() -> tuple[str, dict[str, Any]]:
    value = check_migrations.check()
    up = (
        (ROOT / "infrastructure/migrations/0005_p2_model_gateway.up.sql")
        .read_text(encoding="utf-8")
        .lower()
    )
    invariants = {
        "model_schema_created": "create schema if not exists model" in up,
        "credential_secret_is_ciphertext": "secret_ciphertext bytea not null" in up,
        "rls_for_model_tables": "alter table %s force row level security" in up,
        "invocation_ledger_uses_hashes": "request_sha256" in up and "response_sha256" in up,
        "model_schema_has_no_delete_grant": (
            "grant select, insert, update on all tables in schema model to vulnlab_app" in up
            and "grant select, insert, update, delete on all tables in schema model" not in up
        ),
    }
    errors = list(value["errors"]) + sorted(name for name, valid in invariants.items() if not valid)
    details = {**value, "invariants": invariants, "errors": errors}
    return ("PASS" if not errors else "FAIL"), details


def _security_check() -> tuple[str, dict[str, Any]]:
    sql = (
        (ROOT / "infrastructure/migrations/0005_p2_model_gateway.up.sql")
        .read_text(encoding="utf-8")
        .lower()
    )
    tests = (ROOT / "tests/test_api.py").read_text(encoding="utf-8")
    invariants = {
        "no_prompt_or_response_body_columns": all(
            marker not in sql for marker in ("prompt_text", "response_text", "body_json")
        ),
        "no_cleartext_secret_columns": all(
            marker not in sql for marker in ("secret_plaintext", "api_key text", "api_key varchar")
        ),
        "secret_non_echo_test_exists": "never_echoes_secret" in tests,
        "quota_test_exists": "token_quota_is_enforced" in tests,
        "stream_test_exists": "streams_sse" in tests,
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
        _timed("p2_repository_layout", _layout_check),
        _timed("p2_runtime_gateway_invariants", _runtime_gateway_check),
        _timed("p2_openapi_contract_and_runtime_projection", _contract_check),
        _timed("p2_postgres_migration_static_invariants", _migration_check),
        _timed("p2_secret_and_payload_safety", _security_check),
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
                    "python_p2_tests",
                    [
                        python,
                        "-m",
                        "pytest",
                        "-q",
                        "tests/test_api.py",
                        "tests/contract/test_openapi_contract.py",
                        "tests/contract/test_postgres_migrations.py",
                    ],
                ),
                _command_check("workspace_lint", ["pnpm", "lint"], optional_tool="pnpm"),
                _command_check("workspace_typecheck", ["pnpm", "typecheck"], optional_tool="pnpm"),
                _command_check("workspace_tests", ["pnpm", "test"], optional_tool="pnpm"),
                _command_check("workspace_build", ["pnpm", "build"], optional_tool="pnpm"),
            ]
        )

    passed = sum(check.status == "PASS" for check in checks)
    failed = sum(check.status == "FAIL" for check in checks)
    skipped = sum(check.status == "SKIP" for check in checks)
    return {
        "phase": "P2",
        "scope": "model-gateway-provider-credential-routing-quota-cost-audit",
        "valid": failed == 0,
        "mode": "full" if full else "baseline",
        "summary": {"passed": passed, "failed": failed, "skipped": skipped},
        "checks": [asdict(check) for check in checks],
        "safety": {
            "starts_containers": False,
            "executes_vulnerability_validation": False,
            "stores_prompt_or_response_bodies": False,
            "returns_secret_material": False,
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Module 2 P2 acceptance runner")
    parser.add_argument("--full", action="store_true", help="run local lint/type/test/build gates")
    args = parser.parse_args()
    result = run(full=args.full)
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if result["valid"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
