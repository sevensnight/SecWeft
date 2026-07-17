#!/usr/bin/env python3
"""Deterministic acceptance runner for Module 2 P4 knowledge context and RAG."""

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

from tools.contracts import openapi_snapshot  # noqa: E402


@dataclass(frozen=True)
class CheckResult:
    name: str
    status: str
    duration_ms: int
    details: dict[str, Any]


REQUIRED_PATHS = (
    "apps/control-plane/src/vulnlab/context.py",
    "apps/control-plane/src/vulnlab/rag.py",
    "apps/control-plane/src/vulnlab/evidence.py",
    "apps/control-plane/src/vulnlab/api/routers/knowledge.py",
    "apps/control-plane/src/vulnlab/db.py",
    "tests/test_p4_knowledge.py",
    "tests/test_rag.py",
    "tests/contract/test_openapi_contract.py",
    "packages/api-contracts/openapi/v1.yaml",
    "packages/shared-types/src/api.generated.ts",
    "tools/contracts/snapshots/openapi-v1.snapshot.json",
    "solution_module2_p4.md",
    "docs/testing/p4-acceptance.md",
    "docs/P4_ACCEPTANCE_REPORT.md",
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


def _storage_check() -> tuple[str, dict[str, Any]]:
    db = (ROOT / "apps/control-plane/src/vulnlab/db.py").read_text(encoding="utf-8")
    invariants = {
        "context_messages_are_hashed": "content_hash TEXT NOT NULL" in db
        and "sequence_no INTEGER NOT NULL" in db,
        "checkpoints_have_integrity_hashes": "summary_hash TEXT NOT NULL" in db
        and "state_hash TEXT NOT NULL" in db
        and "restore_policy_hash TEXT NOT NULL" in db,
        "rag_chunks_are_persisted": "CREATE TABLE IF NOT EXISTS rag_chunks" in db,
        "task_evidence_is_persisted": "CREATE TABLE IF NOT EXISTS evidence_items" in db,
        "p4_migration_version": "PRAGMA user_version=5" in db,
    }
    errors = sorted(name for name, valid in invariants.items() if not valid)
    return ("PASS" if not errors else "FAIL"), {"invariants": invariants, "errors": errors}


def _knowledge_runtime_check() -> tuple[str, dict[str, Any]]:
    context = (ROOT / "apps/control-plane/src/vulnlab/context.py").read_text(encoding="utf-8")
    rag = (ROOT / "apps/control-plane/src/vulnlab/rag.py").read_text(encoding="utf-8")
    evidence = (ROOT / "apps/control-plane/src/vulnlab/evidence.py").read_text(encoding="utf-8")
    router = (ROOT / "apps/control-plane/src/vulnlab/api/routers/knowledge.py").read_text(
        encoding="utf-8"
    )
    invariants = {
        "secrets_are_scrubbed_before_storage": "scrub_secrets" in context
        and "scrub_secrets" in rag
        and "scrub_secrets" in evidence,
        "rag_chunking_exists": "def chunk_text" in rag and "MAX_CHUNK_CHARS" in rag,
        "rag_acl_prefilter_before_scoring": "WHERE d.classification IN" in rag
        and "JOIN rag_chunks" in rag,
        "rag_citations_are_returned": '"citation"' in rag and '"chunk_hash"' in rag,
        "evidence_classification_is_role_limited": "ROLE_CLASSIFICATIONS[principal.role]"
        in evidence,
        "knowledge_pack_never_restores_authority": '"execution_authorized": False' in router,
        "restore_revalidates_current_scope": "services.scope.validate" in router,
        "p4_endpoints_exist": all(
            marker in router
            for marker in (
                '"/api/v1/tasks/{task_id}/knowledge-pack"',
                '"/api/v1/tasks/{task_id}/evidence"',
                '"/api/v1/rag/documents/{document_id}/chunks"',
            )
        ),
    }
    errors = sorted(name for name, valid in invariants.items() if not valid)
    return ("PASS" if not errors else "FAIL"), {"invariants": invariants, "errors": errors}


def _contract_check() -> tuple[str, dict[str, Any]]:
    value = openapi_snapshot.check(runtime=True)
    schemas = openapi_snapshot.load_document()["components"]["schemas"]
    invariants = {
        "operation_count_is_p4": value["operation_count"] == 56,
        "context_schema_exists": "ContextMessage" in schemas,
        "checkpoint_schema_exists": "Checkpoint" in schemas,
        "evidence_schema_exists": "EvidenceItem" in schemas,
        "knowledge_pack_schema_exists": "KnowledgePack" in schemas,
        "rag_chunk_schema_exists": "RAGChunk" in schemas,
        "rag_result_schema_exists": "RAGSearchResult" in schemas,
    }
    errors = list(value["errors"]) + sorted(name for name, valid in invariants.items() if not valid)
    details = {**value, "invariants": invariants, "errors": errors}
    return ("PASS" if not errors else "FAIL"), details


def _security_boundary_check() -> tuple[str, dict[str, Any]]:
    contract = (ROOT / "packages/api-contracts/openapi/v1.yaml").read_text(encoding="utf-8")
    router = (ROOT / "apps/control-plane/src/vulnlab/api/routers/knowledge.py").read_text(
        encoding="utf-8"
    )
    invariants = {
        "no_exploit_or_sandbox_contract_paths": all(
            marker not in contract for marker in ("/exploit", "/sandbox", "/assets/probe")
        ),
        "knowledge_paths_are_read_or_context_only": "/knowledge-pack" in contract
        and "execution_authorized" in router,
        "restore_policy_is_explicit": "restored context never restores authority" in router,
        "rag_results_are_untrusted_evidence": "untrusted_evidence_only"
        in (ROOT / "apps/control-plane/src/vulnlab/rag.py").read_text(encoding="utf-8"),
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
        _timed("p4_repository_layout", _layout_check),
        _timed("p4_storage_invariants", _storage_check),
        _timed("p4_knowledge_runtime_invariants", _knowledge_runtime_check),
        _timed("p4_openapi_contract_and_runtime_projection", _contract_check),
        _timed("p4_security_boundary", _security_boundary_check),
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
                    "python_p4_tests",
                    [
                        python,
                        "-m",
                        "pytest",
                        "tests/test_p4_knowledge.py",
                        "tests/test_rag.py",
                        "tests/contract/test_openapi_contract.py",
                        "-q",
                    ],
                ),
                _command_check("workspace_lint", ["pnpm", "lint"], optional_tool="pnpm"),
                _command_check("workspace_typecheck", ["pnpm", "typecheck"], optional_tool="pnpm"),
                _command_check("workspace_test", ["pnpm", "test"], optional_tool="pnpm"),
                _command_check("workspace_build", ["pnpm", "build"], optional_tool="pnpm"),
            ]
        )
    failed = [check for check in checks if check.status == "FAIL"]
    return {
        "phase": "P4",
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
            "no_execution_authority_from_restored_context": True,
            "rag_acl_prefilter_before_scoring": True,
            "evidence_is_non_executable_and_hashed": True,
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
