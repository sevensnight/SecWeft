#!/usr/bin/env python3
"""P9-H production persistence and Linux runtime hardening acceptance runner."""

from __future__ import annotations

import json
import subprocess
import sys
import time
from collections.abc import Callable
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")


@dataclass(frozen=True, slots=True)
class CheckResult:
    name: str
    status: str
    duration_ms: int
    details: dict[str, Any]


def _run(command: list[str], *, timeout_seconds: float = 600) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command,
        cwd=ROOT,
        text=True,
        encoding="utf-8",
        errors="replace",
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
        timeout=timeout_seconds,
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


def _json_objects(output: str) -> list[dict[str, Any]]:
    decoder = json.JSONDecoder()
    objects: list[dict[str, Any]] = []
    index = 0
    while index < len(output):
        start = output.find("{", index)
        if start < 0:
            break
        try:
            value, end = decoder.raw_decode(output[start:])
        except json.JSONDecodeError:
            index = start + 1
            continue
        if isinstance(value, dict):
            objects.append(value)
        index = start + end
    return objects


def _run_json(command: list[str], *, phase: str, timeout_seconds: float = 900) -> dict[str, Any]:
    completed = _run(command, timeout_seconds=timeout_seconds)
    objects = _json_objects(completed.stdout)
    selected = next((item for item in reversed(objects) if item.get("phase") == phase), None)
    if completed.returncode != 0 or selected is None:
        raise RuntimeError(
            json.dumps(
                {
                    "command": command,
                    "returncode": completed.returncode,
                    "output_tail": completed.stdout[-4000:],
                },
                ensure_ascii=False,
            )
        )
    return selected


def _sqlite_baseline() -> tuple[str, dict[str, Any]]:
    result = _run_json(
        [sys.executable, "solve_p9_baseline.py", "--full"],
        phase="P9",
        timeout_seconds=900,
    )
    summary = result.get("summary", {})
    passed = (
        bool(result.get("valid")) and summary.get("failed") == 0 and summary.get("skipped") == 0
    )
    return ("PASS" if passed else "FAIL"), {
        "command": "python solve_p9_baseline.py --full",
        "summary": summary,
        "valid": result.get("valid"),
    }


_POSTGRES_RESULT: dict[str, Any] | None = None


def _postgres_pytest() -> dict[str, Any]:
    global _POSTGRES_RESULT
    if _POSTGRES_RESULT is not None:
        return _POSTGRES_RESULT
    completed = _run(
        [
            sys.executable,
            "-m",
            "pytest",
            "tests/integration/test_p9h_postgres_repository.py",
            "-q",
            "-rs",
        ],
        timeout_seconds=360,
    )
    output = completed.stdout
    skipped = "SKIPPED" in output or " skipped" in output.lower()
    _POSTGRES_RESULT = {
        "command": "python -m pytest tests/integration/test_p9h_postgres_repository.py -q -rs",
        "returncode": completed.returncode,
        "skipped": skipped,
        "output": output[-4000:],
    }
    return _POSTGRES_RESULT


def _postgres_check(name: str, behaviors: list[str]) -> tuple[str, dict[str, Any]]:
    result = _postgres_pytest()
    passed = result["returncode"] == 0 and not result["skipped"]
    return ("PASS" if passed else "FAIL"), {
        "behaviors": behaviors,
        **result,
    }


_RUNTIME_RESULT: dict[str, Any] | None = None


def _runtime() -> dict[str, Any]:
    global _RUNTIME_RESULT
    if _RUNTIME_RESULT is not None:
        return _RUNTIME_RESULT
    _RUNTIME_RESULT = _run_json([sys.executable, "solve_p9_runtime.py"], phase="P9-R")
    return _RUNTIME_RESULT


def _runtime_check(name: str, required_check_names: list[str]) -> tuple[str, dict[str, Any]]:
    result = _runtime()
    checks = {item["name"]: item for item in result.get("checks", [])}
    missing = [item for item in required_check_names if item not in checks]
    failed = [
        item
        for item in required_check_names
        if item in checks and checks[item].get("status") != "PASS"
    ]
    passed = bool(result.get("valid")) and not missing and not failed
    return ("PASS" if passed else "FAIL"), {
        "runtime_valid": result.get("valid"),
        "required_checks": required_check_names,
        "missing": missing,
        "failed": failed,
        "summary": result.get("summary", {}),
    }


def main() -> int:
    checks = [
        _timed("sqlite_baseline", _sqlite_baseline),
        _timed(
            "postgres_api_integration",
            lambda: _postgres_check(
                "postgres_api_integration",
                [
                    "FastAPI compatibility business flow uses PostgreSQL repository backend",
                    "transaction commit and rollback",
                    "foreign keys and unique constraints",
                    "JSONB behavior",
                    "timezone-aware PostgreSQL timestamps",
                    "pagination and sorting",
                ],
            ),
        ),
        _timed(
            "postgres_concurrency",
            lambda: _postgres_check(
                "postgres_concurrency",
                [
                    "Idempotency-Key concurrency",
                    "execution lease compare-and-swap",
                    "approval revocation race",
                    "execution cancellation race",
                    "audit atomicity",
                ],
            ),
        ),
        _timed(
            "tenant_isolation",
            lambda: _postgres_check(
                "tenant_isolation",
                [
                    "cross-principal validation execution isolation",
                    "cross-principal evidence access denial",
                    "repository owner filter compatibility",
                ],
            ),
        ),
        _timed(
            "nats_runtime",
            lambda: _runtime_check(
                "nats_runtime",
                ["p9r_nats_worker_docker_minio_internal_network"],
            ),
        ),
        _timed(
            "docker_runtime",
            lambda: _runtime_check(
                "docker_runtime",
                [
                    "p9r_nats_worker_docker_minio_internal_network",
                    "p9r_docker_sandbox_timeout_cleanup",
                    "p9r_docker_sandbox_memory_limit_kill",
                ],
            ),
        ),
        _timed(
            "minio_runtime",
            lambda: _runtime_check(
                "minio_runtime",
                ["p9r_nats_worker_docker_minio_internal_network"],
            ),
        ),
        _timed(
            "linux_network_isolation",
            lambda: _runtime_check(
                "linux_network_isolation",
                ["p9r_nats_worker_docker_minio_internal_network"],
            ),
        ),
        _timed(
            "worker_recovery",
            lambda: _runtime_check(
                "worker_recovery",
                [
                    "p9r_postgresql_migrations_outbox_schema",
                    "p9r_nats_worker_docker_minio_internal_network",
                ],
            ),
        ),
    ]
    summary = {
        "total": len(checks),
        "passed": sum(1 for check in checks if check.status == "PASS"),
        "failed": sum(1 for check in checks if check.status == "FAIL"),
        "skipped": sum(1 for check in checks if check.status == "SKIP"),
    }
    report = {
        "phase": "P9-H",
        "target_version": "2.9.1-p9h",
        "valid": summary["failed"] == 0 and summary["skipped"] == 0,
        "summary": summary,
        "checks": [asdict(check) for check in checks],
    }
    print(json.dumps(report, indent=2, ensure_ascii=False))
    return 0 if report["valid"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
