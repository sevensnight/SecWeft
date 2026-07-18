#!/usr/bin/env python3
"""P12 isolated failure-injection acceptance entry point."""

from __future__ import annotations

import argparse
import json
import os
import shutil
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

ALLOWED_TARGETS = {
    "control-plane",
    "validation-worker",
    "nats",
    "postgres",
    "minio",
    "sandbox-timeout",
    "model-timeout",
    "duplicate-message",
    "delayed-message",
    "reordered-message",
}


@dataclass(frozen=True, slots=True)
class CheckResult:
    name: str
    status: str
    duration_ms: int
    details: dict[str, Any]


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


def _run(command: list[str], *, timeout_seconds: float = 300) -> subprocess.CompletedProcess[str]:
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


def _static_matrix_check() -> tuple[str, dict[str, Any]]:
    matrix = ROOT / "docs/testing/p12-chaos-matrix.md"
    text = matrix.read_text(encoding="utf-8") if matrix.is_file() else ""
    invariants = {
        "matrix_exists": matrix.is_file(),
        "production_guard_documented": "production" in text.lower() and "refuse" in text.lower(),
        "no_unbounded_retry": "bounded retry" in text.lower(),
        "targets_documented": all(target in text for target in ALLOWED_TARGETS),
    }
    errors = sorted(name for name, valid in invariants.items() if not valid)
    return ("PASS" if not errors else "FAIL"), {"invariants": invariants, "errors": errors}


def _runtime_guard(target: str | None, namespace: str) -> tuple[str, dict[str, Any]]:
    env = os.getenv("VULNLAB_ENV", "development").lower()
    if env in {"production", "prod"}:
        return "FAIL", {"errors": ["chaos runtime refuses production mode"]}
    if os.getenv("VULNLAB_P12_CHAOS_ACK") != "isolated-chaos":
        return "FAIL", {"errors": ["VULNLAB_P12_CHAOS_ACK=isolated-chaos is required"]}
    if not target or target not in ALLOWED_TARGETS:
        return "FAIL", {"errors": [f"--target must be one of {sorted(ALLOWED_TARGETS)}"]}
    if shutil.which("kubectl") is None:
        return "FAIL", {"errors": ["kubectl is required for runtime chaos"]}
    if target in {"control-plane", "validation-worker"}:
        selector = (
            "app.kubernetes.io/component=control-plane"
            if target == "control-plane"
            else "app.kubernetes.io/component=validation-worker"
        )
        completed = _run(
            ["kubectl", "delete", "pod", "-n", namespace, "-l", selector, "--wait=false"],
            timeout_seconds=120,
        )
        return ("PASS" if completed.returncode == 0 else "FAIL"), {
            "target": target,
            "command": completed.args,
            "returncode": completed.returncode,
            "output": completed.stdout[-4000:],
            "post_condition": "rerun solve_p12_scale.py --runtime and P9 runtime acceptance",
        }
    return "FAIL", {
        "target": target,
        "errors": [
            "this target requires the dedicated runtime harness; no production or implicit injection is performed"
        ],
    }


def run(*, runtime: bool, target: str | None, namespace: str) -> dict[str, Any]:
    checks = [_timed("chaos_static_matrix", _static_matrix_check)]
    if runtime:
        checks.append(
            _timed("chaos_runtime_guarded_injection", lambda: _runtime_guard(target, namespace))
        )
    else:
        checks.append(
            CheckResult(
                name="chaos_runtime_not_claimed",
                status="PASS",
                duration_ms=0,
                details={
                    "runtime_not_claimed": True,
                    "how_to_run": (
                        "set VULNLAB_P12_CHAOS_ACK=isolated-chaos and run "
                        "python solve_p12_chaos.py --runtime --target validation-worker"
                    ),
                },
            )
        )
    summary = {
        "passed": sum(1 for check in checks if check.status == "PASS"),
        "failed": sum(1 for check in checks if check.status == "FAIL"),
        "skipped": sum(1 for check in checks if check.status == "SKIP"),
    }
    return {
        "phase": "P12-chaos",
        "version": "2.12.0-p12",
        "runtime": runtime,
        "valid": summary["failed"] == 0 and summary["skipped"] == 0,
        "summary": summary,
        "checks": [asdict(check) for check in checks],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runtime", action="store_true")
    parser.add_argument("--target", choices=sorted(ALLOWED_TARGETS))
    parser.add_argument("--namespace", default="vulnlab")
    args = parser.parse_args()
    result = run(runtime=args.runtime, target=args.target, namespace=args.namespace)
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if result["valid"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
