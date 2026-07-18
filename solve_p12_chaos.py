#!/usr/bin/env python3
"""P12 isolated failure-injection acceptance entry point."""

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

from tools.p12.runtime_acceptance import (  # noqa: E402
    environment_fingerprint,
    require_isolated_runtime,
    runtime_claimed,
    summarize_checks,
    utc_timestamp,
    write_report,
)

ALLOWED_TARGETS = {
    "control-plane",
    "idle-worker",
    "running-worker",
    "validation-worker",
    "nats",
    "postgres",
    "minio",
    "sandbox-timeout",
    "model-timeout",
    "duplicate-message",
    "poison-message",
    "delayed-message",
    "reordered-message",
}

FULL_RUNTIME_TARGETS = [
    "control-plane",
    "idle-worker",
    "running-worker",
    "nats",
    "postgres",
    "minio",
    "sandbox-timeout",
    "duplicate-message",
    "poison-message",
]


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


def _kubectl_json(command: list[str], *, timeout_seconds: float = 120) -> dict[str, Any]:
    completed = _run(command, timeout_seconds=timeout_seconds)
    if completed.returncode != 0:
        return {
            "ok": False,
            "command": command,
            "returncode": completed.returncode,
            "output": completed.stdout[-4000:],
        }
    try:
        parsed = json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        return {
            "ok": False,
            "command": command,
            "returncode": completed.returncode,
            "output": completed.stdout[-4000:],
            "error": f"invalid json: {exc}",
        }
    return {"ok": True, "command": command, "returncode": 0, "json": parsed}


def _delete_component_pod(
    namespace: str, *, target: str, selector: str
) -> tuple[str, dict[str, Any]]:
    pods = _kubectl_json(
        ["kubectl", "get", "pods", "-n", namespace, "-l", selector, "-o", "json"],
        timeout_seconds=120,
    )
    if not pods["ok"]:
        return "FAIL", {
            "runtime_executed": False,
            "target": target,
            "selector": selector,
            "errors": ["target_discovery_failed"],
            "probe": pods,
        }
    items = pods["json"].get("items", [])
    if not items:
        return "FAIL", {
            "runtime_executed": False,
            "target": target,
            "selector": selector,
            "errors": ["target_not_found"],
        }
    pod_name = items[0]["metadata"]["name"]
    completed = _run(
        ["kubectl", "delete", "pod", pod_name, "-n", namespace, "--wait=false"],
        timeout_seconds=120,
    )
    return ("PASS" if completed.returncode == 0 else "FAIL"), {
        "runtime_executed": True,
        "target": target,
        "selector": selector,
        "pod": pod_name,
        "command": completed.args,
        "returncode": completed.returncode,
        "output": completed.stdout[-4000:],
        "post_condition": "rerun solve_p12_scale.py --runtime and P9-P12 runtime acceptance",
    }


def _runtime_guard(target: str | None, namespace: str) -> tuple[str, dict[str, Any]]:
    isolation_ok, isolation = require_isolated_runtime(chaos=True)
    if not isolation_ok:
        return "FAIL", {
            **isolation,
            "errors": ["runtime_precondition_failed", *isolation["errors"]],
        }
    if not target or target not in ALLOWED_TARGETS:
        return "FAIL", {
            "runtime_executed": False,
            "errors": [
                "runtime_precondition_failed",
                f"--target must be one of {sorted(ALLOWED_TARGETS)}",
            ],
        }
    if shutil.which("kubectl") is None:
        return "FAIL", {
            "runtime_executed": False,
            "errors": ["runtime_precondition_failed", "kubectl is required for runtime chaos"],
        }
    pod_targets = {
        "control-plane": "app.kubernetes.io/component=control-plane",
        "validation-worker": "app.kubernetes.io/component=validation-worker",
        "idle-worker": "app.kubernetes.io/component=validation-worker",
        "running-worker": "app.kubernetes.io/component=validation-worker",
        "nats": "app.kubernetes.io/name=nats",
        "postgres": "app.kubernetes.io/name=postgresql",
        "minio": "app.kubernetes.io/name=minio",
    }
    if target in pod_targets:
        return _delete_component_pod(namespace, target=target, selector=pod_targets[target])
    return "FAIL", {
        "runtime_executed": False,
        "target": target,
        "errors": [
            "dedicated_runtime_workload_required",
            "this target requires live workload/NATS/sandbox injection; no implicit static pass is allowed",
        ],
    }


def _target_check_name(target: str) -> str:
    return f"chaos_runtime_{target.replace('-', '_')}"


def run(*, runtime: bool, target: str | None, namespace: str, all_targets: bool) -> dict[str, Any]:
    started_at = utc_timestamp()
    checks = [_timed("chaos_static_matrix", _static_matrix_check)]
    if runtime:
        selected_targets = FULL_RUNTIME_TARGETS if all_targets else [target]
        for selected in selected_targets:
            checks.append(
                _timed(
                    _target_check_name(str(selected)),
                    lambda selected=selected: _runtime_guard(selected, namespace),
                )
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
                        "set CHAOS_ENABLED=true, ENVIRONMENT=test, "
                        "P12R_RUNTIME_ENV=isolated, "
                        "P12R_TEST_CLUSTER_MARKER=isolated-runtime, "
                        "VULNLAB_P12_CHAOS_ACK=isolated-chaos and run "
                        "python solve_p12_chaos.py --runtime --all"
                    ),
                },
            )
        )
    summary = summarize_checks(checks)
    claimed = runtime_claimed(runtime, checks)
    return {
        "phase": "P12-chaos",
        "version": "2.12.1-p12r",
        "runtime": runtime,
        "runtime_not_claimed": not claimed,
        "started_at": started_at,
        "finished_at": utc_timestamp(),
        "environment": environment_fingerprint(),
        "valid": summary["failed"] == 0 and summary["skipped"] == 0,
        "summary": summary,
        "checks": [asdict(check) for check in checks],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runtime", action="store_true")
    parser.add_argument("--target", choices=sorted(ALLOWED_TARGETS))
    parser.add_argument("--all", action="store_true", help="run all P12-R chaos targets")
    parser.add_argument("--namespace", default="vulnlab")
    parser.add_argument("--report-json")
    args = parser.parse_args()
    result = run(
        runtime=args.runtime,
        target=args.target,
        namespace=args.namespace,
        all_targets=args.all,
    )
    write_report(args.report_json, result)
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if result["valid"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
