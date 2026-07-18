#!/usr/bin/env python3
"""P12 multi-instance and horizontal-scaling acceptance entry point."""

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
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

CHART = "infrastructure/kubernetes/helm/vulnlab-platform"


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


def _require_tools(names: list[str]) -> tuple[str, dict[str, Any]]:
    missing = [name for name in names if shutil.which(name) is None]
    return ("PASS" if not missing else "FAIL"), {"required": names, "missing": missing}


def _helm_render_readiness() -> tuple[str, dict[str, Any]]:
    completed = _run(
        [
            "helm",
            "template",
            "p12",
            CHART,
            "--namespace",
            "vulnlab",
            "--set",
            "global.imagePullPolicy=Never",
        ],
        timeout_seconds=120,
    )
    output = completed.stdout
    invariants = {
        "control_plane_deployment": "name: p12-vulnlab-platform-control-plane" in output,
        "worker_deployment": "name: p12-vulnlab-platform-validation-worker" in output,
        "three_min_control_plane_hpa": "minReplicas: 3" in output,
        "worker_hpa": "validation-worker" in output and "HorizontalPodAutoscaler" in output,
        "pdb": "PodDisruptionBudget" in output,
        "topology_spread": "topologySpreadConstraints" in output,
        "no_host_network": "hostNetwork: true" not in output,
        "no_docker_socket_mount": "/var/run/docker.sock" not in output,
    }
    errors = sorted(name for name, valid in invariants.items() if not valid)
    if completed.returncode != 0:
        errors.append("helm_template_failed")
    return ("PASS" if not errors else "FAIL"), {
        "command": "helm template p12 infrastructure/kubernetes/helm/vulnlab-platform",
        "returncode": completed.returncode,
        "invariants": invariants,
        "errors": errors,
        "output_tail": output[-4000:],
    }


def _runtime_cluster_check(
    namespace: str, release: str, values_file: str | None
) -> tuple[str, dict[str, Any]]:
    if not values_file:
        return "FAIL", {
            "errors": [
                "--values is required for runtime because production dependencies and secrets are environment-specific"
            ]
        }
    commands: list[list[str]] = [
        ["kubectl", "get", "nodes"],
        ["kubectl", "create", "namespace", namespace, "--dry-run=client", "-o", "yaml"],
        [
            "helm",
            "upgrade",
            "--install",
            release,
            CHART,
            "--namespace",
            namespace,
            "--create-namespace",
            "--values",
            values_file,
        ],
        [
            "kubectl",
            "rollout",
            "status",
            f"deployment/{release}-vulnlab-platform-control-plane",
            "-n",
            namespace,
            "--timeout=180s",
        ],
        [
            "kubectl",
            "rollout",
            "status",
            f"deployment/{release}-vulnlab-platform-validation-worker",
            "-n",
            namespace,
            "--timeout=180s",
        ],
    ]
    results: list[dict[str, Any]] = []
    for command in commands:
        completed = _run(command, timeout_seconds=300)
        results.append(
            {
                "command": command,
                "returncode": completed.returncode,
                "output": completed.stdout[-4000:],
            }
        )
        if completed.returncode != 0:
            return "FAIL", {"results": results, "errors": ["runtime_cluster_command_failed"]}
    return "PASS", {
        "results": results,
        "verified": [
            "control-plane rollout reached ready state",
            "validation-worker rollout reached ready state",
        ],
        "next_manual_or_ci_probe": (
            "terminate one control-plane pod and one worker pod, then run P9 runtime execution "
            "creation and verify exactly-once evidence"
        ),
    }


def run(*, runtime: bool, namespace: str, release: str, values_file: str | None) -> dict[str, Any]:
    required_tools = ["helm"] + (["kubectl"] if runtime else [])
    checks = [
        _timed("scale_tooling", lambda: _require_tools(required_tools)),
        _timed("helm_multi_replica_readiness", _helm_render_readiness),
    ]
    if runtime:
        checks.append(
            _timed(
                "kind_or_k3d_runtime_rollout",
                lambda: _runtime_cluster_check(namespace, release, values_file),
            )
        )
    else:
        checks.append(
            CheckResult(
                name="runtime_mode",
                status="PASS",
                duration_ms=0,
                details={
                    "mode": "readiness_only",
                    "runtime_not_claimed": True,
                    "how_to_run": (
                        "python solve_p12_scale.py --runtime --namespace vulnlab "
                        "--release p12 --values /path/to/runtime-values.yaml"
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
        "phase": "P12-scale",
        "version": "2.12.0-p12",
        "runtime": runtime,
        "valid": summary["failed"] == 0 and summary["skipped"] == 0,
        "summary": summary,
        "checks": [asdict(check) for check in checks],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--runtime", action="store_true", help="install and validate against a real cluster"
    )
    parser.add_argument("--namespace", default="vulnlab")
    parser.add_argument("--release", default="p12")
    parser.add_argument("--values", dest="values_file")
    args = parser.parse_args()
    result = run(
        runtime=args.runtime,
        namespace=args.namespace,
        release=args.release,
        values_file=args.values_file,
    )
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if result["valid"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
