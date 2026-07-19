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
    isolation_ok, isolation = require_isolated_runtime()
    if not isolation_ok:
        return "FAIL", {
            **isolation,
            "errors": ["runtime_precondition_failed", *isolation["errors"]],
        }
    if not values_file:
        return "FAIL", {
            "runtime_executed": False,
            "errors": [
                "runtime_precondition_failed",
                "--values is required for runtime because production dependencies and secrets are environment-specific",
            ],
        }
    cluster_tools = {
        "helm": shutil.which("helm") is not None,
        "kubectl": shutil.which("kubectl") is not None,
        "kind": shutil.which("kind") is not None,
        "k3d": shutil.which("k3d") is not None,
    }
    if not cluster_tools["helm"] or not cluster_tools["kubectl"]:
        return "FAIL", {
            "runtime_executed": False,
            "cluster_tools": cluster_tools,
            "errors": ["runtime_precondition_failed", "helm and kubectl are required"],
        }
    if not cluster_tools["kind"] and not cluster_tools["k3d"]:
        return "FAIL", {
            "runtime_executed": False,
            "cluster_tools": cluster_tools,
            "errors": [
                "runtime_precondition_failed",
                "kind or k3d is required for authoritative Linux runtime acceptance",
            ],
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
    runtime_executed = False
    for command in commands:
        completed = _run(command, timeout_seconds=300)
        if command[0] == "helm":
            runtime_executed = True
        results.append(
            {
                "command": command,
                "returncode": completed.returncode,
                "output": completed.stdout[-4000:],
            }
        )
        if completed.returncode != 0:
            return "FAIL", {
                "runtime_executed": runtime_executed,
                "results": results,
                "errors": ["runtime_cluster_command_failed"],
            }
    probes = _runtime_kubernetes_probes(namespace, release)
    if probes["errors"]:
        return "FAIL", {
            "runtime_executed": True,
            "results": results,
            "probes": probes,
            "errors": ["runtime_probe_failed", *probes["errors"]],
        }
    return "PASS", {
        "runtime_executed": True,
        "results": results,
        "probes": probes,
        "verified": [
            "control-plane rollout reached ready state",
            "validation-worker rollout reached ready state",
            "at least three control-plane pods are available",
            "at least three validation-worker pods are available",
            "HPA and PDB objects are present",
            "single control-plane and worker pod termination recover through rollout status",
        ],
    }


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


def _deployment_available(namespace: str, deployment: str) -> dict[str, Any]:
    probe = _kubectl_json(
        ["kubectl", "get", "deployment", deployment, "-n", namespace, "-o", "json"]
    )
    if not probe["ok"]:
        return probe
    status = probe["json"].get("status", {})
    spec = probe["json"].get("spec", {})
    return {
        **probe,
        "desired_replicas": int(spec.get("replicas") or 0),
        "available_replicas": int(status.get("availableReplicas") or 0),
        "ready_replicas": int(status.get("readyReplicas") or 0),
    }


def _delete_one_pod(namespace: str, selector: str) -> dict[str, Any]:
    pod_list = _kubectl_json(
        ["kubectl", "get", "pods", "-n", namespace, "-l", selector, "-o", "json"],
        timeout_seconds=120,
    )
    if not pod_list["ok"]:
        return pod_list
    items = pod_list["json"].get("items", [])
    if not items:
        return {"ok": False, "selector": selector, "error": "no matching pods"}
    pod_name = items[0]["metadata"]["name"]
    completed = _run(
        ["kubectl", "delete", "pod", pod_name, "-n", namespace, "--wait=false"],
        timeout_seconds=120,
    )
    return {
        "ok": completed.returncode == 0,
        "selector": selector,
        "pod": pod_name,
        "returncode": completed.returncode,
        "output": completed.stdout[-4000:],
    }


def _rollout_status(namespace: str, deployment: str) -> dict[str, Any]:
    completed = _run(
        [
            "kubectl",
            "rollout",
            "status",
            f"deployment/{deployment}",
            "-n",
            namespace,
            "--timeout=180s",
        ],
        timeout_seconds=240,
    )
    return {
        "ok": completed.returncode == 0,
        "deployment": deployment,
        "returncode": completed.returncode,
        "output": completed.stdout[-4000:],
    }


def _runtime_kubernetes_probes(namespace: str, release: str) -> dict[str, Any]:
    control_plane = f"{release}-vulnlab-platform-control-plane"
    validation_worker = f"{release}-vulnlab-platform-validation-worker"
    control_status = _deployment_available(namespace, control_plane)
    worker_status = _deployment_available(namespace, validation_worker)
    hpa = _kubectl_json(["kubectl", "get", "hpa", "-n", namespace, "-o", "json"])
    pdb = _kubectl_json(["kubectl", "get", "pdb", "-n", namespace, "-o", "json"])
    control_delete = _delete_one_pod(namespace, "app.kubernetes.io/component=control-plane")
    worker_delete = _delete_one_pod(namespace, "app.kubernetes.io/component=validation-worker")
    control_rollout = _rollout_status(namespace, control_plane)
    worker_rollout = _rollout_status(namespace, validation_worker)
    errors: list[str] = []
    if not control_status.get("ok") or control_status.get("available_replicas", 0) < 3:
        errors.append("control_plane_available_replicas_below_three")
    if not worker_status.get("ok") or worker_status.get("available_replicas", 0) < 3:
        errors.append("worker_available_replicas_below_three")
    if not hpa.get("ok") or len(hpa.get("json", {}).get("items", [])) < 2:
        errors.append("hpa_missing")
    if not pdb.get("ok") or len(pdb.get("json", {}).get("items", [])) < 2:
        errors.append("pdb_missing")
    if not control_delete.get("ok") or not control_rollout.get("ok"):
        errors.append("control_plane_pod_termination_recovery_failed")
    if not worker_delete.get("ok") or not worker_rollout.get("ok"):
        errors.append("worker_pod_termination_recovery_failed")
    return {
        "control_plane": control_status,
        "validation_worker": worker_status,
        "hpa_count": len(hpa.get("json", {}).get("items", [])) if hpa.get("ok") else 0,
        "pdb_count": len(pdb.get("json", {}).get("items", [])) if pdb.get("ok") else 0,
        "control_plane_termination": control_delete,
        "worker_termination": worker_delete,
        "control_plane_recovery": control_rollout,
        "worker_recovery": worker_rollout,
        "errors": errors,
    }


def run(*, runtime: bool, namespace: str, release: str, values_file: str | None) -> dict[str, Any]:
    started_at = utc_timestamp()
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
    summary = summarize_checks(checks)
    claimed = runtime_claimed(runtime, checks)
    return {
        "phase": "P12-scale",
        "version": "2.14.0-p14",
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
    parser.add_argument(
        "--runtime", action="store_true", help="install and validate against a real cluster"
    )
    parser.add_argument("--namespace", default="vulnlab")
    parser.add_argument("--release", default="p12")
    parser.add_argument("--values", dest="values_file")
    parser.add_argument("--report-json")
    args = parser.parse_args()
    result = run(
        runtime=args.runtime,
        namespace=args.namespace,
        release=args.release,
        values_file=args.values_file,
    )
    write_report(args.report_json, result)
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if result["valid"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
