from __future__ import annotations

import json
import os
import platform
import shutil
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]


def utc_timestamp() -> str:
    return datetime.now(UTC).isoformat()


def run_command(
    command: list[str],
    *,
    timeout_seconds: float = 300,
    cwd: Path | None = None,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command,
        cwd=cwd or ROOT,
        text=True,
        encoding="utf-8",
        errors="replace",
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
        timeout=timeout_seconds,
    )


def command_probe(command: list[str], *, timeout_seconds: float = 20) -> dict[str, Any]:
    executable = shutil.which(command[0])
    if executable is None:
        return {
            "available": False,
            "command": command,
            "resolved": None,
            "returncode": None,
            "output": "",
        }
    completed = run_command([executable, *command[1:]], timeout_seconds=timeout_seconds)
    return {
        "available": True,
        "command": [executable, *command[1:]],
        "resolved": executable,
        "returncode": completed.returncode,
        "output": completed.stdout.strip()[-2000:],
    }


def environment_fingerprint() -> dict[str, Any]:
    probes = {
        "docker_version": command_probe(["docker", "version", "--format", "{{json .}}"]),
        "docker_info": command_probe(["docker", "info", "--format", "{{json .}}"]),
        "kubectl_client": command_probe(["kubectl", "version", "--client=true", "-o", "json"]),
        "kubectl_cluster": command_probe(["kubectl", "version", "-o", "json"]),
        "helm_version": command_probe(["helm", "version", "--template", "{{.Version}}"]),
        "kind_version": command_probe(["kind", "version"]),
        "k3d_version": command_probe(["k3d", "version"]),
    }
    return {
        "captured_at": utc_timestamp(),
        "platform": platform.platform(),
        "system": platform.system(),
        "release": platform.release(),
        "machine": platform.machine(),
        "python": sys.version.split()[0],
        "environment": os.getenv("ENVIRONMENT"),
        "vulnlab_env": os.getenv("VULNLAB_ENV"),
        "p12_runtime_env": os.getenv("P12R_RUNTIME_ENV"),
        "p12_runtime_acceptance": os.getenv("P12_RUNTIME_ACCEPTANCE"),
        "test_cluster_marker": os.getenv("P12R_TEST_CLUSTER_MARKER")
        or os.getenv("VULNLAB_P12_TEST_CLUSTER_MARKER"),
        "tools": probes,
    }


def _current_kubernetes_context() -> str | None:
    if shutil.which("kubectl") is None:
        return None
    completed = run_command(["kubectl", "config", "current-context"], timeout_seconds=20)
    if completed.returncode != 0:
        return None
    return completed.stdout.strip()


def _cluster_ephemeral_label() -> dict[str, Any]:
    if shutil.which("kubectl") is None:
        return {"checked": False, "present": False, "error": "kubectl_not_available"}
    completed = run_command(["kubectl", "get", "nodes", "-o", "json"], timeout_seconds=30)
    if completed.returncode != 0:
        return {
            "checked": True,
            "present": False,
            "error": "kubectl_get_nodes_failed",
            "output": completed.stdout[-1000:],
        }
    try:
        payload = json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        return {"checked": True, "present": False, "error": f"invalid_kubectl_json:{exc}"}
    expected_key = "vulnlab.openai.local/p12-runtime"
    expected_value = "isolated"
    nodes: list[str] = []
    for item in payload.get("items", []):
        labels = item.get("metadata", {}).get("labels", {})
        if labels.get(expected_key) == expected_value:
            nodes.append(item.get("metadata", {}).get("name", "unknown"))
    return {
        "checked": True,
        "present": bool(nodes),
        "key": expected_key,
        "value": expected_value,
        "nodes": nodes,
    }


def _unsafe_endpoint(value: str | None) -> bool:
    if not value:
        return False
    lowered = value.lower()
    return any(marker in lowered for marker in ("prod", "production", "amazonaws.com", "rds."))


def _first_env(*names: str) -> tuple[str, str | None]:
    for name in names:
        value = os.getenv(name)
        if value:
            return name, value
    return names[0], None


def require_isolated_runtime(*, chaos: bool = False) -> tuple[bool, dict[str, Any]]:
    errors: list[str] = []
    environment = os.getenv("ENVIRONMENT", "").lower()
    vulnlab_env = os.getenv("VULNLAB_ENV", "").lower()
    p12_runtime_env = os.getenv("P12R_RUNTIME_ENV", "").lower()
    runtime_acceptance = os.getenv("P12_RUNTIME_ACCEPTANCE", "").lower()
    marker = os.getenv("P12R_TEST_CLUSTER_MARKER") or os.getenv("VULNLAB_P12_TEST_CLUSTER_MARKER")
    namespace = os.getenv("P12R_RUNTIME_NAMESPACE") or os.getenv("VULNLAB_KUBERNETES_NAMESPACE")
    current_context = _current_kubernetes_context()
    ephemeral_label = (
        _cluster_ephemeral_label() if current_context else {"checked": False, "present": False}
    )
    db_endpoint_name, db_endpoint = _first_env(
        "DATABASE_URL", "VULNLAB_DATABASE_URL", "POSTGRES_HOST"
    )
    minio_endpoint_name, minio_endpoint = _first_env("VULNLAB_MINIO_ENDPOINT", "MINIO_ENDPOINT")
    domain_name, domain = _first_env(
        "VULNLAB_ALLOWED_HOSTS",
        "VULNLAB_PUBLIC_BASE_URL",
        "VULNLAB_CORS_ORIGINS",
        "VULNLAB_ALLOWED_ORIGINS",
    )

    if environment != "test":
        errors.append("ENVIRONMENT=test is required")
    if runtime_acceptance != "true":
        errors.append("P12_RUNTIME_ACCEPTANCE=true is required")
    if vulnlab_env in {"production", "prod"}:
        errors.append("VULNLAB_ENV production/prod is refused")
    if p12_runtime_env != "isolated":
        errors.append("P12R_RUNTIME_ENV=isolated is required")
    if marker != "isolated-runtime":
        errors.append("P12R_TEST_CLUSTER_MARKER=isolated-runtime is required")
    if current_context is None:
        errors.append("kubectl current-context is required for runtime acceptance")
    elif not current_context.startswith(("kind-", "k3d-")):
        errors.append(f"kubernetes context must start with kind- or k3d-, got {current_context!r}")
    if not ephemeral_label.get("present"):
        errors.append(
            "ephemeral Kubernetes cluster label vulnlab.openai.local/p12-runtime=isolated is required"
        )
    if not namespace:
        errors.append("P12R_RUNTIME_NAMESPACE or VULNLAB_KUBERNETES_NAMESPACE is required")
    if namespace and namespace.lower() in {"prod", "production", "default", "kube-system"}:
        errors.append(f"production or shared namespace is refused: {namespace}")
    if not db_endpoint:
        errors.append("DATABASE_URL, VULNLAB_DATABASE_URL, or POSTGRES_HOST is required")
    elif _unsafe_endpoint(db_endpoint):
        errors.append(f"production-like database endpoint is refused from {db_endpoint_name}")
    if not minio_endpoint:
        errors.append("VULNLAB_MINIO_ENDPOINT or MINIO_ENDPOINT is required")
    elif _unsafe_endpoint(minio_endpoint):
        errors.append(f"production-like MinIO endpoint is refused from {minio_endpoint_name}")
    if domain and _unsafe_endpoint(domain):
        errors.append(f"production-like domain is refused from {domain_name}")
    if chaos:
        if os.getenv("CHAOS_ENABLED", "").lower() != "true":
            errors.append("CHAOS_ENABLED=true is required")
        if os.getenv("VULNLAB_P12_CHAOS_ACK") != "isolated-chaos":
            errors.append("VULNLAB_P12_CHAOS_ACK=isolated-chaos is required")
    return not errors, {
        "environment": environment or None,
        "vulnlab_env": vulnlab_env or None,
        "p12_runtime_env": p12_runtime_env or None,
        "p12_runtime_acceptance": runtime_acceptance or None,
        "test_cluster_marker": marker,
        "namespace": namespace,
        "kubernetes_context": current_context,
        "ephemeral_cluster_label": ephemeral_label,
        "database_endpoint_env": db_endpoint_name if db_endpoint else None,
        "minio_endpoint_env": minio_endpoint_name if minio_endpoint else None,
        "domain_env": domain_name if domain else None,
        "chaos_enabled": os.getenv("CHAOS_ENABLED"),
        "errors": errors,
        "runtime_executed": False,
    }


def summarize_checks(checks: list[Any]) -> dict[str, int]:
    return {
        "passed": sum(1 for check in checks if check.status == "PASS"),
        "failed": sum(1 for check in checks if check.status == "FAIL"),
        "skipped": sum(1 for check in checks if check.status == "SKIP"),
    }


def runtime_claimed(runtime: bool, checks: list[Any]) -> bool:
    return bool(runtime) and any(
        isinstance(check.details, dict) and check.details.get("runtime_executed") is True
        for check in checks
    )


def write_report(path: str | None, result: dict[str, Any]) -> None:
    if not path:
        return
    report_path = Path(path)
    if not report_path.is_absolute():
        report_path = ROOT / report_path
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
