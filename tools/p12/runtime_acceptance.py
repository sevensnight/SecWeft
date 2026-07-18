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
        "test_cluster_marker": os.getenv("P12R_TEST_CLUSTER_MARKER")
        or os.getenv("VULNLAB_P12_TEST_CLUSTER_MARKER"),
        "tools": probes,
    }


def require_isolated_runtime(*, chaos: bool = False) -> tuple[bool, dict[str, Any]]:
    errors: list[str] = []
    environment = os.getenv("ENVIRONMENT", "").lower()
    vulnlab_env = os.getenv("VULNLAB_ENV", "").lower()
    p12_runtime_env = os.getenv("P12R_RUNTIME_ENV", "").lower()
    marker = os.getenv("P12R_TEST_CLUSTER_MARKER") or os.getenv("VULNLAB_P12_TEST_CLUSTER_MARKER")

    if environment != "test":
        errors.append("ENVIRONMENT=test is required")
    if vulnlab_env in {"production", "prod"}:
        errors.append("VULNLAB_ENV production/prod is refused")
    if p12_runtime_env != "isolated":
        errors.append("P12R_RUNTIME_ENV=isolated is required")
    if marker != "isolated-runtime":
        errors.append("P12R_TEST_CLUSTER_MARKER=isolated-runtime is required")
    if chaos:
        if os.getenv("CHAOS_ENABLED", "").lower() != "true":
            errors.append("CHAOS_ENABLED=true is required")
        if os.getenv("VULNLAB_P12_CHAOS_ACK") != "isolated-chaos":
            errors.append("VULNLAB_P12_CHAOS_ACK=isolated-chaos is required")
    return not errors, {
        "environment": environment or None,
        "vulnlab_env": vulnlab_env or None,
        "p12_runtime_env": p12_runtime_env or None,
        "test_cluster_marker": marker,
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
