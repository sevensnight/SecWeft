#!/usr/bin/env python3
"""Static P8 operational readiness checks for deployment and security posture."""

from __future__ import annotations

import argparse
import json
import subprocess
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parents[2]
COMPOSE_PATH = ROOT / "infrastructure" / "docker-compose" / "platform.yml"
HELM_ROOT = ROOT / "infrastructure" / "kubernetes" / "helm" / "vulnlab-platform"
ENV_PLATFORM = ROOT / "infrastructure" / "docker-compose" / ".env.platform"
ENV_EXAMPLE = ROOT / "infrastructure" / "docker-compose" / ".env.platform.example"


def _load_yaml(path: Path) -> dict[str, Any]:
    value = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{path} must contain a YAML object")
    return value


def _git_tracked(path: Path) -> bool:
    completed = subprocess.run(
        ["git", "ls-files", "--error-unmatch", str(path.relative_to(ROOT)).replace("\\", "/")],
        cwd=ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        check=False,
    )
    return completed.returncode == 0


def check_compose() -> tuple[bool, dict[str, Any]]:
    document = _load_yaml(COMPOSE_PATH)
    services = document.get("services", {})
    networks = document.get("networks", {})
    required_services = {
        "gateway",
        "web-console",
        "api",
        "postgres",
        "redis",
        "nats",
        "minio",
        "otel-collector",
        "prometheus",
    }
    app_services = ("gateway", "web-console", "api")
    invariants = {
        "required_services_exist": required_services <= set(services),
        "backend_network_is_internal": networks.get("backend", {}).get("internal") is True,
        "gateway_binds_loopback_by_default": "127.0.0.1" in json.dumps(services.get("gateway", {})),
        "app_services_are_read_only": all(
            services[name].get("read_only") is True for name in app_services
        ),
        "app_services_drop_capabilities": all(
            services[name].get("cap_drop") == ["ALL"] for name in app_services
        ),
        "app_services_have_healthchecks": all(
            "healthcheck" in services[name] for name in app_services
        ),
        "legacy_execution_disabled_by_default": "VULNLAB_LEGACY_EXECUTION_ENABLED"
        in json.dumps(services.get("api", {}))
        and "false" in json.dumps(services.get("api", {})),
    }
    return all(invariants.values()), invariants


def check_helm() -> tuple[bool, dict[str, Any]]:
    values = _load_yaml(HELM_ROOT / "values.yaml")
    templates = "\n".join(
        path.read_text(encoding="utf-8") for path in (HELM_ROOT / "templates").glob("*.yaml")
    )
    invariants = {
        "network_policy_enabled_by_default": values.get("networkPolicy", {}).get("enabled") is True,
        "control_plane_single_replica_until_external_state": values.get("controlPlane", {}).get(
            "replicaCount"
        )
        == 1,
        "legacy_execution_disabled": values.get("controlPlane", {}).get("legacyExecutionEnabled")
        is False,
        "service_account_token_not_automounted": "automountServiceAccountToken: false" in templates,
        "read_only_root_filesystem": "readOnlyRootFilesystem: true" in templates,
        "runtime_default_seccomp": "seccompProfile:" in templates and "RuntimeDefault" in templates,
        "drops_all_capabilities": 'drop: ["ALL"]' in templates,
    }
    return all(invariants.values()), invariants


def check_secrets() -> tuple[bool, dict[str, Any]]:
    example = ENV_EXAMPLE.read_text(encoding="utf-8")
    invariants = {
        "example_keeps_placeholders": "GENERATE_" in example,
        "local_env_is_not_git_tracked": not _git_tracked(ENV_PLATFORM),
        "backups_are_not_git_tracked": not any(
            _git_tracked(path) for path in (ROOT / "infrastructure" / "backups").glob("*/*")
        ),
        "root_env_example_exists": (ROOT / ".env.example").is_file(),
    }
    return all(invariants.values()), invariants


def run() -> dict[str, Any]:
    checks = {
        "compose": check_compose(),
        "helm": check_helm(),
        "secrets": check_secrets(),
    }
    return {
        "valid": all(valid for valid, _ in checks.values()),
        "checks": {
            name: {"valid": valid, "invariants": invariants}
            for name, (valid, invariants) in checks.items()
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.parse_args()
    result = run()
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if result["valid"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
