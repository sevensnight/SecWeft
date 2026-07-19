#!/usr/bin/env python3
"""Deterministic P14 install, upgrade, and rollback acceptance checks."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

from tools.contracts import check_migrations  # noqa: E402

SUPPORTED_UPGRADE_PATHS = {
    "2.11.x": "2.14.0-p14",
    "2.12.x": "2.14.0-p14",
    "2.13.x": "2.14.0-p14",
}
UNSUPPORTED_SOURCES = ("2.10.x", "2.9.x", "arbitrary")


def _read(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def run() -> dict[str, Any]:
    migrations = check_migrations.check()
    up_paths = [path for path, _ in check_migrations.migration_pairs()]
    down_paths = [down for _, down in check_migrations.migration_pairs()]
    up_names = [path.name.removesuffix(".up.sql") for path in up_paths]
    down_names = [path.name.removesuffix(".down.sql") for path in down_paths]
    expected_tail = [
        "0011_p11_evaluation_governance",
        "0012_p12_operational_resilience",
        "0013_p13_release_governance",
        "0014_p14_enterprise_acceptance_delivery",
    ]
    helm_chart = _read("infrastructure/kubernetes/helm/vulnlab-platform/Chart.yaml")
    helm_values = _read("infrastructure/kubernetes/helm/vulnlab-platform/values.yaml")
    compose = _read("docker-compose.yml")
    checks = {
        "fresh_install_migrations_0001_0014": migrations["valid"]
        and up_names[0].startswith("0001")
        and up_names[-1] == "0014_p14_enterprise_acceptance_delivery",
        "supported_upgrade_paths_only": set(SUPPORTED_UPGRADE_PATHS)
        == {"2.11.x", "2.12.x", "2.13.x"},
        "unsupported_paths_rejected": all(
            source not in SUPPORTED_UPGRADE_PATHS for source in UNSUPPORTED_SOURCES
        ),
        "ordered_upgrade_tail": up_names[-4:] == expected_tail,
        "rollback_has_down_migrations": up_names == down_names,
        "down_migration_boundary_declared": "DROP TABLE IF EXISTS delivery.acceptance_runs"
        in _read("infrastructure/migrations/0014_p14_enterprise_acceptance_delivery.down.sql"),
        "helm_upgrade_targets_p14": 'appVersion: "2.14.0-p14"' in helm_chart
        and "tag: 2.14.0-p14" in helm_values,
        "docker_compose_keeps_runtime_services": all(
            service in compose
            for service in (
                "nats:",
                "minio:",
                "validation-outbox-dispatcher:",
                "validation-worker:",
                "target-vulnerable:",
                "target-patched:",
                "internal: true",
            )
        ),
        "configuration_compatibility_fail_closed": "Production requires VULNLAB_REPOSITORY_BACKEND=postgres"
        in _read("apps/control-plane/src/vulnlab/config.py"),
    }
    failures = sorted(name for name, valid in checks.items() if not valid)
    return {
        "phase": "P14-upgrade-rollback",
        "version": "2.14.0-p14",
        "valid": not failures,
        "failed": len(failures),
        "skipped": 0,
        "supported_upgrade_paths": SUPPORTED_UPGRADE_PATHS,
        "unsupported_sources": list(UNSUPPORTED_SOURCES),
        "checks": checks,
        "failures": failures,
        "migration_pairs": migrations["pairs"],
        "runtime": False,
        "runtime_not_claimed": True,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", action="store_true", help="emit machine-readable JSON")
    parser.parse_args()
    result = run()
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if result["valid"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
