#!/usr/bin/env python3
"""Import-check core runtime dependencies installed in the current environment."""

from __future__ import annotations

import importlib
import json
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from importlib import metadata
from typing import Any


@dataclass(frozen=True, slots=True)
class RuntimeDependency:
    distribution: str
    import_name: str
    required_for: str


@dataclass(frozen=True, slots=True)
class DependencyCheck:
    distribution: str
    import_name: str
    required_for: str
    imported: bool
    version: str | None
    error: str | None


RUNTIME_DEPENDENCIES = [
    RuntimeDependency("fastapi", "fastapi", "control_plane_api"),
    RuntimeDependency("uvicorn", "uvicorn", "control_plane_server"),
    RuntimeDependency("pydantic", "pydantic", "api_and_policy_models"),
    RuntimeDependency("httpx", "httpx", "validation_templates_and_tests"),
    RuntimeDependency("cryptography", "cryptography", "secret_and_token_crypto"),
    RuntimeDependency("PyJWT", "jwt", "oidc_and_service_tokens"),
    RuntimeDependency("PyYAML", "yaml", "configuration_and_delivery_manifests"),
    RuntimeDependency("minio", "minio", "p9_runtime_evidence_store"),
    RuntimeDependency("nats-py", "nats", "p9_runtime_queue"),
    RuntimeDependency("psycopg", "psycopg", "postgres_repository_runtime"),
]


def _version(distribution: str) -> str | None:
    try:
        return metadata.version(distribution)
    except metadata.PackageNotFoundError:
        return None


def check_dependency(dependency: RuntimeDependency) -> DependencyCheck:
    version = _version(dependency.distribution)
    try:
        importlib.import_module(dependency.import_name)
    except Exception as exc:
        return DependencyCheck(
            distribution=dependency.distribution,
            import_name=dependency.import_name,
            required_for=dependency.required_for,
            imported=False,
            version=version,
            error=f"{type(exc).__name__}: {exc}",
        )
    return DependencyCheck(
        distribution=dependency.distribution,
        import_name=dependency.import_name,
        required_for=dependency.required_for,
        imported=True,
        version=version,
        error=None,
    )


def build_report() -> dict[str, Any]:
    checks = [check_dependency(dependency) for dependency in RUNTIME_DEPENDENCIES]
    failed = [check for check in checks if not check.imported]
    return {
        "phase": "runtime-dependency-imports",
        "valid": not failed,
        "checked_at": datetime.now(UTC).isoformat(),
        "summary": {
            "total": len(checks),
            "passed": len(checks) - len(failed),
            "failed": len(failed),
        },
        "checks": [asdict(check) for check in checks],
    }


def main() -> int:
    report = build_report()
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0 if report["valid"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
