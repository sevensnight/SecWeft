#!/usr/bin/env python3
"""Deterministic P14 delivery package acceptance checks."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import sys
import tempfile
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent
CONTROL_PLANE_SRC = ROOT / "apps" / "control-plane" / "src"
for item in (ROOT, CONTROL_PLANE_SRC):
    if str(item) not in sys.path:
        sys.path.insert(0, str(item))
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

from fastapi.testclient import TestClient  # noqa: E402
from vulnlab.app import create_app  # noqa: E402
from vulnlab.config import Settings  # noqa: E402

ADMIN_KEY = "test-admin-key-with-sufficient-entropy"
REQUIRED_DIRECTORIES = {
    "manifests",
    "docker-compose",
    "helm",
    "migrations",
    "sbom",
    "provenance",
    "signatures",
    "acceptance",
    "compliance",
    "operations",
    "security",
    "api",
    "licenses",
    "checksums",
}
FORBIDDEN_MARKERS = (
    "BEGIN PRIVATE KEY",
    "VULNLAB_MASTER_KEY=",
    "MINIO_SECRET_KEY=",
    "NATS_PASSWORD=",
    "DATABASE_URL=postgresql://",
    ".env.platform",
    "sk-",
)


def _master_key() -> str:
    return base64.urlsafe_b64encode(hashlib.sha256(b"p14-delivery-master-key").digest()).decode()


def _settings(tmp: Path) -> Settings:
    return Settings(
        env="test",
        db_path=tmp / "p14-delivery.db",
        workspace_root=tmp / "workspaces",
        admin_key=ADMIN_KEY,
        master_key=_master_key(),
        legacy_execution_enabled=False,
    )


def _headers(key: str) -> dict[str, str]:
    return {"X-API-Key": ADMIN_KEY, "Idempotency-Key": key}


def _assert(response: Any, expected: int, label: str) -> dict[str, Any]:
    if response.status_code != expected:
        raise RuntimeError(
            f"{label} expected {expected}, got {response.status_code}: {response.text}"
        )
    return response.json()


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def run() -> dict[str, Any]:
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)
        app = create_app(_settings(tmp))
        with TestClient(app) as client:
            package = _assert(
                client.post(
                    "/api/v1/delivery-packages",
                    headers=_headers("p14-delivery-package"),
                    json={
                        "tenant_id": "system",
                        "project_id": "project-alpha",
                        "package_type": "candidate",
                    },
                ),
                202,
                "generate candidate package",
            )
            formal = client.post(
                "/api/v1/delivery-packages",
                headers=_headers("p14-formal-package"),
                json={
                    "tenant_id": "system",
                    "project_id": "project-alpha",
                    "package_type": "formal",
                },
            )
            compliance = _assert(
                client.post(
                    "/api/v1/compliance/evidence-packages",
                    headers=_headers("p14-delivery-compliance"),
                    json={"tenant_id": "system", "project_id": "project-alpha", "frameworks": []},
                ),
                202,
                "generate compliance package",
            )
            readiness = _assert(
                client.get("/api/v1/readiness/production", headers={"X-API-Key": ADMIN_KEY}),
                200,
                "get production readiness",
            )
            audit_valid = bool(client.app.state.services.audit.verify()["valid"])

        root = Path(package["root_path"])
        checksum_file = root / "SHA256SUMS"
        checksum_lines = checksum_file.read_text(encoding="utf-8").splitlines()
        checksum_map = {
            line.split("  ", 1)[1]: line.split("  ", 1)[0]
            for line in checksum_lines
            if "  " in line
        }
        files = [path for path in root.rglob("*") if path.is_file()]
        forbidden_hits = [
            str(path.relative_to(root)).replace("\\", "/")
            for path in files
            if any(
                marker in path.read_text(encoding="utf-8", errors="ignore")
                for marker in FORBIDDEN_MARKERS
            )
        ]
        checksum_failures = [
            relative
            for relative, expected in checksum_map.items()
            if (root / relative).is_file() and _sha256(root / relative) != expected
        ]
        checks = {
            "directories_present": {path.name for path in root.iterdir() if path.is_dir()}
            >= REQUIRED_DIRECTORIES,
            "root_sha256sums_present": checksum_file.is_file(),
            "checksums_sha256sums_present": (root / "checksums" / "SHA256SUMS").is_file(),
            "checksums_verify": not checksum_failures,
            "release_manifest_present": (root / "manifests" / "release-manifest.json").is_file(),
            "acceptance_report_present": (root / "acceptance" / "acceptance-report.md").is_file(),
            "known_limitations_present": (root / "manifests" / "known-limitations.md").is_file(),
            "no_forbidden_sensitive_markers": not forbidden_hits,
            "formal_package_blocked": formal.status_code == 409,
            "compliance_mapping_is_not_certification": compliance["certification_claim"] is False
            and compliance["disclaimer"] == "Control mapping is not certification.",
            "production_ready_fail_closed": readiness["production_ready"] is False
            and readiness["runtime_not_claimed"] is True,
            "audit_valid": audit_valid,
        }
        failures = sorted(name for name, valid in checks.items() if not valid)
        return {
            "phase": "P14-delivery",
            "version": "2.14.0-p14",
            "valid": not failures,
            "failed": len(failures),
            "skipped": 0,
            "package_id": package["id"],
            "package_digest": package["package_digest"],
            "root_path": str(root),
            "checks": checks,
            "failures": failures,
            "forbidden_hits": forbidden_hits,
            "checksum_failures": checksum_failures,
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
