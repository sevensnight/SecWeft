from __future__ import annotations

from pathlib import Path
from typing import Any

from conftest import make_user


def _headers(base: dict[str, str], key: str) -> dict[str, str]:
    return {**base, "Idempotency-Key": key}


def test_p14_requirements_and_production_readiness_fail_closed(client, admin_headers):
    requirements = client.get("/api/v1/acceptance/requirements", headers=admin_headers)
    assert requirements.status_code == 200, requirements.text
    items = requirements.json()
    assert {item["requirement_id"] for item in items} >= {
        "P9.CONTROLLED_EXECUTION_PLANE",
        "P13.RELEASE_GOVERNANCE",
        "P14.ENTERPRISE_DELIVERY",
    }
    assert all(
        item["implementation_status"]
        in {"IMPLEMENTED", "PARTIALLY_IMPLEMENTED", "NOT_IMPLEMENTED", "NOT_APPLICABLE", "BLOCKED"}
        for item in items
    )
    assert any(item["runtime_evidence"].get("runtime_not_claimed", False) for item in items)

    status = client.get("/api/v1/acceptance/status", headers=admin_headers)
    assert status.status_code == 200, status.text
    status_body = status.json()
    assert status_body["valid"] is True
    assert status_body["production_ready"] is False
    assert status_body["runtime"] is False
    assert status_body["runtime_not_claimed"] is True
    assert "p12_authoritative_runtime" in status_body["failed_critical_gates"]
    assert status_body["supported_upgrade_paths"] == [
        "2.11.x -> 2.14.0-p14",
        "2.12.x -> 2.14.0-p14",
        "2.13.x -> 2.14.0-p14",
    ]

    readiness = client.get("/api/v1/readiness/production", headers=admin_headers)
    assert readiness.status_code == 200, readiness.text
    readiness_body = readiness.json()
    assert readiness_body["production_ready"] is False
    assert readiness_body["runtime_not_claimed"] is True
    assert any(
        gate["gate_id"] == "p12_authoritative_runtime" and gate["status"] == "failed"
        for gate in readiness_body["critical_gates"]
    )


def test_p14_acceptance_run_is_idempotent_and_traced(client, admin_headers):
    payload: dict[str, Any] = {
        "tenant_id": "system",
        "project_id": "project-alpha",
        "scenario_id": "p14-final-enterprise-acceptance",
        "trace_id": "a" * 32,
    }
    first = client.post(
        "/api/v1/acceptance/runs",
        headers=_headers(admin_headers, "p14-run-same"),
        json=payload,
    )
    assert first.status_code == 202, first.text
    second = client.post(
        "/api/v1/acceptance/runs",
        headers=_headers(admin_headers, "p14-run-same"),
        json=payload,
    )
    assert second.status_code == 202, second.text
    assert second.json()["id"] == first.json()["id"]
    assert second.json()["status"] == "completed_with_blocked_production"
    assert second.json()["result"]["trace_chain"]["trace_id"] == "a" * 32

    missing_key = client.post("/api/v1/acceptance/runs", headers=admin_headers, json=payload)
    assert missing_key.status_code == 409


def test_p14_delivery_candidate_package_and_formal_gate(client, admin_headers):
    candidate = client.post(
        "/api/v1/delivery-packages",
        headers=_headers(admin_headers, "p14-delivery-candidate"),
        json={"tenant_id": "system", "project_id": "project-alpha", "package_type": "candidate"},
    )
    assert candidate.status_code == 202, candidate.text
    package = candidate.json()
    root = Path(package["root_path"])
    assert root.is_dir()
    for directory in {
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
    }:
        assert (root / directory).is_dir()
    assert (root / "SHA256SUMS").is_file()
    assert package["manifest"]["runtime_not_claimed"] is True
    assert package["manifest"]["production_ready"] is False

    forbidden = ("BEGIN PRIVATE KEY", "VULNLAB_MASTER_KEY=", "MINIO_SECRET_KEY=", ".env.platform")
    for path in root.rglob("*"):
        if path.is_file():
            text = path.read_text(encoding="utf-8")
            assert not any(marker in text for marker in forbidden)

    read_back = client.get(f"/api/v1/delivery-packages/{package['id']}", headers=admin_headers)
    assert read_back.status_code == 200, read_back.text
    assert read_back.json()["package_digest"] == package["package_digest"]

    _, analyst_headers = make_user(client, admin_headers, "p14-analyst-read", "analyst")
    cross_tenant = client.get(f"/api/v1/delivery-packages/{package['id']}", headers=analyst_headers)
    assert cross_tenant.status_code == 404

    formal = client.post(
        "/api/v1/delivery-packages",
        headers=_headers(admin_headers, "p14-delivery-formal"),
        json={"tenant_id": "system", "project_id": "project-alpha", "package_type": "formal"},
    )
    assert formal.status_code == 409
    assert "production_ready=true" in formal.text


def test_p14_compliance_mapping_exports_no_certification_claim(client, admin_headers):
    controls = client.get("/api/v1/compliance/controls", headers=admin_headers)
    assert controls.status_code == 200, controls.text
    body = controls.json()
    assert {item["framework"] for item in body} >= {
        "ISO/IEC 27001",
        "SOC 2 Trust Services Criteria",
        "NIST Cybersecurity Framework",
        "NIST SSDF",
        "OWASP ASVS",
        "OWASP SAMM",
        "SLSA",
        "CIS Kubernetes Benchmark",
    }
    assert all(item["certification_claim"] is False for item in body)
    assert all(item["disclaimer"] == "Control mapping is not certification." for item in body)

    package = client.post(
        "/api/v1/compliance/evidence-packages",
        headers=_headers(admin_headers, "p14-compliance"),
        json={"tenant_id": "system", "project_id": "project-alpha", "frameworks": ["SLSA"]},
    )
    assert package.status_code == 202, package.text
    assert package.json()["certification_claim"] is False
    assert package.json()["controls"][0]["framework"] == "SLSA"


def test_p14_data_governance_export_deletion_and_legal_hold(client, admin_headers):
    export = client.post(
        "/api/v1/data-governance/export",
        headers=_headers(admin_headers, "p14-export"),
        json={"tenant_id": "system", "project_id": "project-alpha", "format": "json"},
    )
    assert export.status_code == 202, export.text
    assert export.json()["redacted"] is True
    assert export.json()["secret_count"] == 0

    hold = client.post(
        "/api/v1/data-governance/legal-holds",
        headers=_headers(admin_headers, "p14-hold"),
        json={
            "tenant_id": "system",
            "project_id": "project-alpha",
            "hold_type": "incident",
            "reason": "active incident preservation",
            "scope": {"target": "project-alpha"},
        },
    )
    assert hold.status_code == 202, hold.text
    assert hold.json()["status"] == "active"

    deletion = client.post(
        "/api/v1/data-governance/deletion-requests",
        headers=_headers(admin_headers, "p14-delete"),
        json={
            "tenant_id": "system",
            "project_id": "project-alpha",
            "target_type": "project",
            "target_id": "project-alpha",
            "dry_run": True,
            "reason": "tenant offboarding dry-run",
        },
    )
    assert deletion.status_code == 202, deletion.text
    body = deletion.json()
    assert body["status"] == "blocked_by_legal_hold"
    assert body["scope_preview"]["physical_deletion_allowed"] is False
    assert body["deletion_certificate"]["legal_hold_block"] is True

    _, analyst_headers = make_user(client, admin_headers, "p14-tenant-analyst", "analyst")
    scoped_export = client.post(
        "/api/v1/data-governance/export",
        headers=_headers(analyst_headers, "p14-analyst-export"),
        json={"tenant_id": "system", "project_id": "project-alpha", "format": "json"},
    )
    assert scoped_export.status_code == 202, scoped_export.text
    assert scoped_export.json()["tenant_id"] != "system"
    assert scoped_export.json()["tenant_id"] == scoped_export.json()["requested_by"]


def test_p14_viewer_cannot_run_or_generate_delivery(client, admin_headers):
    _, viewer_headers = make_user(client, admin_headers, "p14-viewer", "viewer")
    readable = client.get("/api/v1/acceptance/status", headers=viewer_headers)
    assert readable.status_code == 200, readable.text

    run = client.post(
        "/api/v1/acceptance/runs",
        headers=_headers(viewer_headers, "p14-viewer-run"),
        json={"tenant_id": "system", "project_id": "project-alpha"},
    )
    assert run.status_code == 403

    delivery = client.post(
        "/api/v1/delivery-packages",
        headers=_headers(viewer_headers, "p14-viewer-delivery"),
        json={"tenant_id": "system", "project_id": "project-alpha", "package_type": "candidate"},
    )
    assert delivery.status_code == 403
