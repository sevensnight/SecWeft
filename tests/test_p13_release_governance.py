from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

from conftest import make_user
from fastapi.testclient import TestClient

SHA_A = "a" * 64
SHA_B = "b" * 64
SHA_C = "c" * 64
SHA_D = "d" * 64
SHA_E = "e" * 64
SHA_F = "f" * 64


def _headers(base: dict[str, str], key: str) -> dict[str, str]:
    return {**base, "Idempotency-Key": key}


def _artifact_payload(
    suffix: str, *, include_sbom: bool = True, critical: bool = False
) -> dict[str, Any]:
    image_digest = f"registry.local/vulnlab/control-plane-{suffix}@sha256:{SHA_A}"
    payload: dict[str, Any] = {
        "tenant_id": "system",
        "project_id": "project-alpha",
        "name": f"P13 artifact {suffix}",
        "artifact_type": "container",
        "digest": image_digest,
        "repository": "registry.local/vulnlab/control-plane",
        "source_commit": SHA_B[:40],
        "metadata": {"build_record": f"build-{suffix}"},
        "provenance": {
            "subject_digest": image_digest,
            "source_repository": "https://github.com/example/vulnlab",
            "source_commit": SHA_B[:40],
            "builder_workflow": ".github/workflows/ci.yml",
            "statement_digest": f"sha256:{SHA_D}",
            "predicate_type": "https://slsa.dev/provenance/v1",
            "verified": True,
            "metadata": {"oidc": True},
        },
        "signature": {
            "signature_digest": f"sha256:{SHA_E}",
            "signature_identity": "https://github.com/example/vulnlab/.github/workflows/ci.yml@refs/heads/main",
            "certificate_issuer": "https://token.actions.githubusercontent.com",
            "verified": True,
        },
        "security_scan": {
            "scanner": "trivy",
            "severity_summary": {"critical": 1 if critical else 0, "high": 0},
            "critical_count": 1 if critical else 0,
            "high_count": 0,
            "unresolved_critical": critical,
            "scan_digest": f"sha256:{SHA_F}",
        },
        "license_scan": {
            "scanner": "license-policy",
            "license_summary": {"allowed": 42, "prohibited": 0},
            "prohibited_licenses": [],
            "passed": True,
            "scan_digest": f"sha256:{SHA_A}",
        },
    }
    if include_sbom:
        payload["sbom"] = {
            "format": "CycloneDX",
            "generator": "pytest",
            "generated_at": datetime.now(UTC).isoformat(),
            "artifact_digest": image_digest,
            "document_digest": f"sha256:{SHA_C}",
            "component_count": 42,
            "license_summary": {"MIT": 20, "Apache-2.0": 22},
            "vulnerability_summary": {"critical": 1 if critical else 0, "high": 0},
            "document_ref": f"sbom://pytest/{suffix}",
        }
    return payload


def _create_artifact(
    client: TestClient,
    headers: dict[str, str],
    suffix: str,
    *,
    include_sbom: bool = True,
    critical: bool = False,
) -> dict[str, Any]:
    response = client.post(
        "/api/v1/release-artifacts",
        headers=_headers(headers, f"artifact-{suffix}"),
        json=_artifact_payload(suffix, include_sbom=include_sbom, critical=critical),
    )
    assert response.status_code == 201, response.text
    return response.json()


def _create_candidate(
    client: TestClient,
    headers: dict[str, str],
    artifact_id: str,
    suffix: str,
    *,
    p12_runtime: bool = False,
) -> dict[str, Any]:
    response = client.post(
        "/api/v1/release-candidates",
        headers=_headers(headers, f"candidate-{suffix}"),
        json={
            "tenant_id": "system",
            "project_id": "project-alpha",
            "name": f"P13 RC {suffix}",
            "artifact_id": artifact_id,
            "configuration_hash": SHA_B,
            "migration_set": ["0001-0013"],
            "helm_chart_digest": f"sha256:{SHA_C}",
            "metadata": {
                "source_tree_clean": True,
                "p0_p12_baseline": True,
                "p11_evaluation_gates": True,
                "unit_integration_e2e": True,
                "openapi_snapshot": True,
                "migration_compatibility": True,
                "secret_scan": True,
                "container_scan": True,
                "helm_lint": True,
                "helm_policy": True,
                "configuration_policy": True,
                "backup_readiness": True,
                "rollback_readiness": True,
                "p12_authoritative_runtime": {
                    "status": "RUNTIME_ACCEPTED" if p12_runtime else "READINESS_COMPLETE",
                    "runtime": p12_runtime,
                    "runtime_not_claimed": not p12_runtime,
                },
            },
        },
    )
    assert response.status_code == 201, response.text
    return response.json()


def _evaluate(
    client: TestClient, headers: dict[str, str], candidate_id: str, environment: str, suffix: str
) -> list[dict[str, Any]]:
    response = client.post(
        f"/api/v1/release-candidates/{candidate_id}/evaluate",
        headers=_headers(headers, f"evaluate-{environment}-{suffix}"),
        json={"environment": environment},
    )
    assert response.status_code == 200, response.text
    return response.json()


def _approve(
    client: TestClient, headers: dict[str, str], candidate_id: str, environment: str, suffix: str
) -> dict[str, Any]:
    response = client.post(
        f"/api/v1/release-candidates/{candidate_id}/approvals",
        headers=_headers(headers, f"approve-{environment}-{suffix}"),
        json={
            "environment": environment,
            "decision": "approved",
            "reason": f"approve {environment}",
        },
    )
    assert response.status_code == 201, response.text
    return response.json()


def _promote(
    client: TestClient, headers: dict[str, str], candidate_id: str, environment: str, suffix: str
) -> dict[str, Any]:
    response = client.post(
        f"/api/v1/release-candidates/{candidate_id}/promotions",
        headers=_headers(headers, f"promote-{environment}-{suffix}"),
        json={"environment": environment, "canary_percentage": 25, "health": {"replicas": 3}},
    )
    assert response.status_code == 201, response.text
    return response.json()


def test_p13_staging_release_flow(client, admin_headers):
    artifact = _create_artifact(client, admin_headers, "staging")
    candidate = _create_candidate(client, admin_headers, artifact["id"], "staging")

    skip_response = client.post(
        f"/api/v1/release-candidates/{candidate['id']}/promotions",
        headers=_headers(admin_headers, "promote-staging-skip"),
        json={"environment": "staging", "canary_percentage": 25},
    )
    assert skip_response.status_code == 409

    gates = _evaluate(client, admin_headers, candidate["id"], "staging", "staging")
    assert any(
        gate["gate_id"] == "p12_authoritative_runtime" and gate["status"] == "warning"
        for gate in gates
    )
    _approve(client, admin_headers, candidate["id"], "staging", "staging")
    _promote(client, admin_headers, candidate["id"], "development", "staging")
    _promote(client, admin_headers, candidate["id"], "integration", "staging")
    promotion = _promote(client, admin_headers, candidate["id"], "staging", "staging")
    assert promotion["deployment"]["image_digest"] == candidate["image_digest"]

    deployment_id = promotion["deployment"]["id"]
    drift = client.get(f"/api/v1/deployments/{deployment_id}/drift", headers=admin_headers)
    assert drift.status_code == 200, drift.text
    assert drift.json()["status"] == "healthy"

    compliance = client.post(
        f"/api/v1/release-candidates/{candidate['id']}/compliance-package",
        headers=_headers(admin_headers, "compliance-staging"),
    )
    assert compliance.status_code == 201, compliance.text
    assert compliance.json()["package_digest"]

    rollback = client.post(
        f"/api/v1/deployments/{deployment_id}/rollback",
        headers=_headers(admin_headers, "rollback-staging"),
        json={"reason": "deterministic rollback acceptance"},
    )
    assert rollback.status_code == 201, rollback.text
    assert rollback.json()["status"] == "completed"


def test_p13_production_requires_p12_runtime_and_approval_separation(client, admin_headers):
    artifact = _create_artifact(client, admin_headers, "prodblocked")
    candidate = _create_candidate(client, admin_headers, artifact["id"], "prodblocked")

    creator_approval = client.post(
        f"/api/v1/release-candidates/{candidate['id']}/approvals",
        headers=_headers(admin_headers, "creator-prod-approval"),
        json={"environment": "production", "decision": "approved", "reason": "creator blocked"},
    )
    assert creator_approval.status_code == 409

    gates = _evaluate(client, admin_headers, candidate["id"], "production", "prodblocked")
    assert any(
        gate["gate_id"] == "p12_authoritative_runtime" and gate["status"] == "failed"
        for gate in gates
    )
    _promote(client, admin_headers, candidate["id"], "development", "prodblocked")
    _promote(client, admin_headers, candidate["id"], "integration", "prodblocked")
    _promote(client, admin_headers, candidate["id"], "staging", "prodblocked")
    prod_promote = client.post(
        f"/api/v1/release-candidates/{candidate['id']}/promotions",
        headers=_headers(admin_headers, "promote-prodblocked"),
        json={"environment": "production", "canary_percentage": 10},
    )
    assert prod_promote.status_code == 409
    assert "p12_authoritative_runtime" in prod_promote.text


def test_p13_production_promotion_uses_same_digest_after_runtime_acceptance(client, admin_headers):
    second_admin, second_admin_headers = make_user(
        client, admin_headers, "release-admin-2", "admin"
    )
    artifact = _create_artifact(client, admin_headers, "prodok")
    candidate = _create_candidate(client, admin_headers, artifact["id"], "prodok", p12_runtime=True)

    _promote(client, admin_headers, candidate["id"], "development", "prodok")
    _promote(client, admin_headers, candidate["id"], "integration", "prodok")
    _promote(client, admin_headers, candidate["id"], "staging", "prodok")
    _evaluate(client, admin_headers, candidate["id"], "production", "prodok")
    approval = _approve(client, second_admin_headers, candidate["id"], "production", "prodok")
    assert approval["approved_by"] == second_admin["id"]
    production = _promote(client, admin_headers, candidate["id"], "production", "prodok")
    assert production["deployment"]["image_digest"] == candidate["image_digest"]


def test_p13_rejects_mutable_artifacts_and_missing_sbom(client, admin_headers):
    mutable = _artifact_payload("mutable")
    mutable["digest"] = "registry.local/vulnlab/control-plane:latest"
    response = client.post(
        "/api/v1/release-artifacts",
        headers=_headers(admin_headers, "artifact-mutable"),
        json=mutable,
    )
    assert response.status_code == 422

    artifact = _create_artifact(client, admin_headers, "nosbom", include_sbom=False)
    candidate = client.post(
        "/api/v1/release-candidates",
        headers=_headers(admin_headers, "candidate-nosbom"),
        json={
            "tenant_id": "system",
            "project_id": "project-alpha",
            "name": "P13 RC nosbom",
            "artifact_id": artifact["id"],
            "configuration_hash": SHA_B,
            "migration_set": ["0001-0013"],
            "helm_chart_digest": f"sha256:{SHA_C}",
            "metadata": {},
        },
    )
    assert candidate.status_code == 409
    assert "missing sbom" in candidate.text


def test_p13_idempotency_optimistic_lock_and_exceptions(client, admin_headers):
    payload = _artifact_payload("idempotent")
    first = client.post(
        "/api/v1/release-artifacts",
        headers=_headers(admin_headers, "same-artifact-key"),
        json=payload,
    )
    assert first.status_code == 201, first.text
    second = client.post(
        "/api/v1/release-artifacts",
        headers=_headers(admin_headers, "same-artifact-key"),
        json=payload,
    )
    assert second.status_code == 201, second.text
    assert second.json()["id"] == first.json()["id"]

    changed = dict(payload)
    changed["name"] = "different idempotent payload"
    reuse = client.post(
        "/api/v1/release-artifacts",
        headers=_headers(admin_headers, "same-artifact-key"),
        json=changed,
    )
    assert reuse.status_code == 409

    candidate = _create_candidate(client, admin_headers, first.json()["id"], "idempotent")
    bad_version = client.post(
        f"/api/v1/release-candidates/{candidate['id']}/approvals",
        headers=_headers(admin_headers, "approval-bad-version"),
        json={
            "environment": "staging",
            "decision": "approved",
            "reason": "bad version",
            "expected_version": candidate["version"] + 100,
        },
    )
    assert bad_version.status_code == 409

    expired = client.post(
        f"/api/v1/release-candidates/{candidate['id']}/exceptions",
        headers=_headers(admin_headers, "expired-exception"),
        json={
            "gate_id": "vulnerability_policy",
            "reason": "expired exception",
            "risk": "medium",
            "scope": "staging",
            "expires_at": (datetime.now(UTC) - timedelta(hours=1)).isoformat(),
            "compensating_controls": ["manual review"],
            "approve": True,
        },
    )
    assert expired.status_code == 409

    critical_self_approve = client.post(
        f"/api/v1/release-candidates/{candidate['id']}/exceptions",
        headers=_headers(admin_headers, "critical-exception"),
        json={
            "gate_id": "vulnerability_policy",
            "reason": "critical exception",
            "risk": "critical",
            "scope": "production",
            "expires_at": (datetime.now(UTC) + timedelta(hours=1)).isoformat(),
            "compensating_controls": ["isolate environment"],
            "approve": True,
        },
    )
    assert critical_self_approve.status_code == 409


def test_p13_cross_tenant_visibility_and_audit(client, admin_headers):
    _, analyst_a_headers = make_user(client, admin_headers, "release-analyst-a", "analyst")
    _, analyst_b_headers = make_user(client, admin_headers, "release-analyst-b", "analyst")
    artifact = _create_artifact(client, analyst_a_headers, "tenant")

    hidden = client.get(f"/api/v1/release-artifacts/{artifact['id']}", headers=analyst_b_headers)
    assert hidden.status_code == 404

    services = client.app.state.services
    audit_row = services.db.fetch_one(
        "SELECT * FROM audit_logs WHERE action=? AND resource_id=?",
        ("release.artifact.register", artifact["id"]),
    )
    assert audit_row is not None
