#!/usr/bin/env python3
"""Deterministic P14 enterprise end-to-end acceptance scenario."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import sys
import tempfile
from datetime import UTC, datetime
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
SHA_A = "a" * 64
SHA_B = "b" * 64
SHA_C = "c" * 64
SHA_D = "d" * 64
SHA_E = "e" * 64
SHA_F = "f" * 64


def _master_key() -> str:
    return base64.urlsafe_b64encode(hashlib.sha256(b"p14-e2e-master-key").digest()).decode()


def _settings(tmp: Path) -> Settings:
    return Settings(
        env="test",
        db_path=tmp / "p14-e2e.db",
        workspace_root=tmp / "workspaces",
        admin_key=ADMIN_KEY,
        master_key=_master_key(),
        execution_mode="dry_run",
        allowed_hosts=("localhost", "127.0.0.1", "::1"),
        allowed_ports=(80, 8000, 65534),
        allow_private_networks=False,
        max_concurrency=2,
        legacy_execution_enabled=True,
    )


def _assert(response: Any, expected: int, label: str) -> dict[str, Any]:
    if response.status_code != expected:
        raise RuntimeError(
            f"{label} expected {expected}, got {response.status_code}: {response.text}"
        )
    return response.json()


def _headers(key: str) -> dict[str, str]:
    return {"X-API-Key": ADMIN_KEY, "Idempotency-Key": key}


def _http_plan_payload() -> dict[str, Any]:
    return {
        "objectives": ["Confirm approved local training validation can be traced"],
        "steps": [
            {
                "kind": "http_request",
                "host": "127.0.0.1",
                "port": 65534,
                "method": "GET",
                "path": "/health",
                "expected_status": [200],
                "body_pattern": "known-safe-marker",
            }
        ],
        "rollback": ["No target state is changed"],
    }


def _release_artifact_payload() -> dict[str, Any]:
    image_digest = f"registry.local/vulnlab/control-plane@sha256:{SHA_A}"
    return {
        "tenant_id": "system",
        "project_id": "project-alpha",
        "name": "P14 E2E artifact",
        "artifact_type": "container",
        "digest": image_digest,
        "repository": "registry.local/vulnlab/control-plane",
        "source_commit": SHA_B[:40],
        "metadata": {"scenario": "p14-e2e"},
        "sbom": {
            "format": "CycloneDX",
            "generator": "solve_p14_e2e",
            "generated_at": datetime.now(UTC).isoformat(),
            "artifact_digest": image_digest,
            "document_digest": f"sha256:{SHA_C}",
            "component_count": 42,
            "license_summary": {"MIT": 20, "Apache-2.0": 22},
            "vulnerability_summary": {"critical": 0, "high": 0},
            "document_ref": "sbom://p14/e2e",
        },
        "provenance": {
            "subject_digest": image_digest,
            "source_repository": "https://github.com/example/vulnlab",
            "source_commit": SHA_B[:40],
            "builder_workflow": ".github/workflows/ci.yml",
            "statement_digest": f"sha256:{SHA_D}",
            "predicate_type": "https://slsa.dev/provenance/v1",
            "verified": True,
            "metadata": {"scenario": "p14-e2e"},
        },
        "signature": {
            "signature_digest": f"sha256:{SHA_E}",
            "signature_identity": "https://github.com/example/vulnlab/.github/workflows/ci.yml@refs/heads/main",
            "certificate_issuer": "https://token.actions.githubusercontent.com",
            "verified": True,
        },
        "security_scan": {
            "scanner": "trivy",
            "severity_summary": {"critical": 0, "high": 0},
            "critical_count": 0,
            "high_count": 0,
            "unresolved_critical": False,
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


def run() -> dict[str, Any]:
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)
        app = create_app(_settings(tmp))
        with TestClient(app) as client:
            admin = {"X-API-Key": ADMIN_KEY}
            analyst = _assert(
                client.post(
                    "/api/v1/users",
                    headers=admin,
                    json={"username": "p14-e2e-analyst", "role": "analyst"},
                ),
                201,
                "create analyst",
            )
            analyst_headers = {"X-API-Key": analyst["api_key"]}
            scope = _assert(
                client.post(
                    "/api/v1/scopes",
                    headers=analyst_headers,
                    json={
                        "name": "p14-e2e-local-lab",
                        "target_pattern": "127.0.0.1",
                        "protocols": ["tcp", "http"],
                        "ports": [80, 8000, 65534],
                    },
                ),
                201,
                "create scope",
            )
            approved_scope = _assert(
                client.post(
                    f"/api/v1/scopes/{scope['id']}/approve",
                    headers=admin,
                    json={"approved": True, "reason": "P14 deterministic local scope"},
                ),
                200,
                "approve scope",
            )
            task = _assert(
                client.post(
                    "/api/v1/tasks",
                    headers=analyst_headers,
                    json={
                        "title": "P14 deterministic local validation",
                        "target": "tcp://127.0.0.1:65534",
                        "intent": "defensive_regression",
                        "indicators": ["known-safe-marker"],
                        "scope_id": approved_scope["id"],
                    },
                ),
                201,
                "create task",
            )
            plan = _assert(
                client.post(
                    f"/api/v1/tasks/{task['id']}/validation-plans",
                    headers=analyst_headers,
                    json=_http_plan_payload(),
                ),
                201,
                "create validation plan",
            )
            _assert(
                client.post(
                    f"/api/v1/validation-plans/{plan['id']}/submit", headers=analyst_headers
                ),
                200,
                "submit validation plan",
            )
            reviewed_plan = _assert(
                client.post(
                    f"/api/v1/validation-plans/{plan['id']}/review",
                    headers=admin,
                    json={"approved": True, "reason": "P14 E2E bounded plan"},
                ),
                200,
                "approve validation plan",
            )
            execution = _assert(
                client.post(
                    f"/api/v1/validation-plans/{reviewed_plan['id']}/executions",
                    headers=_headers("p14-e2e-execution"),
                    json={"template_id": "local.training-lab"},
                ),
                202,
                "create validation execution",
            )
            worker_result = client.app.state.services.validation_execution.run_worker_once(
                "p14-e2e-worker"
            )
            if worker_result is None or worker_result["status"] != "SUCCEEDED":
                raise RuntimeError(f"worker did not complete execution: {worker_result}")
            _assert(
                client.post(
                    f"/api/v1/validation-executions/{worker_result['id']}/reviews",
                    headers=admin,
                    json={"accepted": True, "reason": "P14 E2E evidence accepted"},
                ),
                200,
                "review execution",
            )
            evidence = _assert(
                client.get(
                    f"/api/v1/validation-executions/{worker_result['id']}/evidence", headers=admin
                ),
                200,
                "list evidence",
            )
            case = _assert(
                client.post(
                    "/api/v1/vulnerability-cases",
                    headers={**analyst_headers, "Idempotency-Key": "p14-e2e-case"},
                    json={
                        "title": "P14 E2E synthetic finding",
                        "summary": "The controlled local training lab produced accepted evidence.",
                        "severity": "medium",
                        "project_id": "project-alpha",
                        "source": "VALIDATION",
                        "metadata": {"validation_execution_id": worker_result["id"]},
                    },
                ),
                201,
                "create case",
            )
            artifact = _assert(
                client.post(
                    "/api/v1/release-artifacts",
                    headers=_headers("p14-e2e-artifact"),
                    json=_release_artifact_payload(),
                ),
                201,
                "register release artifact",
            )
            candidate = _assert(
                client.post(
                    "/api/v1/release-candidates",
                    headers=_headers("p14-e2e-candidate"),
                    json={
                        "tenant_id": "system",
                        "project_id": "project-alpha",
                        "name": "P14 E2E release candidate",
                        "artifact_id": artifact["id"],
                        "configuration_hash": SHA_B,
                        "migration_set": ["0001-0014"],
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
                                "status": "READINESS_COMPLETE",
                                "runtime": False,
                                "runtime_not_claimed": True,
                            },
                        },
                    },
                ),
                201,
                "create release candidate",
            )
            gates = _assert(
                client.post(
                    f"/api/v1/release-candidates/{candidate['id']}/evaluate",
                    headers=_headers("p14-e2e-gates"),
                    json={"environment": "staging"},
                ),
                200,
                "evaluate release gates",
            )
            release_compliance = _assert(
                client.post(
                    f"/api/v1/release-candidates/{candidate['id']}/compliance-package",
                    headers=_headers("p14-e2e-release-compliance"),
                ),
                201,
                "generate release compliance",
            )
            acceptance = _assert(
                client.post(
                    "/api/v1/acceptance/runs",
                    headers=_headers("p14-e2e-acceptance"),
                    json={
                        "tenant_id": "system",
                        "project_id": "project-alpha",
                        "scenario_id": "p14-final-enterprise-acceptance",
                        "trace_id": execution["trace_id"],
                    },
                ),
                202,
                "run P14 acceptance",
            )
            delivery = _assert(
                client.post(
                    "/api/v1/delivery-packages",
                    headers=_headers("p14-e2e-delivery"),
                    json={
                        "tenant_id": "system",
                        "project_id": "project-alpha",
                        "package_type": "candidate",
                    },
                ),
                202,
                "generate delivery package",
            )
            p14_compliance = _assert(
                client.post(
                    "/api/v1/compliance/evidence-packages",
                    headers=_headers("p14-e2e-p14-compliance"),
                    json={"tenant_id": "system", "project_id": "project-alpha", "frameworks": []},
                ),
                202,
                "generate P14 compliance package",
            )
            readiness = _assert(
                client.get("/api/v1/readiness/production", headers=admin),
                200,
                "get production readiness",
            )
            audit_valid = bool(client.app.state.services.audit.verify()["valid"])

        steps = {
            "tenant_user_rbac": analyst["id"],
            "authorized_scope": approved_scope["id"],
            "task": task["id"],
            "validation_plan": reviewed_plan["id"],
            "p9_execution": worker_result["id"],
            "evidence": evidence[0]["id"] if evidence else None,
            "p10_case": case["id"],
            "p13_artifact": artifact["id"],
            "p13_candidate": candidate["id"],
            "p13_gates": [gate["gate_id"] for gate in gates],
            "p13_compliance_package": release_compliance["id"],
            "p14_acceptance_run": acceptance["id"],
            "p14_delivery_package": delivery["id"],
            "p14_compliance_package": p14_compliance["id"],
        }
        return {
            "phase": "P14-final-e2e",
            "version": "2.14.0-p14",
            "valid": audit_valid
            and readiness["production_ready"] is False
            and readiness["runtime_not_claimed"] is True,
            "failed": 0
            if audit_valid
            and readiness["production_ready"] is False
            and readiness["runtime_not_claimed"] is True
            else 1,
            "skipped": 0,
            "runtime": False,
            "runtime_not_claimed": True,
            "trace_chain": {
                "trace_id": execution["trace_id"],
                "execution_id": worker_result["id"],
                "acceptance_run_id": acceptance["id"],
                "delivery_package_id": delivery["id"],
                "policy_decision_id": acceptance["policy_decision_id"],
            },
            "steps": steps,
            "production_ready": readiness["production_ready"],
            "failed_critical_gates": readiness["failed_critical_gates"],
            "audit_valid": audit_valid,
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
