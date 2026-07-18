from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path

from conftest import ADMIN_KEY, make_user
from fastapi.testclient import TestClient
from vulnlab.app import create_app
from vulnlab.config import Settings


def _http_plan_payload() -> dict:
    return {
        "objectives": ["Confirm approved HTTP response characteristics"],
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


def _approved_plan(
    client: TestClient, admin_headers: dict[str, str]
) -> tuple[dict, dict[str, str]]:
    _, analyst_headers = make_user(client, admin_headers, "p12-analyst", "analyst")
    scope_response = client.post(
        "/api/v1/scopes",
        headers=analyst_headers,
        json={
            "name": "p12-local-lab",
            "target_pattern": "127.0.0.1",
            "protocols": ["tcp", "http"],
            "ports": [80, 8000, 65534],
        },
    )
    assert scope_response.status_code == 201, scope_response.text
    approved_scope = client.post(
        f"/api/v1/scopes/{scope_response.json()['id']}/approve",
        headers=admin_headers,
        json={"approved": True, "reason": "P12 bounded local fixture"},
    )
    assert approved_scope.status_code == 200, approved_scope.text
    task_response = client.post(
        "/api/v1/tasks",
        headers=analyst_headers,
        json={
            "title": "P12 local resilience task",
            "target": "tcp://127.0.0.1:65534",
            "intent": "defensive_regression",
            "indicators": ["known-safe-marker"],
            "scope_id": approved_scope.json()["id"],
        },
    )
    assert task_response.status_code == 201, task_response.text
    created = client.post(
        f"/api/v1/tasks/{task_response.json()['id']}/validation-plans",
        headers=analyst_headers,
        json=_http_plan_payload(),
    )
    assert created.status_code == 201, created.text
    submitted = client.post(
        f"/api/v1/validation-plans/{created.json()['id']}/submit",
        headers=analyst_headers,
    )
    assert submitted.status_code == 200, submitted.text
    reviewed = client.post(
        f"/api/v1/validation-plans/{created.json()['id']}/review",
        headers=admin_headers,
        json={"approved": True, "reason": "P12 bounded execution"},
    )
    assert reviewed.status_code == 200, reviewed.text
    return reviewed.json(), analyst_headers


def _create_local_lab_execution(
    client: TestClient,
    plan_id: str,
    headers: dict[str, str],
    key: str,
) -> dict:
    response = client.post(
        f"/api/v1/validation-plans/{plan_id}/executions",
        headers={**headers, "Idempotency-Key": key},
        json={"template_id": "local.training-lab"},
    )
    assert response.status_code == 202, response.text
    return response.json()


def test_p12_system_resilience_snapshot_and_worker_heartbeat(client, admin_headers):
    services = client.app.state.services
    services.operations.record_worker_heartbeat(
        tenant_id="system",
        worker_id="worker-a",
        active_executions=0,
        sandbox_capacity=3,
        metadata={"pod": "validation-worker-0"},
    )

    live = client.get("/live")
    assert live.status_code == 200
    ready = client.get("/ready")
    assert ready.status_code == 200
    response = client.get("/api/v1/system/resilience", headers=admin_headers)

    assert response.status_code == 200, response.text
    body = response.json()
    assert body["version"] == "2.12.0-p12"
    assert body["capacity"]["global_concurrency_limit"] >= 1
    assert body["queue"]["dead_letter"] == 0
    assert "worker-a" in {item["worker_id"] for item in body["workers"]}
    assert "no arbitrary shell or command execution" in body["boundaries"]


def test_p12_three_workers_are_effectively_once_and_do_not_duplicate_evidence(
    client,
    admin_headers,
):
    plan, _ = _approved_plan(client, admin_headers)
    execution = _create_local_lab_execution(client, plan["id"], admin_headers, "p12-effective-once")
    services = client.app.state.services
    for index in range(3):
        services.operations.record_worker_heartbeat(
            tenant_id="system",
            worker_id=f"worker-{index}",
            active_executions=0,
            sandbox_capacity=1,
        )

    first = services.validation_execution.run_worker_once("worker-0")
    assert first is not None
    assert first["status"] == "SUCCEEDED"

    queue_id = execution["queue_message_id"]
    services.db.execute(
        """UPDATE validation_queue_messages
           SET status='ready',available_at=?,published_at=NULL WHERE id=?""",
        (execution["created_at"], queue_id),
    )
    duplicate = services.validation_execution.run_worker_once("worker-1")
    assert duplicate is not None
    assert duplicate["id"] == execution["id"]
    assert duplicate["status"] == "SUCCEEDED"
    assert services.validation_execution.run_worker_once("worker-2") is None

    evidence_rows = services.db.fetch_all(
        "SELECT * FROM validation_execution_evidence WHERE execution_id=?",
        (execution["id"],),
    )
    assert len(evidence_rows) == 1
    assert services.operations.queue_summary()["by_status"]["done"]["count"] == 1


def test_p12_tenant_quota_and_queue_saturation_are_distinct(settings: Settings):
    quota_settings = replace(
        settings,
        db_path=settings.db_path.with_name("p12-quota.db"),
        p12_tenant_concurrency_limit=1,
        p12_project_concurrency_limit=10,
        p12_global_concurrency_limit=10,
        p12_queue_depth_threshold=100,
    )
    with TestClient(create_app(quota_settings)) as quota_client:
        admin_headers = {"X-API-Key": ADMIN_KEY}
        plan, _ = _approved_plan(quota_client, admin_headers)
        _create_local_lab_execution(quota_client, plan["id"], admin_headers, "p12-quota-1")
        blocked = quota_client.post(
            f"/api/v1/validation-plans/{plan['id']}/executions",
            headers={**admin_headers, "Idempotency-Key": "p12-quota-2"},
            json={"template_id": "local.training-lab"},
        )
        assert blocked.status_code == 429, blocked.text
        assert blocked.json()["code"] == "quota_exceeded"

    saturated_settings = replace(
        settings,
        db_path=settings.db_path.with_name("p12-saturated.db"),
        p12_tenant_concurrency_limit=10,
        p12_project_concurrency_limit=10,
        p12_global_concurrency_limit=10,
        p12_queue_depth_threshold=1,
    )
    with TestClient(create_app(saturated_settings)) as saturated_client:
        admin_headers = {"X-API-Key": ADMIN_KEY}
        plan, _ = _approved_plan(saturated_client, admin_headers)
        _create_local_lab_execution(saturated_client, plan["id"], admin_headers, "p12-saturated-1")
        blocked = saturated_client.post(
            f"/api/v1/validation-plans/{plan['id']}/executions",
            headers={**admin_headers, "Idempotency-Key": "p12-saturated-2"},
            json={"template_id": "local.training-lab"},
        )
        assert blocked.status_code == 503, blocked.text
        assert blocked.json()["code"] == "queue_saturated"


def test_p12_dead_letter_preserves_attempt_and_last_error(client, admin_headers):
    plan, _ = _approved_plan(client, admin_headers)
    execution = _create_local_lab_execution(client, plan["id"], admin_headers, "p12-dead-letter")
    services = client.app.state.services
    services.db.execute(
        """UPDATE validation_queue_messages
           SET schema_version=999,max_attempts=1 WHERE id=?""",
        (execution["queue_message_id"],),
    )

    result = services.validation_execution.run_worker_once("worker-dead-letter")

    assert result is not None
    assert result["status"] == "SANDBOX_FAILED"
    queue_row = services.db.fetch_one(
        "SELECT * FROM validation_queue_messages WHERE id=?",
        (execution["queue_message_id"],),
    )
    assert queue_row is not None
    assert queue_row["status"] == "dead"
    assert int(queue_row["attempt"]) == 1
    assert "unsupported validation queue message schema version" in queue_row["last_error"]


def test_p12_evidence_consistency_reports_missing_object(client, admin_headers):
    plan, analyst_headers = _approved_plan(client, admin_headers)
    execution = _create_local_lab_execution(
        client,
        plan["id"],
        admin_headers,
        "p12-evidence-consistency",
    )
    services = client.app.state.services
    result = services.validation_execution.run_worker_once("worker-evidence")
    assert result is not None
    assert result["status"] == "SUCCEEDED"

    healthy = client.post(
        "/api/v1/system/resilience/evidence-consistency/check",
        headers=analyst_headers,
        json={"repair": False, "repair_action": "none"},
    )
    assert healthy.status_code == 200, healthy.text
    assert healthy.json()["status"] == "healthy"

    row = services.db.fetch_one(
        "SELECT * FROM validation_execution_evidence WHERE execution_id=?",
        (execution["id"],),
    )
    assert row is not None
    metadata = json.loads(row["metadata_json"])
    artifact_path = Path(metadata["local_artifact_path"])
    artifact_path.unlink()

    inconsistent = client.post(
        "/api/v1/system/resilience/evidence-consistency/check",
        headers=analyst_headers,
        json={"repair": False, "repair_action": "none"},
    )
    assert inconsistent.status_code == 200, inconsistent.text
    body = inconsistent.json()
    assert body["status"] == "inconsistent"
    assert body["summary"]["missing_object"] == 1
    assert any(item["status"] == "missing_object" for item in body["findings"])
