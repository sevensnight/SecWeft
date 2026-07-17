from __future__ import annotations

from dataclasses import replace

from conftest import ADMIN_KEY
from fastapi.testclient import TestClient
from vulnlab.app import create_app


def test_p5_policy_evaluation_denies_destructive_actions(client, admin_headers):
    response = client.post(
        "/api/v1/policies/evaluate",
        headers=admin_headers,
        json={
            "action": "task.execute",
            "resource_type": "task",
            "resource_id": "synthetic-task",
            "destructive": True,
            "reason": "negative policy fixture",
        },
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["decision"] == "deny"
    assert "destructive" in body["reason"]
    assert len(body["policy_hash"]) == 64


def test_p5_policy_requires_approval_for_unapproved_task(client, admin_headers, pending_task):
    response = client.post(
        "/api/v1/policies/evaluate",
        headers=admin_headers,
        json={
            "action": "task.execute",
            "resource_type": "task",
            "resource_id": pending_task["id"],
            "task_id": pending_task["id"],
        },
    )
    assert response.status_code == 200, response.text
    assert response.json()["decision"] == "requires_approval"


def test_p5_legacy_disabled_execution_records_policy_decisions(settings):
    app = create_app(replace(settings, legacy_execution_enabled=False))
    headers = {"X-API-Key": ADMIN_KEY}
    with TestClient(app) as client:
        probe = client.post(
            "/api/v1/assets/probe",
            headers=headers,
            json={
                "target": "tcp://127.0.0.1:80",
                "scope_id": "00000000-0000-0000-0000-000000000000",
                "ports": [80],
            },
        )
        sandbox = client.post(
            "/api/v1/sandbox/runs",
            headers=headers,
            json={"argv": ["python", "--version"]},
        )
        assert probe.status_code == 503
        assert sandbox.status_code == 503
        rows = app.state.services.db.fetch_all(
            "SELECT action, decision, reason FROM policy_decisions ORDER BY created_at, id"
        )
    assert [row["action"] for row in rows] == ["asset.probe", "sandbox.run"]
    assert {row["decision"] for row in rows} == {"deny"}
    assert all("legacy execution capability is disabled" in row["reason"] for row in rows)


def test_p5_policy_pep_blocks_sandbox_shell_metacharacters(client, admin_headers):
    response = client.post(
        "/api/v1/sandbox/runs",
        headers=admin_headers,
        json={"argv": ["python", "--version;whoami"]},
    )
    assert response.status_code == 403
    assert "policy decision deny" in response.json()["detail"]
