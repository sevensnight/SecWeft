from __future__ import annotations


def _plan_payload(port: int = 65534) -> dict:
    return {
        "objectives": ["Confirm authorized defensive reachability only"],
        "steps": [
            {
                "kind": "tcp_connect",
                "host": "127.0.0.1",
                "port": port,
            }
        ],
        "rollback": ["No state change performed"],
    }


def test_p6_validation_plan_create_submit_and_review(client, admin_headers, analyst, pending_task):
    _, analyst_headers = analyst
    task_id = pending_task["id"]
    created = client.post(
        f"/api/v1/tasks/{task_id}/validation-plans",
        headers=analyst_headers,
        json=_plan_payload(),
    )
    assert created.status_code == 201, created.text
    plan = created.json()
    assert plan["status"] == "draft"
    assert plan["plan"]["destructive"] is False
    assert len(plan["plan_hash"]) == 64
    assert plan["policy_decision_ids"]

    listed = client.get(f"/api/v1/tasks/{task_id}/validation-plans", headers=analyst_headers)
    assert listed.status_code == 200
    assert listed.json()[0]["id"] == plan["id"]

    submitted = client.post(
        f"/api/v1/validation-plans/{plan['id']}/submit",
        headers=analyst_headers,
    )
    assert submitted.status_code == 200, submitted.text
    assert submitted.json()["status"] == "submitted"

    reviewed = client.post(
        f"/api/v1/validation-plans/{plan['id']}/review",
        headers=admin_headers,
        json={"approved": True, "reason": "bounded non-destructive plan"},
    )
    assert reviewed.status_code == 200, reviewed.text
    assert reviewed.json()["status"] == "approved"
    assert reviewed.json()["review_reason"] == "bounded non-destructive plan"

    runs = client.get(f"/api/v1/tasks/{task_id}/executions", headers=admin_headers)
    assert runs.status_code == 200
    assert runs.json() == []


def test_p6_validation_plan_rejects_out_of_scope_step(client, analyst, pending_task):
    _, analyst_headers = analyst
    response = client.post(
        f"/api/v1/tasks/{pending_task['id']}/validation-plans",
        headers=analyst_headers,
        json=_plan_payload(port=22),
    )
    assert response.status_code == 403
    assert "validation plan step denied" in response.json()["detail"]


def test_p6_validation_plan_review_requires_admin(client, analyst, pending_task):
    _, analyst_headers = analyst
    created = client.post(
        f"/api/v1/tasks/{pending_task['id']}/validation-plans",
        headers=analyst_headers,
        json=_plan_payload(),
    )
    assert created.status_code == 201
    plan_id = created.json()["id"]
    submitted = client.post(
        f"/api/v1/validation-plans/{plan_id}/submit",
        headers=analyst_headers,
    )
    assert submitted.status_code == 200
    reviewed = client.post(
        f"/api/v1/validation-plans/{plan_id}/review",
        headers=analyst_headers,
        json={"approved": True, "reason": "should require admin"},
    )
    assert reviewed.status_code == 403
