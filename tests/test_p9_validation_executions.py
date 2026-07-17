from __future__ import annotations

import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class _Handler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802 - stdlib callback name
        body = b"known-safe-marker"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args: object) -> None:
        return


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


def _approved_http_plan(client, admin_headers, analyst, pending_task) -> dict:
    _, analyst_headers = analyst
    created = client.post(
        f"/api/v1/tasks/{pending_task['id']}/validation-plans",
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
        json={"approved": True, "reason": "bounded P9 HTTP validation"},
    )
    assert reviewed.status_code == 200, reviewed.text
    return reviewed.json()


def test_p9_http_validation_execution_closes_loop(
    client,
    admin_headers,
    analyst,
    pending_task,
):
    server = ThreadingHTTPServer(("127.0.0.1", 65534), _Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        plan = _approved_http_plan(client, admin_headers, analyst, pending_task)
        created = client.post(
            f"/api/v1/validation-plans/{plan['id']}/executions",
            headers={**admin_headers, "Idempotency-Key": "p9-http-loop"},
            json={"template_id": "http.response"},
        )
        assert created.status_code == 202, created.text
        execution = created.json()
        assert execution["status"] == "QUEUED"
        assert execution["trace_id"]
        assert execution["sandbox_id"].startswith("vlsbx-")
        assert execution["approval_id"].startswith("validation-plan:")
        assert execution["policy_decision_id"]

        services = client.app.state.services
        worker_result = services.validation_execution.run_worker_once("pytest-worker")
        assert worker_result is not None
        assert worker_result["id"] == execution["id"]
        assert worker_result["status"] == "SUCCEEDED"
        assert worker_result["result"]["matched"] is True

        fetched = client.get(
            f"/api/v1/validation-executions/{execution['id']}",
            headers=admin_headers,
        )
        assert fetched.status_code == 200
        assert fetched.json()["status"] == "SUCCEEDED"

        events = client.get(
            f"/api/v1/validation-executions/{execution['id']}/events",
            headers=admin_headers,
        )
        assert events.status_code == 200
        event_types = [item["event_type"] for item in events.json()]
        assert "validation_execution.queued" in event_types
        assert "validation_execution.completed" in event_types

        evidence = client.get(
            f"/api/v1/validation-executions/{execution['id']}/evidence",
            headers=admin_headers,
        )
        assert evidence.status_code == 200
        items = evidence.json()
        assert len(items) == 1
        assert items[0]["artifact_ref"].startswith("minio://validation-evidence/")
        assert len(items[0]["content_sha256"]) == 64

        reviewed = client.post(
            f"/api/v1/validation-executions/{execution['id']}/reviews",
            headers=admin_headers,
            json={"accepted": True, "reason": "evidence is complete"},
        )
        assert reviewed.status_code == 200, reviewed.text
        assert reviewed.json()["review_decision"] == "accepted"
    finally:
        server.shutdown()
        server.server_close()


def test_p9_create_execution_requires_approved_plan(client, admin_headers, analyst, pending_task):
    _, analyst_headers = analyst
    created = client.post(
        f"/api/v1/tasks/{pending_task['id']}/validation-plans",
        headers=analyst_headers,
        json=_http_plan_payload(),
    )
    assert created.status_code == 201
    response = client.post(
        f"/api/v1/validation-plans/{created.json()['id']}/executions",
        headers={**admin_headers, "Idempotency-Key": "p9-unapproved"},
        json={"template_id": "http.response"},
    )
    assert response.status_code == 409
    assert "approved" in response.json()["detail"]


def test_p9_duplicate_idempotency_key_does_not_duplicate_execution(
    client,
    admin_headers,
    analyst,
    pending_task,
):
    plan = _approved_http_plan(client, admin_headers, analyst, pending_task)
    headers = {**admin_headers, "Idempotency-Key": "p9-idempotent"}
    first = client.post(
        f"/api/v1/validation-plans/{plan['id']}/executions",
        headers=headers,
        json={"template_id": "http.response"},
    )
    second = client.post(
        f"/api/v1/validation-plans/{plan['id']}/executions",
        headers=headers,
        json={"template_id": "http.response"},
    )
    assert first.status_code == 202, first.text
    assert second.status_code == 202, second.text
    assert first.json()["id"] == second.json()["id"]
    rows = client.app.state.services.db.fetch_all("SELECT * FROM validation_executions")
    assert len(rows) == 1


def test_p9_worker_rejects_revoked_approval(client, admin_headers, analyst, pending_task):
    plan = _approved_http_plan(client, admin_headers, analyst, pending_task)
    created = client.post(
        f"/api/v1/validation-plans/{plan['id']}/executions",
        headers={**admin_headers, "Idempotency-Key": "p9-revoked"},
        json={"template_id": "http.response"},
    )
    assert created.status_code == 202
    client.app.state.services.db.execute(
        "UPDATE validation_plans SET status='revoked' WHERE id=?",
        (plan["id"],),
    )
    result = client.app.state.services.validation_execution.run_worker_once("pytest-worker")
    assert result is not None
    assert result["status"] == "APPROVAL_REVOKED"


def test_p9_cross_tenant_execution_is_not_visible(
    client,
    admin_headers,
    analyst,
    pending_task,
):
    plan = _approved_http_plan(client, admin_headers, analyst, pending_task)
    created = client.post(
        f"/api/v1/validation-plans/{plan['id']}/executions",
        headers={**admin_headers, "Idempotency-Key": "p9-cross-tenant"},
        json={"template_id": "http.response"},
    )
    assert created.status_code == 202

    other = client.post(
        "/api/v1/users",
        headers=admin_headers,
        json={"username": "other-analyst", "role": "analyst"},
    )
    assert other.status_code == 201
    other_headers = {"X-API-Key": other.json()["api_key"]}
    response = client.get(
        f"/api/v1/validation-executions/{created.json()['id']}",
        headers=other_headers,
    )
    assert response.status_code == 404


def test_p9_unknown_template_and_arbitrary_shell_are_rejected(
    client,
    admin_headers,
    analyst,
    pending_task,
):
    plan = _approved_http_plan(client, admin_headers, analyst, pending_task)
    unknown = client.post(
        f"/api/v1/validation-plans/{plan['id']}/executions",
        headers={**admin_headers, "Idempotency-Key": "p9-unknown-template"},
        json={"template_id": "shell.arbitrary"},
    )
    assert unknown.status_code == 400

    arbitrary_shell = client.post(
        f"/api/v1/validation-plans/{plan['id']}/executions",
        headers={**admin_headers, "Idempotency-Key": "p9-arbitrary-shell"},
        json={"template_id": "http.response", "argv": ["sh", "-c", "id"]},
    )
    assert arbitrary_shell.status_code == 422

    templates = client.get("/api/v1/validation-templates", headers=admin_headers)
    assert templates.status_code == 200
    assert {item["id"] for item in templates.json()} == {
        "http.response",
        "sbom.dependency-version",
        "local.training-lab",
    }


def test_p9_sbom_and_fixed_training_lab_templates_execute_without_shell(
    client,
    admin_headers,
    analyst,
    pending_task,
):
    plan = _approved_http_plan(client, admin_headers, analyst, pending_task)
    for index, template_id in enumerate(("sbom.dependency-version", "local.training-lab")):
        created = client.post(
            f"/api/v1/validation-plans/{plan['id']}/executions",
            headers={**admin_headers, "Idempotency-Key": f"p9-template-{index}"},
            json={"template_id": template_id},
        )
        assert created.status_code == 202, created.text
        result = client.app.state.services.validation_execution.run_worker_once("pytest-worker")
        assert result is not None
        assert result["status"] == "SUCCEEDED"
        assert result["template_id"] == template_id
        assert result["result"]["observed"]["non_executing"] is True
        assert result["result"]["assertions"]

        evidence = client.get(
            f"/api/v1/validation-executions/{result['id']}/evidence",
            headers=admin_headers,
        )
        assert evidence.status_code == 200
        assert len(evidence.json()) == 1
