from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta

import pytest
from conftest import ADMIN_KEY
from vulnlab.orchestrator import TaskStateError


@pytest.mark.asyncio
async def test_simultaneous_task_start_has_one_execution_side_effect(
    client, app, admin_headers, pending_task, monkeypatch
):
    approved = client.post(
        f"/api/v1/tasks/{pending_task['id']}/approve",
        headers=admin_headers,
        json={"approved": True, "reason": "concurrency regression fixture"},
    )
    assert approved.status_code == 200
    calls = 0

    async def fake_probe(target: str, scope_id: str, ports: list[int], timeout: float):
        nonlocal calls
        calls += 1
        await asyncio.sleep(0.02)
        return {
            "target": target,
            "results": [{"port": ports[0], "status": "open", "resolved_addresses": ["127.0.0.1"]}],
            "non_destructive": True,
        }

    monkeypatch.setattr(app.state.services.scope, "probe", fake_probe)
    principal = app.state.services.security.authenticate(ADMIN_KEY)
    first, second = await asyncio.gather(
        app.state.services.orchestrator.run(principal, pending_task["id"]),
        app.state.services.orchestrator.run(principal, pending_task["id"]),
        return_exceptions=True,
    )
    outcomes = (first, second)
    assert sum(isinstance(item, TaskStateError) for item in outcomes) == 1
    assert sum(isinstance(item, dict) and item["status"] == "succeeded" for item in outcomes) == 1
    assert calls == 1


def test_p3_dispatch_is_idempotent_and_worker_records_execution(
    client, app, admin_headers, pending_task
):
    approved = client.post(
        f"/api/v1/tasks/{pending_task['id']}/approve",
        headers=admin_headers,
        json={"approved": True, "reason": "p3 dispatch fixture"},
    )
    assert approved.status_code == 200

    headers = {**admin_headers, "Idempotency-Key": "dispatch-once"}
    first = client.post(f"/api/v1/tasks/{pending_task['id']}/executions", headers=headers)
    second = client.post(f"/api/v1/tasks/{pending_task['id']}/executions", headers=headers)

    assert first.status_code == 202, first.text
    assert second.status_code == 202, second.text
    assert first.json()["status"] == "queued"
    assert second.json()["id"] == first.json()["id"]
    queue_count = app.state.services.db.fetch_one(
        "SELECT COUNT(*) AS count FROM task_queue_messages WHERE task_id=?",
        (pending_task["id"],),
    )
    assert queue_count["count"] == 1

    principal = app.state.services.security.authenticate(ADMIN_KEY)
    result = asyncio.run(app.state.services.orchestrator.run(principal, pending_task["id"]))
    assert result["status"] == "succeeded"
    assert all(stage["status"] == "succeeded" for stage in result["stages"])
    executions = client.get(f"/api/v1/tasks/{pending_task['id']}/executions", headers=admin_headers)
    assert executions.status_code == 200
    assert executions.json()[0]["status"] == "succeeded"


def test_p3_pause_resume_uses_persisted_state(client, app, admin_headers, pending_task):
    client.post(
        f"/api/v1/tasks/{pending_task['id']}/approve",
        headers=admin_headers,
        json={"approved": True, "reason": "pause resume fixture"},
    )
    queued = client.post(
        f"/api/v1/tasks/{pending_task['id']}/executions",
        headers={**admin_headers, "Idempotency-Key": "pause-resume"},
    )
    assert queued.status_code == 202
    paused = client.post(
        f"/api/v1/tasks/{pending_task['id']}/pause",
        headers=admin_headers,
        json={"reason": "operator hold"},
    )
    assert paused.status_code == 200
    assert paused.json()["status"] == "paused"
    resumed = client.post(
        f"/api/v1/tasks/{pending_task['id']}/resume",
        headers=admin_headers,
        json={"reason": "operator resume"},
    )
    assert resumed.status_code == 200
    assert resumed.json()["status"] == "queued"

    principal = app.state.services.security.authenticate(ADMIN_KEY)
    result = asyncio.run(app.state.services.orchestrator.run(principal, pending_task["id"]))
    assert result["status"] == "succeeded"


def test_p3_stale_worker_lease_recovers_to_queue(client, app, admin_headers, pending_task):
    client.post(
        f"/api/v1/tasks/{pending_task['id']}/approve",
        headers=admin_headers,
        json={"approved": True, "reason": "lease recovery fixture"},
    )
    client.post(
        f"/api/v1/tasks/{pending_task['id']}/executions",
        headers={**admin_headers, "Idempotency-Key": "lease-recovery"},
    )
    expired = (datetime.now(UTC) - timedelta(seconds=5)).isoformat()
    app.state.services.db.execute(
        """UPDATE tasks SET status='running',lease_owner='dead-worker',
           lease_token='dead-token',lease_expires_at=? WHERE id=?""",
        (expired, pending_task["id"]),
    )
    app.state.services.db.execute(
        """UPDATE task_queue_messages SET status='leased',locked_by='dead-worker',
           lock_token='dead-token',locked_until=? WHERE task_id=?""",
        (expired, pending_task["id"]),
    )

    recovered = app.state.services.orchestrator.recover_stale_leases()

    assert recovered == {"recovered": 1}
    assert app.state.services.orchestrator.get(pending_task["id"])["status"] == "queued"
    principal = app.state.services.security.authenticate(ADMIN_KEY)
    result = asyncio.run(app.state.services.orchestrator.run(principal, pending_task["id"]))
    assert result["status"] == "succeeded"


def test_p3_failed_queue_message_goes_to_dlq_and_retry_succeeds(
    client, app, admin_headers, pending_task, monkeypatch
):
    client.post(
        f"/api/v1/tasks/{pending_task['id']}/approve",
        headers=admin_headers,
        json={"approved": True, "reason": "dlq retry fixture"},
    )
    client.post(
        f"/api/v1/tasks/{pending_task['id']}/executions",
        headers={**admin_headers, "Idempotency-Key": "dlq-retry"},
    )

    async def broken_probe(target: str, scope_id: str, ports: list[int], timeout: float):
        raise RuntimeError("synthetic probe transport failed")

    monkeypatch.setattr(app.state.services.scope, "probe", broken_probe)
    principal = app.state.services.security.authenticate(ADMIN_KEY)
    failed = asyncio.run(app.state.services.orchestrator.run(principal, pending_task["id"]))
    assert failed["status"] == "failed"
    assert app.state.services.orchestrator.dead_letters(10)[0]["task_id"] == pending_task["id"]

    async def fixed_probe(target: str, scope_id: str, ports: list[int], timeout: float):
        return {
            "target": target,
            "results": [{"port": ports[0], "status": "open", "resolved_addresses": ["127.0.0.1"]}],
            "non_destructive": True,
        }

    monkeypatch.setattr(app.state.services.scope, "probe", fixed_probe)
    retried = client.post(
        f"/api/v1/tasks/{pending_task['id']}/retry",
        headers=admin_headers,
        json={"reason": "transient transport fixed"},
    )
    assert retried.status_code == 200, retried.text
    assert retried.json()["status"] == "queued"
    succeeded = asyncio.run(app.state.services.orchestrator.run(principal, pending_task["id"]))
    assert succeeded["status"] == "succeeded"
