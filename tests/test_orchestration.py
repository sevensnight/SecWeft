from __future__ import annotations

import asyncio

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
