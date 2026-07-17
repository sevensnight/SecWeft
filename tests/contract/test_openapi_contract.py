from __future__ import annotations

import uuid
from dataclasses import replace

from conftest import ADMIN_KEY
from fastapi.testclient import TestClient
from vulnlab.app import create_app

from tools.contracts.openapi_snapshot import (
    SNAPSHOT_PATH,
    build_snapshot,
    check,
    load_document,
    load_snapshot,
    validate_document,
)


def test_checked_in_openapi_matches_reviewed_semantic_snapshot() -> None:
    document = load_document()
    assert SNAPSHOT_PATH.is_file()
    assert load_snapshot() == build_snapshot(document)


def test_checked_in_p1_operations_exist_in_runtime() -> None:
    result = check(runtime=True)
    assert result["valid"], result["errors"]
    assert result["operation_count"] == 56


def test_sse_contract_is_resumable_and_uses_event_stream_media_type() -> None:
    document = load_document()
    operation = document["paths"]["/tasks/{task_id}/events/stream"]["get"]
    parameters = operation["parameters"]
    last_event_id = next(item for item in parameters if item.get("name") == "Last-Event-ID")

    assert operation["operationId"] == "streamTaskEvents"
    assert last_event_id == {
        "name": "Last-Event-ID",
        "in": "header",
        "required": False,
        "schema": {"type": "integer", "minimum": 0},
    }
    assert set(operation["responses"]["200"]["content"]) == {"text/event-stream"}
    assert validate_document(document) == []


def test_sse_contract_rejects_json_transport_regression() -> None:
    document = load_document()
    operation = document["paths"]["/tasks/{task_id}/events/stream"]["get"]
    operation["responses"]["200"]["content"] = {"application/json": {"schema": {"type": "object"}}}

    assert any("text/event-stream" in error for error in validate_document(document))


def test_p2_model_stream_contract_uses_event_stream_media_type() -> None:
    document = load_document()
    operation = document["paths"]["/models/stream"]["post"]

    assert operation["operationId"] == "streamModelCompletion"
    assert set(operation["responses"]["200"]["content"]) == {"text/event-stream"}
    assert validate_document(document) == []


def test_p0_runtime_critical_read_paths_and_request_correlation(settings) -> None:
    app = create_app(replace(settings, legacy_execution_enabled=False))
    request_id = str(uuid.uuid4())
    with TestClient(app) as client:
        health = client.get("/health", headers={"X-Request-ID": request_id})
        unauthorized = client.get("/api/v1/system/requirements")
        requirements = client.get(
            "/api/v1/system/requirements",
            headers={"X-API-Key": ADMIN_KEY, "X-Request-ID": request_id},
        )
        tasks = client.get("/api/v1/tasks", headers={"X-API-Key": ADMIN_KEY})

    assert health.status_code == 200
    assert health.headers["X-Request-ID"] == request_id
    assert health.headers["X-Content-Type-Options"] == "nosniff"
    assert unauthorized.status_code == 401
    assert requirements.status_code == 200
    assert requirements.headers["X-Request-ID"] == request_id
    assert set(requirements.json()) >= {"scope", "implemented", "p0_migration", "excluded"}
    assert requirements.json()["p0_migration"]["legacy_execution_enabled"] is False
    assert tasks.status_code == 200
    assert tasks.json() == []


def test_p3_signed_contract_dispatches_tasks_without_sync_run_operation() -> None:
    document = load_document()
    paths = set(document["paths"])
    assert all("/run" not in path for path in paths)
    assert all("/sandbox" not in path for path in paths)
    assert all("/assets/probe" not in path for path in paths)
    assert all("/validation" not in path for path in paths)
    assert {
        method.lower()
        for path_item in document["paths"].values()
        for method in path_item
        if method.lower() in {"get", "post", "put", "patch", "delete"}
    } == {"get", "post", "put"}
    assert "post" in document["paths"]["/tasks"]
    assert "post" in document["paths"]["/tasks/{task_id}/executions"]
    for path in {
        "/system/requirements",
        "/tasks/{task_id}",
        "/tasks/{task_id}/events",
        "/tasks/{task_id}/events/stream",
    }:
        assert set(document["paths"][path]) <= {"get", "parameters"}
