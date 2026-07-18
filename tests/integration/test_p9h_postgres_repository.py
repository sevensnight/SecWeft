from __future__ import annotations

import base64
import hashlib
import socket
import subprocess
import threading
import time
from collections.abc import Iterator
from datetime import UTC, datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from uuid import uuid4

import psycopg
import pytest
from fastapi.testclient import TestClient
from vulnlab.app import create_app
from vulnlab.config import Settings

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_POSTGRES_IMAGE = "postgres:17.4-alpine"
ADMIN_KEY = "test-admin-key-with-sufficient-entropy"


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


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


def _run(command: list[str], *, timeout_seconds: float = 120) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(
            command,
            cwd=ROOT,
            text=True,
            encoding="utf-8",
            errors="replace",
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            check=False,
            timeout=timeout_seconds,
        )
    except FileNotFoundError as exc:
        pytest.skip(f"Docker is required for P9-H PostgreSQL integration: {exc}")


def _wait_postgres(database_url: str) -> None:
    deadline = time.time() + 45
    last_error: Exception | None = None
    while time.time() < deadline:
        try:
            with psycopg.connect(database_url, connect_timeout=2) as connection:
                connection.execute("SELECT 1")
                return
        except Exception as exc:  # noqa: BLE001 - transient container startup errors.
            last_error = exc
            time.sleep(0.5)
    raise RuntimeError(f"temporary PostgreSQL did not become ready: {last_error}")


@pytest.fixture(scope="module")
def p9h_postgres_dsn() -> Iterator[str]:
    image = DEFAULT_POSTGRES_IMAGE
    name = f"vulnlab-p9h-postgres-{uuid4().hex[:10]}"
    password = f"p9h-{uuid4().hex}"
    host_port = _free_port()
    database_url = f"postgresql://p9h:{password}@127.0.0.1:{host_port}/p9h"
    started = _run(
        [
            "docker",
            "run",
            "-d",
            "--rm",
            "--name",
            name,
            "-p",
            f"127.0.0.1:{host_port}:5432",
            "-e",
            "POSTGRES_USER=p9h",
            "-e",
            f"POSTGRES_PASSWORD={password}",
            "-e",
            "POSTGRES_DB=p9h",
            image,
        ],
        timeout_seconds=90,
    )
    if started.returncode != 0:
        pytest.skip(f"temporary PostgreSQL container could not start: {started.stdout}")
    try:
        _wait_postgres(database_url)
        yield database_url
    finally:
        _run(["docker", "rm", "-f", name], timeout_seconds=30)


@pytest.fixture()
def postgres_settings(tmp_path: Path, p9h_postgres_dsn: str) -> Settings:
    master = base64.urlsafe_b64encode(hashlib.sha256(b"p9h-test-master").digest()).decode()
    return Settings(
        env="test",
        db_path=tmp_path / "unused-sqlite.db",
        workspace_root=tmp_path / "workspaces",
        admin_key=ADMIN_KEY,
        master_key=master,
        repository_backend="postgres",
        repository_schema=f"compat_{uuid4().hex[:10]}",
        database_url=p9h_postgres_dsn,
        execution_mode="dry_run",
        allowed_hosts=("localhost", "127.0.0.1", "::1"),
        allowed_ports=(80, 8000, 65534),
        allow_private_networks=False,
        max_concurrency=4,
        legacy_execution_enabled=True,
    )


@pytest.fixture()
def postgres_client(postgres_settings: Settings) -> Iterator[TestClient]:
    app = create_app(postgres_settings)
    with TestClient(app) as client:
        yield client
    app.state.services.close()


def _make_user(
    client: TestClient, headers: dict[str, str], username: str, role: str
) -> tuple[dict, dict[str, str]]:
    response = client.post(
        "/api/v1/users", headers=headers, json={"username": username, "role": role}
    )
    assert response.status_code == 201, response.text
    body = response.json()
    return body, {"X-API-Key": body["api_key"]}


def _approved_scope(
    client: TestClient, admin_headers: dict[str, str], analyst_headers: dict[str, str]
) -> dict:
    response = client.post(
        "/api/v1/scopes",
        headers=analyst_headers,
        json={
            "name": f"p9h-local-lab-{uuid4().hex[:8]}",
            "target_pattern": "127.0.0.1",
            "protocols": ["tcp", "http"],
            "ports": [80, 8000, 65534],
        },
    )
    assert response.status_code == 201, response.text
    scope = response.json()
    approved = client.post(
        f"/api/v1/scopes/{scope['id']}/approve",
        headers=admin_headers,
        json={"approved": True, "reason": "P9-H postgres integration"},
    )
    assert approved.status_code == 200, approved.text
    return approved.json()


def _pending_task(client: TestClient, analyst_headers: dict[str, str], scope: dict) -> dict:
    response = client.post(
        "/api/v1/tasks",
        headers=analyst_headers,
        json={
            "title": "P9-H PostgreSQL defensive reachability",
            "target": "tcp://127.0.0.1:65534",
            "intent": "defensive_regression",
            "indicators": ["known-safe-marker"],
            "scope_id": scope["id"],
        },
    )
    assert response.status_code == 201, response.text
    return response.json()


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
    client: TestClient,
    admin_headers: dict[str, str],
    analyst_headers: dict[str, str],
    task: dict,
) -> dict:
    created = client.post(
        f"/api/v1/tasks/{task['id']}/validation-plans",
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
        json={"approved": True, "reason": "bounded P9-H validation"},
    )
    assert reviewed.status_code == 200, reviewed.text
    return reviewed.json()


def _postgres_fixture_flow(client: TestClient) -> tuple[dict[str, str], dict[str, str], dict, dict]:
    admin_headers = {"X-API-Key": ADMIN_KEY}
    _, analyst_headers = _make_user(
        client, admin_headers, f"p9h-analyst-{uuid4().hex[:8]}", "analyst"
    )
    scope = _approved_scope(client, admin_headers, analyst_headers)
    task = _pending_task(client, analyst_headers, scope)
    plan = _approved_plan(client, admin_headers, analyst_headers, task)
    return admin_headers, analyst_headers, task, plan


def test_postgres_repository_runs_full_p9_api_business_flow(
    postgres_client: TestClient,
) -> None:
    admin_headers, _, _, plan = _postgres_fixture_flow(postgres_client)
    server = ThreadingHTTPServer(("127.0.0.1", 65534), _Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        headers = {**admin_headers, "Idempotency-Key": "p9h-http-execution"}
        first = postgres_client.post(
            f"/api/v1/validation-plans/{plan['id']}/executions",
            headers=headers,
            json={"template_id": "http.response"},
        )
        second = postgres_client.post(
            f"/api/v1/validation-plans/{plan['id']}/executions",
            headers=headers,
            json={"template_id": "http.response"},
        )
        assert first.status_code == 202, first.text
        assert second.status_code == 202, second.text
        assert first.json()["id"] == second.json()["id"]

        services = postgres_client.app.state.services
        result = services.validation_execution.run_worker_once("p9h-worker")
        assert result is not None
        assert result["status"] == "SUCCEEDED"
        assert result["result"]["matched"] is True

        reviewed = postgres_client.post(
            f"/api/v1/validation-executions/{result['id']}/reviews",
            headers=admin_headers,
            json={"accepted": True, "reason": "P9-H evidence accepted"},
        )
        assert reviewed.status_code == 200, reviewed.text
        assert reviewed.json()["review_decision"] == "accepted"

        evidence = postgres_client.get(
            f"/api/v1/validation-executions/{result['id']}/evidence",
            headers=admin_headers,
        )
        assert evidence.status_code == 200
        assert len(evidence.json()) == 1
        assert len(evidence.json()[0]["content_sha256"]) == 64

        rows = services.db.fetch_all("SELECT * FROM validation_executions")
        assert len(rows) == 1
        assert services.audit.verify()["valid"] is True
    finally:
        server.shutdown()
        server.server_close()


def test_postgres_repository_transactions_constraints_json_and_sorting(
    postgres_client: TestClient,
) -> None:
    admin_headers, analyst_headers, task, plan = _postgres_fixture_flow(postgres_client)
    services = postgres_client.app.state.services

    admin = services.db.fetch_one("SELECT * FROM users WHERE username=?", ("admin",))
    assert admin is not None
    with pytest.raises(RuntimeError), services.db.transaction() as connection:
        connection.execute(
            """INSERT INTO scopes(
               id,name,target_pattern,protocols_json,ports_json,expires_at,approved,
               approved_by,approved_at,approval_reason,resolved_ips_json,scope_hash,
               created_by,created_at
               ) VALUES(?,?,?,?,?,NULL,0,NULL,NULL,NULL,'[]','rollback',?,?)""",
            (
                "rolled-back-scope",
                "rolled-back-scope",
                "127.0.0.1",
                '["tcp"]',
                "[65534]",
                admin["id"],
                datetime.now(UTC).isoformat(),
            ),
        )
        raise RuntimeError("force rollback")
    assert services.db.fetch_one("SELECT * FROM scopes WHERE id=?", ("rolled-back-scope",)) is None

    with pytest.raises(psycopg.Error):
        services.db.execute(
            """INSERT INTO tasks(
               id,title,target,intent,indicators_json,scope_id,status,approval_status,
               scope_hash,created_by,assigned_skills_json,created_at,updated_at
               ) VALUES(?,?,?,?,?,'missing-scope','pending_approval','pending','x',?,'[]',?,?)""",
            (
                "fk-missing-task",
                "FK missing",
                "tcp://127.0.0.1:65534",
                "defensive_regression",
                "[]",
                admin["id"],
                datetime.now(UTC).isoformat(),
                datetime.now(UTC).isoformat(),
            ),
        )

    duplicate = postgres_client.post(
        "/api/v1/users",
        headers=admin_headers,
        json={"username": "admin", "role": "viewer"},
    )
    assert duplicate.status_code == 409

    jsonb_row = services.db.fetch_one(
        "SELECT jsonb_typeof(?::jsonb) AS json_type",
        ('{"policy":"validation.execute","allowed":true}',),
    )
    assert jsonb_row["json_type"] == "object"

    first = postgres_client.post(
        f"/api/v1/validation-plans/{plan['id']}/executions",
        headers={**admin_headers, "Idempotency-Key": "p9h-sorted-a"},
        json={"template_id": "sbom.dependency-version"},
    )
    second = postgres_client.post(
        f"/api/v1/validation-plans/{plan['id']}/executions",
        headers={**admin_headers, "Idempotency-Key": "p9h-sorted-b"},
        json={"template_id": "local.training-lab"},
    )
    assert first.status_code == 202
    assert second.status_code == 202
    listed = postgres_client.get(
        "/api/v1/validation-executions?limit=1",
        headers=admin_headers,
    )
    assert listed.status_code == 200
    assert len(listed.json()) == 1
    assert listed.json()[0]["id"] == second.json()["id"]

    other_user, other_headers = _make_user(
        postgres_client, admin_headers, f"p9h-other-{uuid4().hex[:8]}", "analyst"
    )
    cross_tenant = postgres_client.get(
        f"/api/v1/validation-executions/{second.json()['id']}",
        headers=other_headers,
    )
    assert other_user["id"] != "admin"
    assert cross_tenant.status_code == 404
    assert analyst_headers
    assert task


def test_postgres_repository_idempotency_lease_and_races(
    postgres_client: TestClient,
) -> None:
    admin_headers, _, _, plan = _postgres_fixture_flow(postgres_client)
    services = postgres_client.app.state.services
    ids: list[str] = []
    statuses: list[int] = []
    lock = threading.Lock()

    def create_execution() -> None:
        response = postgres_client.post(
            f"/api/v1/validation-plans/{plan['id']}/executions",
            headers={**admin_headers, "Idempotency-Key": "p9h-concurrent-idempotency"},
            json={"template_id": "sbom.dependency-version"},
        )
        with lock:
            statuses.append(response.status_code)
            if response.status_code == 202:
                ids.append(response.json()["id"])

    threads = [threading.Thread(target=create_execution) for _ in range(6)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert set(statuses) == {202}
    assert len(set(ids)) == 1
    queue_row = services.db.fetch_one(
        "SELECT * FROM validation_queue_messages WHERE execution_id=?",
        (ids[0],),
    )
    assert queue_row is not None
    first = services.validation_queue.lease_by_message_id(queue_row["message_id"], "worker-a")
    second = services.validation_queue.lease_by_message_id(queue_row["message_id"], "worker-b")
    assert first.action == "leased"
    assert second.action == "unavailable"

    cancelled = postgres_client.post(
        f"/api/v1/validation-executions/{ids[0]}/cancel",
        headers=admin_headers,
        json={"reason": "P9-H cancellation race"},
    )
    assert cancelled.status_code == 200
    assert cancelled.json()["status"] == "CANCELLED"

    _, _, _, revoked_plan = _postgres_fixture_flow(postgres_client)
    created = postgres_client.post(
        f"/api/v1/validation-plans/{revoked_plan['id']}/executions",
        headers={**admin_headers, "Idempotency-Key": "p9h-revocation-race"},
        json={"template_id": "sbom.dependency-version"},
    )
    assert created.status_code == 202
    services.db.execute(
        "UPDATE validation_plans SET status='revoked' WHERE id=?",
        (revoked_plan["id"],),
    )
    result = services.validation_execution.run_worker_once("p9h-revoked-worker")
    assert result is not None
    assert result["status"] == "APPROVAL_REVOKED"
