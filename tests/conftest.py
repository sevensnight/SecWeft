from __future__ import annotations

import base64
import hashlib

import pytest
from fastapi.testclient import TestClient
from vulnlab.app import create_app
from vulnlab.config import Settings

ADMIN_KEY = "test-admin-key-with-sufficient-entropy"


@pytest.fixture()
def settings(tmp_path):
    master = base64.urlsafe_b64encode(hashlib.sha256(b"test-master-key").digest()).decode()
    return Settings(
        env="test",
        db_path=tmp_path / "test.db",
        workspace_root=tmp_path / "workspaces",
        admin_key=ADMIN_KEY,
        master_key=master,
        execution_mode="dry_run",
        allowed_hosts=("localhost", "127.0.0.1", "::1"),
        allowed_ports=(80, 8000, 65534),
        allow_private_networks=False,
        max_concurrency=2,
        legacy_execution_enabled=True,
    )


@pytest.fixture()
def app(settings):
    return create_app(settings)


@pytest.fixture()
def client(app):
    with TestClient(app) as value:
        yield value


@pytest.fixture()
def admin_headers():
    return {"X-API-Key": ADMIN_KEY}


def make_user(
    client: TestClient, admin_headers: dict[str, str], username: str, role: str
) -> tuple[dict, dict[str, str]]:
    response = client.post(
        "/api/v1/users", headers=admin_headers, json={"username": username, "role": role}
    )
    assert response.status_code == 201, response.text
    body = response.json()
    return body, {"X-API-Key": body["api_key"]}


@pytest.fixture()
def analyst(client, admin_headers):
    return make_user(client, admin_headers, "analyst1", "analyst")


@pytest.fixture()
def operator(client, admin_headers):
    return make_user(client, admin_headers, "operator1", "operator")


@pytest.fixture()
def approved_scope(client, admin_headers, analyst):
    _, analyst_headers = analyst
    response = client.post(
        "/api/v1/scopes",
        headers=analyst_headers,
        json={
            "name": "local-lab",
            "target_pattern": "127.0.0.1",
            "protocols": ["tcp", "http"],
            "ports": [80, 8000, 65534],
        },
    )
    assert response.status_code == 201, response.text
    scope = response.json()
    response = client.post(
        f"/api/v1/scopes/{scope['id']}/approve",
        headers=admin_headers,
        json={"approved": True, "reason": "dedicated local test fixture"},
    )
    assert response.status_code == 200, response.text
    return response.json()


@pytest.fixture()
def pending_task(client, analyst, approved_scope):
    _, analyst_headers = analyst
    response = client.post(
        "/api/v1/tasks",
        headers=analyst_headers,
        json={
            "title": "Local defensive reachability regression",
            "target": "tcp://127.0.0.1:65534",
            "intent": "defensive_regression",
            "indicators": ["known-safe-marker"],
            "scope_id": approved_scope["id"],
        },
    )
    assert response.status_code == 201, response.text
    return response.json()
