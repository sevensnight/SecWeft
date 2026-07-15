from __future__ import annotations

from dataclasses import replace

from fastapi.testclient import TestClient
from vulnlab.app import create_app


def test_bootstrap_admin_key_rotates_on_restart(settings, admin_headers):
    first = create_app(settings)
    with TestClient(first) as client:
        assert client.get("/api/v1/users", headers=admin_headers).status_code == 200

    new_key = "rotated-admin-key-with-sufficient-entropy"
    restarted = create_app(replace(settings, admin_key=new_key))
    with TestClient(restarted) as client:
        assert client.get("/api/v1/users", headers=admin_headers).status_code == 401
        assert client.get("/api/v1/users", headers={"X-API-Key": new_key}).status_code == 200
