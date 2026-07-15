from __future__ import annotations

from dataclasses import replace

from conftest import ADMIN_KEY
from fastapi.testclient import TestClient
from vulnlab.app import create_app


def test_p0_default_disables_legacy_execution_apis(settings):
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
    assert "P0/P1" in probe.json()["detail"]
    assert "P0/P1" in sandbox.json()["detail"]
