from __future__ import annotations

import json
import threading
from dataclasses import replace
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from conftest import ADMIN_KEY, make_user
from fastapi.testclient import TestClient
from vulnlab.app import create_app


def _server(marker: str) -> tuple[ThreadingHTTPServer, threading.Thread]:
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            body = json.dumps({"marker": marker}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, format: str, *args: object) -> None:
            return

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, thread


def test_vulnerable_and_patched_marker_comparison(settings):
    vulnerable, vulnerable_thread = _server("VULNLAB_SYNTHETIC_FINDING")
    patched, patched_thread = _server("PATCH_APPLIED")
    ports = (vulnerable.server_port, patched.server_port)
    app = create_app(replace(settings, allowed_ports=ports))
    admin = {"X-API-Key": ADMIN_KEY}
    try:
        with TestClient(app) as client:
            _, analyst = make_user(client, admin, "e2e-analyst", "analyst")

            def validate(port: int, suffix: str) -> dict:
                scope_response = client.post(
                    "/api/v1/scopes",
                    headers=analyst,
                    json={
                        "name": f"http-fixture-{suffix}",
                        "target_pattern": "127.0.0.1",
                        "protocols": ["http", "tcp"],
                        "ports": [port],
                    },
                )
                assert scope_response.status_code == 201, scope_response.text
                scope_id = scope_response.json()["id"]
                assert (
                    client.post(
                        f"/api/v1/scopes/{scope_id}/approve",
                        headers=admin,
                        json={"approved": True, "reason": "local synthetic marker fixture"},
                    ).status_code
                    == 200
                )
                task_response = client.post(
                    "/api/v1/tasks",
                    headers=analyst,
                    json={
                        "title": f"Marker comparison {suffix}",
                        "target": f"http://127.0.0.1:{port}",
                        "intent": "defensive_regression",
                        "indicators": ["VULNLAB_SYNTHETIC_FINDING"],
                        "scope_id": scope_id,
                    },
                )
                assert task_response.status_code == 201, task_response.text
                task_id = task_response.json()["id"]
                assert (
                    client.post(
                        f"/api/v1/tasks/{task_id}/approve",
                        headers=admin,
                        json={"approved": True, "reason": "GET-only marker plan"},
                    ).status_code
                    == 200
                )
                execution = client.post(f"/api/v1/tasks/{task_id}/run", headers=admin)
                assert execution.status_code == 200, execution.text
                return execution.json()["result"]

            vulnerable_result = validate(vulnerable.server_port, "vulnerable")
            patched_result = validate(patched.server_port, "patched")
            assert vulnerable_result["validation_signal"] is True
            assert patched_result["validation_signal"] is False
            assert vulnerable_result["non_destructive"] is True
            assert patched_result["non_destructive"] is True
    finally:
        vulnerable.shutdown()
        patched.shutdown()
        vulnerable.server_close()
        patched.server_close()
        vulnerable_thread.join(timeout=2)
        patched_thread.join(timeout=2)
