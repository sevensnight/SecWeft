#!/usr/bin/env python3
"""Launcher, self-check, and end-to-end demonstration for Module 2."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent
SRC = ROOT / "apps" / "control-plane" / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))


def serve(host: str, port: int, reload: bool) -> None:
    import uvicorn

    uvicorn.run("vulnlab.app:create_app", factory=True, host=host, port=port, reload=reload)


def check() -> dict[str, object]:
    from vulnlab.app import create_app
    from vulnlab.config import Settings

    app = create_app(Settings.from_env())
    schema = app.openapi()
    paths = schema.get("paths", {})
    result = {
        "status": "ok",
        "version": app.version,
        "openapi": schema.get("openapi"),
        "routes": len(paths),
        "database": str(app.state.services.settings.db_path),
        "execution_mode": app.state.services.settings.execution_mode,
        "audit_chain": app.state.services.audit.verify(),
    }
    if not result["audit_chain"]["valid"]:
        raise RuntimeError("audit chain verification failed")
    return result


def demo() -> dict[str, object]:
    from fastapi.testclient import TestClient
    from vulnlab.app import create_app
    from vulnlab.config import Settings

    master = base64.urlsafe_b64encode(hashlib.sha256(b"vulnlab-ephemeral-demo").digest()).decode()
    admin_key = "ephemeral-demo-admin-key-with-entropy"
    with tempfile.TemporaryDirectory(prefix="vulnlab-demo-") as temp:
        root = Path(temp)
        settings = Settings(
            env="demo",
            db_path=root / "demo.db",
            workspace_root=root / "workspaces",
            admin_key=admin_key,
            master_key=master,
            execution_mode="dry_run",
            allowed_hosts=("localhost", "127.0.0.1", "::1"),
            allowed_ports=(65534,),
            max_concurrency=2,
            legacy_execution_enabled=True,
        )
        app = create_app(settings)
        admin = {"X-API-Key": admin_key}
        with TestClient(app) as client:
            user_response = client.post(
                "/api/v1/users", headers=admin, json={"username": "demo-analyst", "role": "analyst"}
            )
            user_response.raise_for_status()
            analyst = {"X-API-Key": user_response.json()["api_key"]}

            scope_response = client.post(
                "/api/v1/scopes",
                headers=analyst,
                json={
                    "name": "ephemeral-local-lab",
                    "target_pattern": "127.0.0.1",
                    "protocols": ["tcp"],
                    "ports": [65534],
                },
            )
            scope_response.raise_for_status()
            scope_id = scope_response.json()["id"]
            approval = client.post(
                f"/api/v1/scopes/{scope_id}/approve",
                headers=admin,
                json={"approved": True, "reason": "ephemeral loopback demo fixture"},
            )
            approval.raise_for_status()

            task_response = client.post(
                "/api/v1/tasks",
                headers=analyst,
                json={
                    "title": "End-to-end authorized validation demo",
                    "target": "tcp://127.0.0.1:65534",
                    "intent": "defensive_regression",
                    "indicators": ["safe-demo-marker"],
                    "scope_id": scope_id,
                },
            )
            task_response.raise_for_status()
            task_id = task_response.json()["id"]
            task_approval = client.post(
                f"/api/v1/tasks/{task_id}/approve",
                headers=admin,
                json={"approved": True, "reason": "non-destructive local validation plan"},
            )
            task_approval.raise_for_status()
            execution = client.post(f"/api/v1/tasks/{task_id}/run", headers=admin)
            execution.raise_for_status()
            model = client.post(
                "/api/v1/models/complete",
                headers=analyst,
                json={
                    "messages": [
                        {"role": "user", "content": "Summarize the authorized lab result."}
                    ]
                },
            )
            model.raise_for_status()
            audit = client.get("/api/v1/audit/verify", headers=admin)
            audit.raise_for_status()
            return {
                "status": "ok",
                "scope": {"id": scope_id, "approved": approval.json()["approved"]},
                "task": {
                    "id": task_id,
                    "status": execution.json()["status"],
                    "outcome": execution.json()["result"]["outcome"],
                    "non_destructive": execution.json()["result"]["non_destructive"],
                },
                "model": {"provider": model.json()["provider"], "model": model.json()["model"]},
                "audit": audit.json(),
            }


def main() -> None:
    parser = argparse.ArgumentParser(description="VulnLab Module 2 authorized-lab platform")
    subcommands = parser.add_subparsers(dest="command", required=True)

    serve_parser = subcommands.add_parser("serve", help="start the REST API")
    serve_parser.add_argument("--host", default="127.0.0.1")
    serve_parser.add_argument("--port", type=int, default=8000)
    serve_parser.add_argument("--reload", action="store_true")
    subcommands.add_parser("check", help="initialize and validate local configuration")
    subcommands.add_parser("demo", help="run an ephemeral end-to-end acceptance flow")
    args = parser.parse_args()

    if args.command == "serve":
        serve(args.host, args.port, args.reload)
    elif args.command == "check":
        print(json.dumps(check(), ensure_ascii=False, indent=2))
    else:
        print(json.dumps(demo(), ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
