#!/usr/bin/env python3
"""Runtime acceptance runner for P9-R controlled execution runtime closure.

The default mode currently exercises:
transactional validation outbox -> NATS JetStream -> worker idempotent consumption
-> DockerSandboxBackend execution for the HTTP response template -> MinIO evidence
upload/download SHA-256 verification -> internal Docker lab network allow/deny
behavior -> timeout cleanup -> memory-limit kill. It also applies PostgreSQL
migrations 0001-0008 in a temporary PostgreSQL container and verifies the P9-R
outbox/lease columns and constraints.
"""

from __future__ import annotations

import argparse
import asyncio
import base64
import hashlib
import json
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
import uuid
from collections.abc import Callable
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, cast

ROOT = Path(__file__).resolve().parent
CONTROL_PLANE_SRC = ROOT / "apps" / "control-plane" / "src"
DEFAULT_MINIO_IMAGE = "minio/minio:RELEASE.2025-04-22T22-12-26Z"
DEFAULT_POSTGRES_IMAGE = "postgres:17.4-alpine"
TARGET_HTTP_ENTRYPOINT = r"""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import sys

port = int(sys.argv[1])

class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        body = b"known-safe-marker"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        return

ThreadingHTTPServer(("0.0.0.0", port), Handler).serve_forever()
"""
HTTP_WAIT_ENTRYPOINT = r"""
import sys
import urllib.request

url = f"http://{sys.argv[1]}:{int(sys.argv[2])}/health"
body = urllib.request.urlopen(url, timeout=2).read().decode()
if "known-safe-marker" not in body:
    raise SystemExit("target marker not found")
print(body)
"""
MEMORY_PRESSURE_ENTRYPOINT = r"""
blocks = []
while True:
    blocks.append(bytearray(1024 * 1024))
"""
TIMEOUT_ENTRYPOINT = r"""
import time
time.sleep(30)
"""
if str(CONTROL_PLANE_SRC) not in sys.path:
    sys.path.insert(0, str(CONTROL_PLANE_SRC))
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

from fastapi.testclient import TestClient  # noqa: E402
from vulnlab.app import create_app  # noqa: E402
from vulnlab.config import Settings  # noqa: E402
from vulnlab.validation_sandbox import (  # noqa: E402
    HttpResponseSandboxRequest,
    ValidationSandboxError,
)


@dataclass(frozen=True)
class CheckResult:
    name: str
    status: str
    duration_ms: int
    details: dict[str, Any]


def _timed(name: str, function: Callable[[], tuple[str, dict[str, Any]]]) -> CheckResult:
    started = time.perf_counter()
    try:
        status, details = function()
    except Exception as exc:
        status, details = "FAIL", {"errors": [f"{type(exc).__name__}: {exc}"]}
    return CheckResult(
        name=name,
        status=status,
        duration_ms=round((time.perf_counter() - started) * 1000),
        details=details,
    )


def _run_async_clean(value: Any) -> Any:
    loop = asyncio.new_event_loop()
    try:
        asyncio.set_event_loop(loop)
        return loop.run_until_complete(value)
    finally:
        loop.run_until_complete(asyncio.sleep(0.2))
        asyncio.set_event_loop(None)
        loop.close()


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


def _wait_tcp(host: str, port: int, *, timeout_seconds: float) -> None:
    deadline = time.time() + timeout_seconds
    last_error: OSError | None = None
    while time.time() < deadline:
        try:
            with socket.create_connection((host, port), timeout=1):
                return
        except OSError as exc:
            last_error = exc
            time.sleep(0.2)
    raise RuntimeError(f"{host}:{port} did not become reachable: {last_error}")


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
    except subprocess.TimeoutExpired as exc:
        output = exc.stdout or ""
        if isinstance(output, bytes):
            output = output.decode("utf-8", errors="replace")
        return subprocess.CompletedProcess(
            args=command,
            returncode=124,
            stdout=f"{output}\ncommand timed out after {timeout_seconds} seconds".strip(),
        )


def _start_nats_container(host_port: int) -> str:
    name = f"vulnlab-p9r-nats-{uuid.uuid4().hex[:10]}"
    command = [
        "docker",
        "run",
        "-d",
        "--rm",
        "--name",
        name,
        "-p",
        f"127.0.0.1:{host_port}:4222",
        "nats:2.11-alpine",
        "-js",
        "-sd",
        "/tmp/nats",
    ]
    completed = _run(command, timeout_seconds=90)
    if completed.returncode != 0:
        raise RuntimeError(completed.stdout.strip())
    _wait_tcp("127.0.0.1", host_port, timeout_seconds=30)
    return name


def _wait_http(url: str, *, timeout_seconds: float) -> None:
    deadline = time.time() + timeout_seconds
    last_error: Exception | None = None
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(url, timeout=1) as response:  # noqa: S310 - local runtime.
                if response.status < 500:
                    return
        except (OSError, urllib.error.URLError) as exc:
            last_error = exc
            time.sleep(0.5)
    raise RuntimeError(f"{url} did not become healthy: {last_error}")


def _start_minio_container(host_port: int, *, access_key: str, secret_key: str, image: str) -> str:
    name = f"vulnlab-p9r-minio-{uuid.uuid4().hex[:10]}"
    command = [
        "docker",
        "run",
        "-d",
        "--rm",
        "--name",
        name,
        "-p",
        f"127.0.0.1:{host_port}:9000",
        "-e",
        f"MINIO_ROOT_USER={access_key}",
        "-e",
        f"MINIO_ROOT_PASSWORD={secret_key}",
        image,
        "server",
        "/data",
        "--console-address",
        ":9001",
    ]
    completed = _run(command, timeout_seconds=180)
    if completed.returncode != 0:
        raise RuntimeError(completed.stdout.strip())
    _wait_http(f"http://127.0.0.1:{host_port}/minio/health/ready", timeout_seconds=60)
    return name


def _start_postgres_container(host_port: int, *, password: str, image: str) -> str:
    name = f"vulnlab-p9r-postgres-{uuid.uuid4().hex[:10]}"
    completed = _run(
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
            "POSTGRES_USER=p9r",
            "-e",
            f"POSTGRES_PASSWORD={password}",
            "-e",
            "POSTGRES_DB=p9r",
            image,
        ],
        timeout_seconds=90,
    )
    if completed.returncode != 0:
        raise RuntimeError(completed.stdout.strip())
    _wait_postgres(f"postgresql://p9r:{password}@127.0.0.1:{host_port}/p9r")
    return name


def _wait_postgres(dsn: str) -> None:
    try:
        import psycopg
    except ImportError as exc:  # pragma: no cover - packaging guard.
        raise RuntimeError("psycopg is required for PostgreSQL runtime checks") from exc
    deadline = time.time() + 45
    last_error: Exception | None = None
    while time.time() < deadline:
        try:
            with psycopg.connect(dsn, connect_timeout=2) as connection:
                connection.execute("SELECT 1")
                return
        except Exception as exc:  # noqa: BLE001 - startup probe.
            last_error = exc
            time.sleep(0.5)
    raise RuntimeError(f"PostgreSQL did not become ready: {last_error}")


def _start_internal_network() -> str:
    name = f"vulnlab-p9r-lab-{uuid.uuid4().hex[:10]}"
    completed = _run(
        ["docker", "network", "create", "--driver", "bridge", "--internal", name],
        timeout_seconds=30,
    )
    if completed.returncode != 0:
        raise RuntimeError(completed.stdout.strip())
    return name


def _remove_network(name: str | None) -> None:
    if name:
        _run(["docker", "network", "rm", name], timeout_seconds=30)


def _start_target_container(network: str, *, port: int) -> str:
    name = f"vulnlab-p9r-target-{uuid.uuid4().hex[:10]}"
    completed = _run(
        [
            "docker",
            "run",
            "-d",
            "--rm",
            "--name",
            name,
            "--network",
            network,
            "--read-only",
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges:true",
            "--pids-limit",
            "32",
            "--memory",
            "128m",
            "--cpus",
            "0.25",
            "python:3.12-alpine",
            "python",
            "-I",
            "-c",
            TARGET_HTTP_ENTRYPOINT,
            str(port),
        ],
        timeout_seconds=60,
    )
    if completed.returncode != 0:
        raise RuntimeError(completed.stdout.strip())
    return name


def _container_ip(container_name: str, network: str) -> str:
    completed = _run(["docker", "inspect", container_name], timeout_seconds=30)
    if completed.returncode != 0:
        raise RuntimeError(completed.stdout.strip())
    data = json.loads(completed.stdout)
    return str(data[0]["NetworkSettings"]["Networks"][network]["IPAddress"])


def _wait_target_from_network(network: str, host: str, port: int) -> None:
    deadline = time.time() + 30
    last_output = ""
    while time.time() < deadline:
        completed = _run(
            [
                "docker",
                "run",
                "--rm",
                "--network",
                network,
                "--read-only",
                "--cap-drop",
                "ALL",
                "--security-opt",
                "no-new-privileges:true",
                "--pids-limit",
                "16",
                "--memory",
                "96m",
                "--cpus",
                "0.25",
                "--user",
                "65534:65534",
                "python:3.12-alpine",
                "python",
                "-I",
                "-c",
                HTTP_WAIT_ENTRYPOINT,
                host,
                str(port),
            ],
            timeout_seconds=10,
        )
        last_output = completed.stdout
        if completed.returncode == 0:
            return
        time.sleep(0.5)
    raise RuntimeError(f"target container did not become reachable: {last_output[:2048]}")


def _run_fixed_sandbox_probe(
    *,
    name: str,
    network: str,
    code: str,
    timeout_seconds: float,
    memory: str = "128m",
) -> subprocess.CompletedProcess[str]:
    command = [
        "docker",
        "run",
        "--name",
        name,
        "--network",
        network,
        "--read-only",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges:true",
        "--pids-limit",
        "32",
        "--memory",
        memory,
        "--cpus",
        "0.25",
        "--user",
        "65534:65534",
        "--tmpfs",
        "/tmp:rw,noexec,nosuid,size=16m",
        "python:3.12-alpine",
        "python",
        "-I",
        "-c",
        code,
    ]
    return _run(command, timeout_seconds=timeout_seconds)


def _container_exists(name: str) -> bool:
    completed = _run(
        ["docker", "ps", "-a", "--filter", f"name=^{name}$", "--format", "{{.Names}}"],
        timeout_seconds=15,
    )
    return name in completed.stdout.splitlines()


def _stop_named_container(name: str | None) -> None:
    if name:
        _run(["docker", "rm", "-f", name], timeout_seconds=30)


def _stop_container(name: str | None) -> None:
    if name:
        _run(["docker", "rm", "-f", name])


def _master_key() -> str:
    return base64.urlsafe_b64encode(hashlib.sha256(b"p9r-runtime-master-key").digest()).decode()


def _create_settings(
    temp_root: Path,
    *,
    nats_url: str,
    target_host: str,
    target_port: int,
    sandbox_network: str,
    minio_endpoint: str,
    minio_access_key: str,
    minio_secret_key: str,
    minio_bucket: str,
) -> Settings:
    run_id = uuid.uuid4().hex[:10].upper()
    return Settings(
        env="test",
        db_path=temp_root / "runtime.db",
        workspace_root=temp_root / "workspaces",
        admin_key="p9r-runtime-admin-key-with-entropy",
        master_key=_master_key(),
        execution_mode="dry_run",
        allowed_hosts=("localhost", "127.0.0.1", "::1", target_host),
        allowed_ports=(80, 443, 8000, 8080, target_port),
        allow_private_networks=True,
        # The current compatibility validation-plan API still gates HTTP probe steps behind the
        # legacy execution capability flag. P9-R runtime execution remains constrained to
        # registered validation templates; arbitrary argv/shell is still rejected by API schema.
        legacy_execution_enabled=True,
        validation_queue_backend="nats",
        validation_message_schema_version=1,
        validation_queue_lease_seconds=10,
        nats_url=nats_url,
        nats_stream=f"VALIDATION_EXECUTIONS_{run_id}",
        nats_subject=f"validation.executions.requested.{run_id.lower()}",
        nats_durable=f"validation-worker-{run_id.lower()}",
        nats_fetch_timeout_seconds=5.0,
        validation_sandbox_backend="docker",
        validation_sandbox_network=sandbox_network,
        validation_sandbox_add_host_gateway=False,
        evidence_store_backend="minio",
        minio_endpoint=minio_endpoint,
        minio_access_key=minio_access_key,
        minio_secret_key=minio_secret_key,
        minio_bucket=minio_bucket,
        minio_secure=False,
    )


def _create_user(
    client: TestClient, admin_headers: dict[str, str]
) -> tuple[dict[str, Any], dict[str, str]]:
    response = client.post(
        "/api/v1/users",
        headers=admin_headers,
        json={"username": f"runtime-analyst-{uuid.uuid4().hex[:8]}", "role": "analyst"},
    )
    if response.status_code != 201:
        raise RuntimeError(response.text)
    body = response.json()
    return body, {"X-API-Key": body["api_key"]}


def _create_approved_plan(
    client: TestClient,
    *,
    admin_headers: dict[str, str],
    analyst_headers: dict[str, str],
    target_host: str,
    target_port: int,
) -> dict[str, Any]:
    scope = client.post(
        "/api/v1/scopes",
        headers=analyst_headers,
        json={
            "name": f"runtime-local-{uuid.uuid4().hex[:8]}",
            "target_pattern": target_host,
            "protocols": ["tcp", "http"],
            "ports": [target_port],
        },
    )
    if scope.status_code != 201:
        raise RuntimeError(scope.text)
    approved_scope = client.post(
        f"/api/v1/scopes/{scope.json()['id']}/approve",
        headers=admin_headers,
        json={"approved": True, "reason": "P9-R runtime target"},
    )
    if approved_scope.status_code != 200:
        raise RuntimeError(approved_scope.text)
    task = client.post(
        "/api/v1/tasks",
        headers=analyst_headers,
        json={
            "title": "P9-R runtime queue validation",
            "target": f"tcp://{target_host}:{target_port}",
            "intent": "defensive_regression",
            "indicators": ["known-safe-marker"],
            "scope_id": approved_scope.json()["id"],
        },
    )
    if task.status_code != 201:
        raise RuntimeError(task.text)
    plan = client.post(
        f"/api/v1/tasks/{task.json()['id']}/validation-plans",
        headers=analyst_headers,
        json={
            "objectives": ["Confirm P9-R runtime HTTP response characteristics"],
            "steps": [
                {
                    "kind": "http_request",
                    "host": target_host,
                    "port": target_port,
                    "method": "GET",
                    "path": "/health",
                    "expected_status": [200],
                    "body_pattern": "known-safe-marker",
                }
            ],
            "rollback": ["No target state is changed"],
        },
    )
    if plan.status_code != 201:
        raise RuntimeError(plan.text)
    submitted = client.post(
        f"/api/v1/validation-plans/{plan.json()['id']}/submit",
        headers=analyst_headers,
    )
    if submitted.status_code != 200:
        raise RuntimeError(submitted.text)
    reviewed = client.post(
        f"/api/v1/validation-plans/{plan.json()['id']}/review",
        headers=admin_headers,
        json={"approved": True, "reason": "P9-R runtime approval"},
    )
    if reviewed.status_code != 200:
        raise RuntimeError(reviewed.text)
    return reviewed.json()


def _assert_egress_blocked(services: Any, target_port: int) -> str:
    try:
        observed = _run_async_clean(
            services.validation_execution.sandbox_backend.run_http_response(
                HttpResponseSandboxRequest(
                    sandbox_id=f"vlsbx-egress-{uuid.uuid4().hex[:12]}",
                    task_id="p9r-runtime-egress",
                    scope_id="p9r-runtime-egress",
                    host="example.com",
                    port=80,
                    method="GET",
                    path="/",
                    timeout_seconds=3.0,
                )
            )
        )
    except (TimeoutError, ValidationSandboxError) as exc:
        return f"{type(exc).__name__}: {exc}"
    raise RuntimeError(
        "internet egress unexpectedly succeeded from sandbox: "
        f"status={observed.get('status')} target_port={target_port}"
    )


def _timeout_cleanup_check(network: str) -> tuple[str, dict[str, Any]]:
    name = f"vulnlab-p9r-timeout-{uuid.uuid4().hex[:10]}"
    completed = _run_fixed_sandbox_probe(
        name=name,
        network=network,
        code=TIMEOUT_ENTRYPOINT,
        timeout_seconds=2,
    )
    if completed.returncode != 124:
        _stop_named_container(name)
        raise RuntimeError(f"timeout probe unexpectedly returned {completed.returncode}")
    _stop_named_container(name)
    exists_after_cleanup = _container_exists(name)
    if exists_after_cleanup:
        raise RuntimeError("timeout probe container still exists after cleanup")
    return "PASS", {
        "container": name,
        "returncode": completed.returncode,
        "cleanup_verified": True,
    }


def _memory_limit_check(network: str) -> tuple[str, dict[str, Any]]:
    name = f"vulnlab-p9r-memory-{uuid.uuid4().hex[:10]}"
    completed = _run_fixed_sandbox_probe(
        name=name,
        network=network,
        code=MEMORY_PRESSURE_ENTRYPOINT,
        timeout_seconds=20,
        memory="32m",
    )
    _stop_named_container(name)
    if completed.returncode == 0:
        raise RuntimeError("memory pressure probe unexpectedly completed successfully")
    if completed.returncode == 124:
        raise RuntimeError("memory pressure probe timed out instead of being killed")
    exists_after_cleanup = _container_exists(name)
    if exists_after_cleanup:
        raise RuntimeError("memory pressure probe container still exists after cleanup")
    return "PASS", {
        "container": name,
        "returncode": completed.returncode,
        "cleanup_verified": True,
        "resource_exceeded": True,
    }


def _postgres_runtime_check(dsn: str) -> tuple[str, dict[str, Any]]:
    import psycopg
    from psycopg.errors import UniqueViolation
    from psycopg.types.json import Jsonb

    migration_files = sorted((ROOT / "infrastructure" / "migrations").glob("*.up.sql"))
    tenant_id = uuid.uuid4()
    user_id = uuid.uuid4()
    execution_id = uuid.uuid4()
    queue_id = uuid.uuid4()
    message_id = uuid.uuid4()
    lease_token = uuid.uuid4()
    with psycopg.connect(dsn, autocommit=True) as connection:
        for migration in migration_files:
            connection.execute(migration.read_text(encoding="utf-8"))
        with connection.cursor() as cursor:
            cursor.execute(
                "INSERT INTO iam.tenants(id, slug, display_name) VALUES(%s,%s,%s)",
                (tenant_id, f"p9r-{tenant_id.hex[:12]}", "P9-R runtime tenant"),
            )
            cursor.execute(
                """INSERT INTO iam.users(id, tenant_id, subject, username, issuer)
                   VALUES(%s,%s,%s,%s,%s)""",
                (
                    user_id,
                    tenant_id,
                    f"subject-{user_id.hex}",
                    f"user-{user_id.hex[:12]}",
                    "urn:vulnlab:p9r-runtime",
                ),
            )
            cursor.execute(
                """INSERT INTO validation.executions(
                   id,tenant_id,task_id,plan_id,template_id,template_version,status,
                   trace_id,sandbox_id,approval_id,policy_decision_id,created_by
                   ) VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)""",
                (
                    execution_id,
                    tenant_id,
                    uuid.uuid4(),
                    uuid.uuid4(),
                    "http.response",
                    "1.0.0",
                    "QUEUED",
                    uuid.uuid4().hex,
                    f"vlsbx-{uuid.uuid4().hex[:20]}",
                    f"validation-plan:{uuid.uuid4()}:runtime",
                    uuid.uuid4(),
                    user_id,
                ),
            )
            payload = {
                "schema_version": 1,
                "execution_id": str(execution_id),
                "tenant_id": str(tenant_id),
                "message_id": str(message_id),
                "trace_id": uuid.uuid4().hex,
            }
            cursor.execute(
                """INSERT INTO validation.queue_messages(
                   id,tenant_id,execution_id,message_id,subject,status,available_at,payload
                   ) VALUES(%s,%s,%s,%s,%s,'ready',CURRENT_TIMESTAMP,%s)""",
                (
                    queue_id,
                    tenant_id,
                    execution_id,
                    message_id,
                    "validation.executions.requested",
                    Jsonb(payload),
                ),
            )
            cursor.execute(
                """UPDATE validation.executions
                   SET lease_owner=%s,
                       lease_token=%s,
                       lease_expires_at=CURRENT_TIMESTAMP + interval '60 seconds',
                       worker_attempt=worker_attempt + 1
                   WHERE tenant_id=%s
                     AND id=%s
                     AND status='QUEUED'
                     AND (lease_expires_at IS NULL OR lease_expires_at < CURRENT_TIMESTAMP)
                   RETURNING worker_attempt""",
                ("p9r-postgres-worker", lease_token, tenant_id, execution_id),
            )
            lease_row = cursor.fetchone()
            if lease_row is None or lease_row[0] != 1:
                raise RuntimeError("PostgreSQL execution lease CAS did not update exactly once")
            cursor.execute(
                """UPDATE validation.queue_messages
                   SET publish_attempt=publish_attempt + 1,
                       published_at=CURRENT_TIMESTAMP
                   WHERE tenant_id=%s AND id=%s
                   RETURNING publish_attempt, published_at""",
                (tenant_id, queue_id),
            )
            publish_row = cursor.fetchone()
            if publish_row is None or publish_row[0] != 1 or publish_row[1] is None:
                raise RuntimeError("PostgreSQL outbox publish metadata was not persisted")
            duplicate_rejected = False
            try:
                cursor.execute(
                    """INSERT INTO validation.queue_messages(
                       id,tenant_id,execution_id,message_id,subject,status,available_at,payload
                       ) VALUES(%s,%s,%s,%s,%s,'ready',CURRENT_TIMESTAMP,%s)""",
                    (
                        uuid.uuid4(),
                        tenant_id,
                        execution_id,
                        message_id,
                        "validation.executions.requested",
                        Jsonb(payload),
                    ),
                )
            except UniqueViolation:
                duplicate_rejected = True
            if not duplicate_rejected:
                raise RuntimeError("PostgreSQL duplicate message_id was not rejected")
            cursor.execute(
                "SELECT to_regclass('validation.idx_validation_queue_outbox_unpublished')::text"
            )
            outbox_index_row = cursor.fetchone()
            cursor.execute("SELECT to_regclass('validation.idx_validation_execution_lease')::text")
            lease_index_row = cursor.fetchone()
            cursor.execute(
                """SELECT schema_version, publish_attempt, published_at IS NOT NULL
                   FROM validation.queue_messages
                   WHERE tenant_id=%s AND id=%s""",
                (tenant_id, queue_id),
            )
            queue_row = cursor.fetchone()
            if outbox_index_row is None or lease_index_row is None or queue_row is None:
                raise RuntimeError("PostgreSQL runtime verification query returned no rows")
            outbox_index = outbox_index_row[0]
            lease_index = lease_index_row[0]
    return "PASS", {
        "migration_count": len(migration_files),
        "tenant_id": str(tenant_id),
        "execution_id": str(execution_id),
        "queue_message_id": str(queue_id),
        "message_id": str(message_id),
        "worker_attempt": 1,
        "schema_version": queue_row[0],
        "publish_attempt": queue_row[1],
        "published": queue_row[2],
        "duplicate_message_rejected": duplicate_rejected,
        "outbox_index": outbox_index,
        "lease_index": lease_index,
    }


def _queue_runtime_check(
    *,
    nats_url: str,
    sandbox_network: str,
    target_host: str,
    target_port: int,
    minio_endpoint: str,
    minio_access_key: str,
    minio_secret_key: str,
    minio_bucket: str,
) -> tuple[str, dict[str, Any]]:
    with tempfile.TemporaryDirectory(prefix="vulnlab-p9r-runtime-") as temp:
        settings = _create_settings(
            Path(temp),
            nats_url=nats_url,
            target_host=target_host,
            target_port=target_port,
            sandbox_network=sandbox_network,
            minio_endpoint=minio_endpoint,
            minio_access_key=minio_access_key,
            minio_secret_key=minio_secret_key,
            minio_bucket=minio_bucket,
        )
        app = create_app(settings)
        with TestClient(app) as client:
            services = cast(Any, client.app).state.services
            admin_headers = {"X-API-Key": settings.admin_key}
            _, analyst_headers = _create_user(client, admin_headers)
            plan = _create_approved_plan(
                client,
                admin_headers=admin_headers,
                analyst_headers=analyst_headers,
                target_host=target_host,
                target_port=target_port,
            )
            created = client.post(
                f"/api/v1/validation-plans/{plan['id']}/executions",
                headers={**admin_headers, "Idempotency-Key": "p9r-runtime-queue"},
                json={"template_id": "http.response"},
            )
            if created.status_code != 202:
                raise RuntimeError(created.text)
            execution = created.json()
            dispatched = services.validation_execution.dispatch_outbox_once()
            if dispatched is None:
                raise RuntimeError("outbox dispatcher did not publish a message")
            result = services.validation_execution.run_worker_once("runtime-worker")
            if result is None:
                raise RuntimeError("worker did not consume a JetStream message")
            if result["status"] != "SUCCEEDED":
                raise RuntimeError(f"unexpected execution status: {result['status']}")
            row = services.db.fetch_one(
                "SELECT * FROM validation_queue_messages WHERE execution_id=?",
                (execution["id"],),
            )
            if row is None:
                raise RuntimeError("queue row disappeared")
            evidence_rows = services.db.fetch_all(
                "SELECT * FROM validation_execution_evidence WHERE execution_id=?",
                (execution["id"],),
            )
            evidence_count = len(evidence_rows)
            if evidence_count != 1:
                raise RuntimeError(f"expected one evidence row, got {evidence_count}")
            evidence = result["result"]["evidence"]
            evidence_metadata = json.loads(evidence_rows[0]["metadata_json"])
            object_key = evidence_metadata["object_key"]
            if evidence_metadata["object_store_mode"] != "minio":
                raise RuntimeError("evidence was not stored through MinioEvidenceStore")
            if execution["tenant_id"] not in object_key or execution["id"] not in object_key:
                raise RuntimeError("MinIO object key is not tenant/execution scoped")
            if not evidence["artifact_ref"].startswith(f"minio://{minio_bucket}/"):
                raise RuntimeError("evidence artifact_ref does not point at the runtime bucket")
            duplicate_headers = {
                "schema_version": "1",
                "message_id": row["message_id"],
                "execution_id": execution["id"],
                "tenant_id": execution["tenant_id"],
                "trace_id": execution["trace_id"],
                "request_id": "p9r-runtime-duplicate",
                "queue_message_id": row["id"],
                "Nats-Msg-Id": f"{row['message_id']}-duplicate",
                "transport": "nats-jetstream",
            }
            payload = row["payload_json"].encode()
            services.validation_queue._publish_to_jetstream  # noqa: B018 - runtime guard.

            services.validation_queue._run(
                services.validation_queue._publish_to_jetstream(
                    subject=row["subject"],
                    payload=payload,
                    headers=duplicate_headers,
                )
            )
            duplicate_result = services.validation_execution.run_worker_once(
                "runtime-worker-duplicate"
            )
            evidence_after_duplicate = len(
                services.db.fetch_all(
                    "SELECT * FROM validation_execution_evidence WHERE execution_id=?",
                    (execution["id"],),
                )
            )
            if duplicate_result is not None:
                raise RuntimeError("duplicate JetStream message unexpectedly re-ran execution")
            if evidence_after_duplicate != 1:
                raise RuntimeError("duplicate message created duplicate evidence")
            egress_error = _assert_egress_blocked(services, target_port)
            events = services.validation_execution.events(execution["id"])
            services.close()
            return "PASS", {
                "execution_id": execution["id"],
                "trace_id": execution["trace_id"],
                "queue_message_id": row["id"],
                "message_id": row["message_id"],
                "published_at": row["published_at"],
                "publish_attempt": row["publish_attempt"],
                "queue_status": row["status"],
                "worker_status": result["status"],
                "sandbox_backend": result["result"]["observed"].get("sandbox_backend"),
                "sandbox_network": sandbox_network,
                "sandboxed": result["result"]["observed"].get("sandboxed"),
                "authorized_target": f"{target_host}:{target_port}",
                "internet_egress_blocked": True,
                "internet_egress_error": egress_error,
                "evidence_backend": evidence_metadata["object_store_mode"],
                "evidence_artifact_ref": evidence["artifact_ref"],
                "evidence_object_key": object_key,
                "evidence_object_size": evidence_metadata["object_size"],
                "evidence_sha256": evidence["content_sha256"],
                "evidence_count": evidence_count,
                "duplicate_evidence_count": evidence_after_duplicate,
                "event_types": [item["event_type"] for item in events],
            }


def run(
    *,
    nats_url: str | None,
    minio_endpoint: str | None,
    minio_access_key: str,
    minio_secret_key: str,
    minio_bucket: str,
    minio_image: str,
    postgres_dsn: str | None,
    postgres_image: str,
    keep_containers: bool,
) -> dict[str, Any]:
    nats_container_name: str | None = None
    minio_container_name: str | None = None
    postgres_container_name: str | None = None
    lab_network_name: str | None = None
    target_container_name: str | None = None
    target_host: str | None = None
    target_port = 8080
    effective_nats_url = nats_url
    effective_minio_endpoint = minio_endpoint
    effective_postgres_dsn = postgres_dsn
    checks: list[CheckResult] = []
    startup_started = time.perf_counter()
    try:
        if effective_nats_url is None:
            host_port = _free_port()
            nats_container_name = _start_nats_container(host_port)
            effective_nats_url = f"nats://127.0.0.1:{host_port}"
        if effective_minio_endpoint is None:
            host_port = _free_port()
            minio_container_name = _start_minio_container(
                host_port,
                access_key=minio_access_key,
                secret_key=minio_secret_key,
                image=minio_image,
            )
            effective_minio_endpoint = f"127.0.0.1:{host_port}"
        if effective_postgres_dsn is None:
            host_port = _free_port()
            postgres_password = f"p9r-{uuid.uuid4().hex}"
            postgres_container_name = _start_postgres_container(
                host_port,
                password=postgres_password,
                image=postgres_image,
            )
            effective_postgres_dsn = (
                f"postgresql://p9r:{postgres_password}@127.0.0.1:{host_port}/p9r"
            )
        lab_network_name = _start_internal_network()
        target_container_name = _start_target_container(lab_network_name, port=target_port)
        target_host = _container_ip(target_container_name, lab_network_name)
        _wait_target_from_network(lab_network_name, target_host, target_port)
        assert effective_nats_url is not None
        assert effective_minio_endpoint is not None
        assert effective_postgres_dsn is not None
        assert lab_network_name is not None
        assert target_host is not None
        checks = [
            _timed(
                "p9r_postgresql_migrations_outbox_schema",
                lambda: _postgres_runtime_check(effective_postgres_dsn),
            ),
            _timed(
                "p9r_nats_worker_docker_minio_internal_network",
                lambda: _queue_runtime_check(
                    nats_url=effective_nats_url,
                    sandbox_network=lab_network_name,
                    target_host=target_host,
                    target_port=target_port,
                    minio_endpoint=effective_minio_endpoint,
                    minio_access_key=minio_access_key,
                    minio_secret_key=minio_secret_key,
                    minio_bucket=minio_bucket,
                ),
            ),
            _timed(
                "p9r_docker_sandbox_timeout_cleanup",
                lambda: _timeout_cleanup_check(lab_network_name),
            ),
            _timed(
                "p9r_docker_sandbox_memory_limit_kill",
                lambda: _memory_limit_check(lab_network_name),
            ),
        ]
    except Exception as exc:
        checks = [
            CheckResult(
                name="p9r_runtime_environment_startup",
                status="FAIL",
                duration_ms=round((time.perf_counter() - startup_started) * 1000),
                details={"errors": [f"{type(exc).__name__}: {exc}"]},
            )
        ]
    finally:
        if not keep_containers:
            _stop_named_container(target_container_name)
            _stop_container(nats_container_name)
            _stop_container(minio_container_name)
            _stop_container(postgres_container_name)
            _remove_network(lab_network_name)
    failed = [check for check in checks if check.status == "FAIL"]
    return {
        "phase": "P9-R",
        "mode": "queue-docker-sandbox-minio-network-resource",
        "valid": not failed,
        "summary": {
            "total": len(checks),
            "passed": sum(check.status == "PASS" for check in checks),
            "failed": len(failed),
        },
        "checks": [asdict(check) for check in checks],
        "not_executed": {
            "full_fastapi_control_plane_postgresql_repository": (
                "The runtime applies PostgreSQL migrations 0001-0008 and verifies P9-R "
                "outbox/lease behavior in PostgreSQL. The compatibility FastAPI control "
                "plane still uses the existing SQLite Database adapter for its API-level "
                "business flow in this repository."
            )
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--nats-url",
        help="Use an existing NATS JetStream server instead of starting a temporary Docker NATS.",
    )
    parser.add_argument(
        "--minio-endpoint",
        help="Use an existing MinIO endpoint host:port instead of starting a temporary MinIO.",
    )
    parser.add_argument("--minio-access-key", default="p9rminioadmin")
    parser.add_argument("--minio-secret-key", default="p9rminioadmin-secret")
    parser.add_argument("--minio-bucket", default="validation-evidence")
    parser.add_argument("--minio-image", default=DEFAULT_MINIO_IMAGE)
    parser.add_argument(
        "--postgres-dsn",
        help="Use an existing PostgreSQL DSN instead of starting a temporary PostgreSQL.",
    )
    parser.add_argument("--postgres-image", default=DEFAULT_POSTGRES_IMAGE)
    parser.add_argument(
        "--keep-containers",
        action="store_true",
        help="Do not remove temporary NATS/MinIO containers after the run.",
    )
    args = parser.parse_args()
    result = run(
        nats_url=args.nats_url,
        minio_endpoint=args.minio_endpoint,
        minio_access_key=args.minio_access_key,
        minio_secret_key=args.minio_secret_key,
        minio_bucket=args.minio_bucket,
        minio_image=args.minio_image,
        postgres_dsn=args.postgres_dsn,
        postgres_image=args.postgres_image,
        keep_containers=args.keep_containers,
    )
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if result["valid"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
