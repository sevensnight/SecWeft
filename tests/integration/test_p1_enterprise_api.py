from __future__ import annotations

import base64
import hashlib
import os
import socket
import subprocess
import time
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import uuid4

import jwt
import psycopg
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient
from vulnlab.app import create_app
from vulnlab.config import Settings
from vulnlab.enterprise.auth import OidcTokenVerifier
from vulnlab.enterprise.repository import EnterpriseRepository

ISSUER = "https://identity.example.test/realms/vulnlab"
AUDIENCE = "vulnlab-control-plane"
ROOT = Path(__file__).resolve().parents[2]
MIGRATIONS = ROOT / "infrastructure" / "migrations"
DEFAULT_POSTGRES_IMAGE = "postgres:17.4-alpine"


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
        pytest.skip(f"Docker is required when P1_POSTGRES_APP_DSN is not set: {exc}")
    except subprocess.TimeoutExpired as exc:
        output = exc.stdout or ""
        if isinstance(output, bytes):
            output = output.decode("utf-8", errors="replace")
        return subprocess.CompletedProcess(
            args=command,
            returncode=124,
            stdout=f"{output}\ncommand timed out after {timeout_seconds} seconds".strip(),
        )


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


def _apply_migrations(database_url: str) -> None:
    with psycopg.connect(database_url, autocommit=True) as connection:
        for migration in sorted(MIGRATIONS.glob("*.up.sql")):
            connection.execute(migration.read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def p1_postgres_dsn() -> Iterator[str]:
    configured = os.getenv("P1_POSTGRES_APP_DSN")
    if configured:
        yield configured
        return

    if os.getenv("P1_POSTGRES_AUTO_DOCKER", "true").strip().lower() in {
        "0",
        "false",
        "no",
        "off",
    }:
        pytest.skip("P1_POSTGRES_APP_DSN is required when P1_POSTGRES_AUTO_DOCKER=false")

    image = os.getenv("P1_POSTGRES_IMAGE", DEFAULT_POSTGRES_IMAGE)
    name = f"vulnlab-p1-postgres-{uuid4().hex[:10]}"
    password = f"p1-{uuid4().hex}"
    host_port = _free_port()
    database_url = f"postgresql://p1:{password}@127.0.0.1:{host_port}/p1"
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
            "POSTGRES_USER=p1",
            "-e",
            f"POSTGRES_PASSWORD={password}",
            "-e",
            "POSTGRES_DB=p1",
            image,
        ],
        timeout_seconds=90,
    )
    if started.returncode != 0:
        pytest.skip(f"temporary PostgreSQL container could not start: {started.stdout}")
    try:
        _wait_postgres(database_url)
        _apply_migrations(database_url)
        yield database_url
    finally:
        _run(["docker", "rm", "-f", name], timeout_seconds=30)


def _token(private_key, *, tenant_id, subject, username, audience=AUDIENCE) -> str:
    now = datetime.now(UTC)
    return jwt.encode(
        {
            "iss": ISSUER,
            "sub": subject,
            "aud": audience,
            "iat": now,
            "exp": now + timedelta(minutes=5),
            "tenant_id": str(tenant_id),
            "preferred_username": username,
        },
        private_key,
        algorithm="RS256",
        headers={"kid": "p1-integration-key"},
    )


def test_enterprise_api_auth_scope_rbac_and_idempotency(tmp_path, p1_postgres_dsn) -> None:
    database_url = p1_postgres_dsn
    suffix = uuid4().hex[:10]
    tenant_id = uuid4()
    subject = f"api-admin-{suffix}"
    username = f"api-admin-{suffix}"
    bootstrap = EnterpriseRepository(database_url, min_size=1, max_size=2)
    try:
        bootstrap.bootstrap_tenant(
            tenant_id=tenant_id,
            tenant_slug=f"api-tenant-{suffix}",
            tenant_name="P1 API integration tenant",
            issuer=ISSUER,
            subject=subject,
            username=username,
            email=None,
        )
    finally:
        bootstrap.close()

    master = base64.urlsafe_b64encode(hashlib.sha256(b"p1-api-test-master").digest()).decode()
    settings = Settings(
        env="test",
        db_path=tmp_path / "compatibility.db",
        workspace_root=tmp_path / "workspaces",
        admin_key="unused-in-oidc-mode",
        master_key=master,
        auth_mode="oidc",
        database_url=database_url,
        oidc_issuer=ISSUER,
        oidc_audience=AUDIENCE,
        oidc_jwks_url="https://identity.example.test/jwks",
        database_pool_min_size=1,
        database_pool_max_size=3,
    )
    app = create_app(settings)
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    assert app.state.services.enterprise is not None
    app.state.services.enterprise.verifier = OidcTokenVerifier(
        issuer=ISSUER,
        audience=AUDIENCE,
        jwks_url="https://identity.example.test/jwks",
        signing_key_resolver=lambda _: private_key.public_key(),
    )
    admin_token = _token(private_key, tenant_id=tenant_id, subject=subject, username=username)
    admin_headers = {"Authorization": f"Bearer {admin_token}"}

    with TestClient(app) as client:
        unauthenticated = client.get("/api/v1/session")
        assert unauthenticated.status_code == 401
        assert unauthenticated.json()["code"] == "authentication_failed"
        assert unauthenticated.headers["www-authenticate"].startswith("Bearer")

        session = client.get("/api/v1/session", headers=admin_headers)
        assert session.status_code == 200, session.text
        assert session.json()["tenant_id"] == str(tenant_id)
        assert "tenant_admin" in session.json()["roles"]
        assert "role.assign" in session.json()["permissions"]

        organization_key = f"api-organization-{suffix}-0001"
        organization = client.post(
            "/api/v1/organizations",
            headers={**admin_headers, "Idempotency-Key": organization_key},
            json={"slug": f"org-{suffix}", "display_name": "Integration organization"},
        )
        assert organization.status_code == 201, organization.text
        replay = client.post(
            "/api/v1/organizations",
            headers={**admin_headers, "Idempotency-Key": organization_key},
            json={"slug": f"org-{suffix}", "display_name": "Integration organization"},
        )
        assert replay.status_code == 201, replay.text
        assert replay.json()["id"] == organization.json()["id"]
        assert replay.headers["idempotency-replayed"] == "true"

        operator_subject = f"api-readonly-{suffix}"
        operator_username = f"api-readonly-{suffix}"
        provision = client.post(
            "/api/v1/iam/users",
            headers={
                **admin_headers,
                "Idempotency-Key": f"api-provision-{suffix}-0001",
            },
            json={"subject": operator_subject, "username": operator_username},
        )
        assert provision.status_code == 201, provision.text
        project = client.post(
            "/api/v1/projects",
            headers={
                **admin_headers,
                "Idempotency-Key": f"api-project-{suffix}-0001",
            },
            json={
                "organization_id": organization.json()["id"],
                "slug": f"project-{suffix}",
                "display_name": "Integration project",
            },
        )
        assert project.status_code == 201, project.text
        grant = client.post(
            "/api/v1/iam/role-assignments",
            headers={
                **admin_headers,
                "Idempotency-Key": f"api-grant-{suffix}-0001",
            },
            json={
                "user_id": provision.json()["id"],
                "role_code": "readonly_user",
                "project_id": project.json()["id"],
                "reason": "P1 API authorization integration",
            },
        )
        assert grant.status_code == 201, grant.text

        readonly_token = _token(
            private_key,
            tenant_id=tenant_id,
            subject=operator_subject,
            username=operator_username,
        )
        readonly_headers = {"Authorization": f"Bearer {readonly_token}"}
        projects = client.get("/api/v1/projects", headers=readonly_headers)
        assert projects.status_code == 200, projects.text
        assert [item["id"] for item in projects.json()["items"]] == [project.json()["id"]]
        denied = client.post(
            "/api/v1/projects",
            headers={
                **readonly_headers,
                "Idempotency-Key": f"api-denied-{suffix}-0001",
            },
            json={"slug": f"denied-{suffix}", "display_name": "Must not be created"},
        )
        assert denied.status_code == 403
        assert denied.json()["code"] == "permission_denied"

        wrong_tenant_token = _token(
            private_key,
            tenant_id=uuid4(),
            subject=subject,
            username=username,
        )
        cross_tenant = client.get(
            "/api/v1/session", headers={"Authorization": f"Bearer {wrong_tenant_token}"}
        )
        assert cross_tenant.status_code == 401

        wrong_audience = _token(
            private_key,
            tenant_id=tenant_id,
            subject=subject,
            username=username,
            audience="wrong-audience",
        )
        rejected = client.get(
            "/api/v1/session", headers={"Authorization": f"Bearer {wrong_audience}"}
        )
        assert rejected.status_code == 401
