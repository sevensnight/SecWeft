from __future__ import annotations

import base64
import hashlib
import os
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit

from cryptography.fernet import Fernet


def _csv(value: str) -> tuple[str, ...]:
    return tuple(item.strip() for item in value.split(",") if item.strip())


def _bool(value: str) -> bool:
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _validated_service_url(name: str, value: str, *, require_https: bool) -> str:
    candidate = value.strip().rstrip("/")
    parsed = urlsplit(candidate)
    allowed_schemes = {"https"} if require_https else {"http", "https"}
    if (
        parsed.scheme not in allowed_schemes
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
    ):
        scheme_hint = "https" if require_https else "http or https"
        raise RuntimeError(
            f"{name} must be an absolute {scheme_hint} URL without credentials, query, or fragment"
        )
    return candidate


@dataclass(frozen=True, slots=True)
class Settings:
    env: str
    db_path: Path
    workspace_root: Path
    admin_key: str
    master_key: str
    execution_mode: str = "dry_run"
    docker_image: str = "python:3.12-alpine"
    allowed_hosts: tuple[str, ...] = ("localhost", "127.0.0.1", "::1")
    allowed_ports: tuple[int, ...] = (80, 443, 8000, 8080)
    allow_private_networks: bool = False
    max_concurrency: int = 4
    request_timeout_seconds: float = 8.0
    legacy_execution_enabled: bool = False
    auth_mode: str = "compatibility"
    database_url: str | None = None
    oidc_issuer: str | None = None
    oidc_audience: str | None = None
    oidc_jwks_url: str | None = None
    oidc_tenant_claim: str = "tenant_id"
    oidc_required_acr: str | None = None
    oidc_leeway_seconds: int = 30
    database_pool_min_size: int = 1
    database_pool_max_size: int = 8
    database_pool_timeout_seconds: float = 10.0
    validation_queue_backend: str = "sqlite"
    validation_message_schema_version: int = 1
    validation_queue_lease_seconds: int = 60
    nats_url: str | None = None
    nats_stream: str = "VALIDATION_EXECUTIONS"
    nats_subject: str = "validation.executions.requested"
    nats_durable: str = "validation-worker"
    nats_fetch_timeout_seconds: float = 5.0
    validation_sandbox_backend: str = "inprocess"
    validation_sandbox_network: str = "none"
    validation_sandbox_add_host_gateway: bool = False
    validation_sandbox_cpu: str = "0.5"
    validation_sandbox_memory: str = "256m"
    validation_sandbox_pids_limit: int = 64
    evidence_store_backend: str = "filesystem"
    minio_endpoint: str | None = None
    minio_access_key: str | None = None
    minio_secret_key: str | None = None
    minio_bucket: str = "validation-evidence"
    minio_secure: bool = False

    @classmethod
    def from_env(cls) -> Settings:
        env = os.getenv("VULNLAB_ENV", "development").strip().lower()
        production = env in {"production", "prod"}
        cwd = Path.cwd()
        admin_key = os.getenv("VULNLAB_ADMIN_KEY", "dev-admin-key-change-me")
        explicit_master_key = os.getenv("VULNLAB_MASTER_KEY")
        master_key = explicit_master_key or ""
        if not master_key:
            digest = hashlib.sha256(b"vulnlab-development-master-key").digest()
            master_key = base64.urlsafe_b64encode(digest).decode()
        auth_mode = os.getenv("VULNLAB_AUTH_MODE", "compatibility").strip().lower()
        if auth_mode not in {"compatibility", "oidc"}:
            raise RuntimeError("VULNLAB_AUTH_MODE must be compatibility or oidc")
        if production and auth_mode != "oidc":
            raise RuntimeError("Production requires VULNLAB_AUTH_MODE=oidc")
        if production and explicit_master_key is None:
            raise RuntimeError("Production requires an explicit unique VULNLAB_MASTER_KEY")
        execution_mode = os.getenv("VULNLAB_EXECUTION_MODE", "dry_run").strip().lower()
        if execution_mode not in {"dry_run", "local", "docker"}:
            raise RuntimeError("VULNLAB_EXECUTION_MODE must be dry_run, local, or docker")
        if production and execution_mode == "local":
            raise RuntimeError(
                "Production forbids host-local execution; use dry_run or a dedicated sandbox runner"
            )
        database_url = os.getenv("DATABASE_URL") or None
        oidc_issuer = os.getenv("VULNLAB_OIDC_ISSUER") or None
        oidc_audience = os.getenv("VULNLAB_OIDC_AUDIENCE") or None
        oidc_jwks_url = os.getenv("VULNLAB_OIDC_JWKS_URL") or None
        oidc_tenant_claim = os.getenv("VULNLAB_OIDC_TENANT_CLAIM", "tenant_id").strip()
        oidc_required_acr = os.getenv("VULNLAB_OIDC_REQUIRED_ACR", "").strip() or None
        oidc_leeway_seconds = int(os.getenv("VULNLAB_OIDC_LEEWAY_SECONDS", "30"))
        pool_min_size = int(os.getenv("VULNLAB_DATABASE_POOL_MIN_SIZE", "1"))
        pool_max_size = int(os.getenv("VULNLAB_DATABASE_POOL_MAX_SIZE", "8"))
        pool_timeout = float(os.getenv("VULNLAB_DATABASE_POOL_TIMEOUT_SECONDS", "10"))
        validation_queue_backend = (
            os.getenv("VULNLAB_VALIDATION_QUEUE_BACKEND", "sqlite").strip().lower()
        )
        if validation_queue_backend not in {"sqlite", "nats"}:
            raise RuntimeError("VULNLAB_VALIDATION_QUEUE_BACKEND must be sqlite or nats")
        validation_schema_version = int(os.getenv("VULNLAB_VALIDATION_MESSAGE_SCHEMA_VERSION", "1"))
        if validation_schema_version != 1:
            raise RuntimeError("VULNLAB_VALIDATION_MESSAGE_SCHEMA_VERSION must be 1")
        validation_lease_seconds = int(os.getenv("VULNLAB_VALIDATION_QUEUE_LEASE_SECONDS", "60"))
        if not 5 <= validation_lease_seconds <= 3600:
            raise RuntimeError("VULNLAB_VALIDATION_QUEUE_LEASE_SECONDS must be 5 to 3600")
        nats_url = os.getenv("VULNLAB_NATS_URL") or None
        nats_stream = os.getenv("VULNLAB_NATS_STREAM", "VALIDATION_EXECUTIONS").strip()
        nats_subject = os.getenv("VULNLAB_NATS_SUBJECT", "validation.executions.requested").strip()
        nats_durable = os.getenv("VULNLAB_NATS_DURABLE", "validation-worker").strip()
        nats_fetch_timeout = float(os.getenv("VULNLAB_NATS_FETCH_TIMEOUT_SECONDS", "5"))
        if validation_queue_backend == "nats":
            if not nats_url:
                raise RuntimeError(
                    "VULNLAB_NATS_URL is required when validation queue backend is nats"
                )
            if not nats_stream or not nats_subject or not nats_durable:
                raise RuntimeError("NATS stream, subject, and durable names must be non-empty")
            if not 0.1 <= nats_fetch_timeout <= 60:
                raise RuntimeError("VULNLAB_NATS_FETCH_TIMEOUT_SECONDS must be 0.1 to 60")
        validation_sandbox_backend = (
            os.getenv("VULNLAB_VALIDATION_SANDBOX_BACKEND", "inprocess").strip().lower()
        )
        if validation_sandbox_backend not in {"inprocess", "docker"}:
            raise RuntimeError("VULNLAB_VALIDATION_SANDBOX_BACKEND must be inprocess or docker")
        validation_sandbox_network = os.getenv("VULNLAB_VALIDATION_SANDBOX_NETWORK", "none").strip()
        if validation_sandbox_network.lower() == "host":
            raise RuntimeError("Validation Docker sandbox forbids host network")
        validation_sandbox_add_host_gateway = _bool(
            os.getenv("VULNLAB_VALIDATION_SANDBOX_ADD_HOST_GATEWAY", "false")
        )
        validation_sandbox_cpu = os.getenv("VULNLAB_VALIDATION_SANDBOX_CPU", "0.5").strip()
        validation_sandbox_memory = os.getenv("VULNLAB_VALIDATION_SANDBOX_MEMORY", "256m").strip()
        validation_sandbox_pids_limit = int(
            os.getenv("VULNLAB_VALIDATION_SANDBOX_PIDS_LIMIT", "64")
        )
        if not validation_sandbox_cpu or not validation_sandbox_memory:
            raise RuntimeError("Validation sandbox CPU and memory limits must be non-empty")
        if not 16 <= validation_sandbox_pids_limit <= 512:
            raise RuntimeError("VULNLAB_VALIDATION_SANDBOX_PIDS_LIMIT must be 16 to 512")
        evidence_store_backend = (
            os.getenv("VULNLAB_EVIDENCE_STORE_BACKEND", "filesystem").strip().lower()
        )
        if evidence_store_backend not in {"filesystem", "minio"}:
            raise RuntimeError("VULNLAB_EVIDENCE_STORE_BACKEND must be filesystem or minio")
        minio_endpoint = os.getenv("VULNLAB_MINIO_ENDPOINT") or None
        minio_access_key = os.getenv("VULNLAB_MINIO_ACCESS_KEY") or None
        minio_secret_key = os.getenv("VULNLAB_MINIO_SECRET_KEY") or None
        minio_bucket = os.getenv("VULNLAB_MINIO_BUCKET", "validation-evidence").strip()
        minio_secure = _bool(os.getenv("VULNLAB_MINIO_SECURE", "false"))
        if evidence_store_backend == "minio":
            missing_minio = [
                name
                for name, value in (
                    ("VULNLAB_MINIO_ENDPOINT", minio_endpoint),
                    ("VULNLAB_MINIO_ACCESS_KEY", minio_access_key),
                    ("VULNLAB_MINIO_SECRET_KEY", minio_secret_key),
                    ("VULNLAB_MINIO_BUCKET", minio_bucket),
                )
                if not value
            ]
            if missing_minio:
                raise RuntimeError(f"MinIO evidence store requires: {', '.join(missing_minio)}")
        if auth_mode == "oidc":
            missing = [
                name
                for name, value in (
                    ("DATABASE_URL", database_url),
                    ("VULNLAB_OIDC_ISSUER", oidc_issuer),
                    ("VULNLAB_OIDC_AUDIENCE", oidc_audience),
                    ("VULNLAB_OIDC_JWKS_URL", oidc_jwks_url),
                )
                if not value
            ]
            if missing:
                raise RuntimeError(f"OIDC mode requires: {', '.join(missing)}")
            assert database_url is not None
            assert oidc_issuer is not None
            assert oidc_audience is not None
            assert oidc_jwks_url is not None
            if not database_url.startswith("postgresql://"):
                raise RuntimeError("DATABASE_URL must use PostgreSQL in OIDC mode")
            oidc_issuer = _validated_service_url(
                "VULNLAB_OIDC_ISSUER", oidc_issuer, require_https=production
            )
            oidc_jwks_url = _validated_service_url(
                "VULNLAB_OIDC_JWKS_URL", oidc_jwks_url, require_https=production
            )
            if not oidc_audience.strip() or len(oidc_audience) > 255:
                raise RuntimeError("VULNLAB_OIDC_AUDIENCE must contain 1 to 255 characters")
            oidc_audience = oidc_audience.strip()
            if not oidc_tenant_claim or len(oidc_tenant_claim) > 80:
                raise RuntimeError("VULNLAB_OIDC_TENANT_CLAIM must contain 1 to 80 characters")
            if oidc_required_acr is not None and (
                len(oidc_required_acr) > 255
                or any(character.isspace() for character in oidc_required_acr)
            ):
                raise RuntimeError(
                    "VULNLAB_OIDC_REQUIRED_ACR must be one exact, whitespace-free ACR value"
                )
            if not 0 <= oidc_leeway_seconds <= 300:
                raise RuntimeError("VULNLAB_OIDC_LEEWAY_SECONDS must be between 0 and 300")
            if not 1 <= pool_min_size <= pool_max_size <= 64:
                raise RuntimeError("Database pool sizes must satisfy 1 <= min <= max <= 64")
            if not 1 <= pool_timeout <= 120:
                raise RuntimeError("VULNLAB_DATABASE_POOL_TIMEOUT_SECONDS must be 1 to 120")
        if production and validation_queue_backend != "nats":
            raise RuntimeError(
                "Production requires VULNLAB_VALIDATION_QUEUE_BACKEND=nats; "
                "SQLite validation queue is development/test only"
            )
        if production and validation_sandbox_backend != "docker":
            raise RuntimeError(
                "Production requires VULNLAB_VALIDATION_SANDBOX_BACKEND=docker; "
                "in-process validation sandbox is development/test only"
            )
        if production and evidence_store_backend != "minio":
            raise RuntimeError(
                "Production requires VULNLAB_EVIDENCE_STORE_BACKEND=minio; "
                "filesystem evidence store is development/test only"
            )
        ports = tuple(
            int(port) for port in _csv(os.getenv("VULNLAB_ALLOWED_PORTS", "80,443,8000,8080"))
        )
        return cls(
            env=env,
            db_path=Path(os.getenv("VULNLAB_DB_PATH", str(cwd / "vulnlab.db"))).resolve(),
            workspace_root=Path(
                os.getenv("VULNLAB_WORKSPACE_ROOT", str(cwd / "workspaces"))
            ).resolve(),
            admin_key=admin_key,
            master_key=master_key,
            execution_mode=execution_mode,
            docker_image=os.getenv("VULNLAB_DOCKER_IMAGE", "python:3.12-alpine"),
            allowed_hosts=tuple(
                host.lower()
                for host in _csv(os.getenv("VULNLAB_ALLOWED_HOSTS", "localhost,127.0.0.1,::1"))
            ),
            allowed_ports=ports,
            allow_private_networks=_bool(os.getenv("VULNLAB_ALLOW_PRIVATE_NETWORKS", "false")),
            max_concurrency=max(1, int(os.getenv("VULNLAB_MAX_CONCURRENCY", "4"))),
            request_timeout_seconds=max(0.5, float(os.getenv("VULNLAB_REQUEST_TIMEOUT", "8"))),
            legacy_execution_enabled=_bool(os.getenv("VULNLAB_LEGACY_EXECUTION_ENABLED", "false")),
            auth_mode=auth_mode,
            database_url=database_url,
            oidc_issuer=oidc_issuer,
            oidc_audience=oidc_audience,
            oidc_jwks_url=oidc_jwks_url,
            oidc_tenant_claim=oidc_tenant_claim,
            oidc_required_acr=oidc_required_acr,
            oidc_leeway_seconds=oidc_leeway_seconds,
            database_pool_min_size=pool_min_size,
            database_pool_max_size=pool_max_size,
            database_pool_timeout_seconds=pool_timeout,
            validation_queue_backend=validation_queue_backend,
            validation_message_schema_version=validation_schema_version,
            validation_queue_lease_seconds=validation_lease_seconds,
            nats_url=nats_url,
            nats_stream=nats_stream,
            nats_subject=nats_subject,
            nats_durable=nats_durable,
            nats_fetch_timeout_seconds=nats_fetch_timeout,
            validation_sandbox_backend=validation_sandbox_backend,
            validation_sandbox_network=validation_sandbox_network,
            validation_sandbox_add_host_gateway=validation_sandbox_add_host_gateway,
            validation_sandbox_cpu=validation_sandbox_cpu,
            validation_sandbox_memory=validation_sandbox_memory,
            validation_sandbox_pids_limit=validation_sandbox_pids_limit,
            evidence_store_backend=evidence_store_backend,
            minio_endpoint=minio_endpoint,
            minio_access_key=minio_access_key,
            minio_secret_key=minio_secret_key,
            minio_bucket=minio_bucket,
            minio_secure=minio_secure,
        )

    @property
    def fernet(self) -> Fernet:
        try:
            return Fernet(self.master_key.encode())
        except (TypeError, ValueError) as exc:
            raise RuntimeError("VULNLAB_MASTER_KEY must be a valid Fernet key") from exc

    @property
    def audit_key(self) -> bytes:
        return hashlib.sha256((self.master_key + ":audit").encode()).digest()

    def prepare(self) -> None:
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.workspace_root.mkdir(parents=True, exist_ok=True)
