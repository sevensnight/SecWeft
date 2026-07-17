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
