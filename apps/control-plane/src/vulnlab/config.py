from __future__ import annotations

import base64
import hashlib
import os
from dataclasses import dataclass
from pathlib import Path

from cryptography.fernet import Fernet


def _csv(value: str) -> tuple[str, ...]:
    return tuple(item.strip() for item in value.split(",") if item.strip())


def _bool(value: str) -> bool:
    return value.strip().lower() in {"1", "true", "yes", "on"}


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

    @classmethod
    def from_env(cls) -> Settings:
        env = os.getenv("VULNLAB_ENV", "development").strip().lower()
        cwd = Path.cwd()
        admin_key = os.getenv("VULNLAB_ADMIN_KEY", "dev-admin-key-change-me")
        explicit_master_key = os.getenv("VULNLAB_MASTER_KEY")
        master_key = explicit_master_key or ""
        if not master_key:
            digest = hashlib.sha256(b"vulnlab-development-master-key").digest()
            master_key = base64.urlsafe_b64encode(digest).decode()
        if env in {"production", "prod"}:
            if admin_key == "dev-admin-key-change-me" or len(admin_key) < 24:
                raise RuntimeError(
                    "Production requires a unique VULNLAB_ADMIN_KEY of at least 24 characters"
                )
            if explicit_master_key is None:
                raise RuntimeError("Production requires an explicit unique VULNLAB_MASTER_KEY")
        execution_mode = os.getenv("VULNLAB_EXECUTION_MODE", "dry_run").strip().lower()
        if execution_mode not in {"dry_run", "local", "docker"}:
            raise RuntimeError("VULNLAB_EXECUTION_MODE must be dry_run, local, or docker")
        if env in {"production", "prod"} and execution_mode == "local":
            raise RuntimeError(
                "Production forbids host-local execution; use dry_run or a dedicated sandbox runner"
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
