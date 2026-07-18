from __future__ import annotations

import asyncio
import json
import shutil
import uuid
from dataclasses import dataclass
from typing import Any, Protocol

from .config import Settings
from .scope import ScopeService

HTTP_RESPONSE_ENTRYPOINT = r"""
import http.client
import json
import sys

request = json.loads(sys.argv[1])
host = request["host"]
port = int(request["port"])
method = request["method"]
path = request["path"]
timeout = float(request["timeout_seconds"])

connection = http.client.HTTPConnection(host, port, timeout=timeout)
try:
    connection.request(
        method,
        path,
        headers={
            "Host": request.get("host_header") or host,
            "User-Agent": "VulnLab-Validation-Sandbox/1.0",
            "Connection": "close",
        },
    )
    response = connection.getresponse()
    body = response.read(65536 if method == "GET" else 0)
    print(json.dumps({
        "target": host,
        "connected_address": host,
        "port": port,
        "method": method,
        "path": path,
        "status": response.status,
        "reason": response.reason,
        "headers": {
            key.lower(): value[:512]
            for key, value in response.getheaders()
            if key.lower() in {"server", "content-type", "content-length", "location"}
        },
        "body": body.decode("utf-8", errors="replace"),
        "non_destructive": True,
        "sandboxed": True,
    }, sort_keys=True))
finally:
    connection.close()
"""


class ValidationSandboxError(RuntimeError):
    pass


class ValidationSandboxResourceExceeded(ValidationSandboxError):
    pass


@dataclass(frozen=True, slots=True)
class HttpResponseSandboxRequest:
    sandbox_id: str
    task_id: str
    scope_id: str
    host: str
    port: int
    method: str
    path: str
    timeout_seconds: float


class SandboxBackend(Protocol):
    def describe(self) -> dict[str, Any]: ...

    async def run_http_response(self, request: HttpResponseSandboxRequest) -> dict[str, Any]: ...


class InProcessSandboxBackend:
    """Development/test adapter that preserves deterministic P9 behavior."""

    def __init__(self, scope: ScopeService) -> None:
        self.scope = scope

    def describe(self) -> dict[str, Any]:
        return {
            "backend": "inprocess",
            "production_allowed": False,
            "network": "host-process-scope-service",
        }

    async def run_http_response(self, request: HttpResponseSandboxRequest) -> dict[str, Any]:
        return dict(
            await self.scope.http_probe(
                f"http://{request.host}:{request.port}",
                request.scope_id,
                request.port,
                request.method,
                request.path,
                request.timeout_seconds,
            )
        )


class DockerSandboxBackend:
    """Docker-backed fixed-template runner. It never accepts user-provided shell."""

    def __init__(self, settings: Settings) -> None:
        self.settings = settings

    def describe(self) -> dict[str, Any]:
        return {
            "backend": "docker",
            "image": self.settings.docker_image,
            "network": self.settings.validation_sandbox_network,
            "non_root": True,
            "privileged": False,
            "host_network": False,
            "docker_socket": False,
            "read_only_rootfs": True,
            "cpu": self.settings.validation_sandbox_cpu,
            "memory": self.settings.validation_sandbox_memory,
            "pids_limit": self.settings.validation_sandbox_pids_limit,
        }

    async def run_http_response(self, request: HttpResponseSandboxRequest) -> dict[str, Any]:
        docker = shutil.which("docker")
        if not docker:
            raise ValidationSandboxError("Docker CLI is unavailable")
        if self.settings.validation_sandbox_network.lower() == "host":
            raise ValidationSandboxError("host network is forbidden")
        container_name = f"vulnlab-validation-{uuid.uuid4().hex[:12]}"
        payload = {
            "host": request.host,
            "host_header": request.host,
            "port": request.port,
            "method": request.method,
            "path": request.path,
            "timeout_seconds": request.timeout_seconds,
        }
        command = [
            docker,
            "run",
            "--rm",
            "--name",
            container_name,
            "--network",
            self.settings.validation_sandbox_network,
            "--read-only",
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges:true",
            "--pids-limit",
            str(self.settings.validation_sandbox_pids_limit),
            "--memory",
            self.settings.validation_sandbox_memory,
            "--cpus",
            self.settings.validation_sandbox_cpu,
            "--user",
            "65534:65534",
            "--tmpfs",
            "/tmp:rw,noexec,nosuid,size=32m",
        ]
        if self.settings.validation_sandbox_add_host_gateway:
            command.extend(["--add-host", "host.docker.internal:host-gateway"])
        command.extend(
            [
                self.settings.docker_image,
                "python",
                "-I",
                "-c",
                HTTP_RESPONSE_ENTRYPOINT,
                json.dumps(payload, sort_keys=True),
            ]
        )
        try:
            process = await asyncio.create_subprocess_exec(
                *command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
        except OSError as exc:
            raise ValidationSandboxError("Docker sandbox process could not be started") from exc
        try:
            stdout, stderr = await asyncio.wait_for(
                process.communicate(), timeout=request.timeout_seconds + 2
            )
        except TimeoutError as exc:
            await self._cleanup_container(docker, container_name)
            raise TimeoutError("Docker sandbox execution timed out") from exc
        stdout_text = stdout.decode(errors="replace")
        stderr_text = stderr.decode(errors="replace")
        if process.returncode == 137:
            raise ValidationSandboxResourceExceeded("Docker sandbox memory or CPU limit exceeded")
        if process.returncode != 0:
            raise ValidationSandboxError(
                f"Docker sandbox failed with exit code {process.returncode}: {stderr_text[:2048]}"
            )
        try:
            observed = json.loads(stdout_text)
        except json.JSONDecodeError as exc:
            raise ValidationSandboxError("Docker sandbox produced invalid JSON evidence") from exc
        if not isinstance(observed, dict):
            raise ValidationSandboxError("Docker sandbox evidence must be a JSON object")
        observed["sandbox_backend"] = "docker"
        return observed

    @staticmethod
    async def _cleanup_container(docker: str, container_name: str) -> None:
        try:
            cleanup = await asyncio.create_subprocess_exec(
                docker,
                "rm",
                "-f",
                container_name,
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL,
            )
            await cleanup.wait()
        except OSError:
            return


def build_sandbox_backend(settings: Settings, scope: ScopeService) -> SandboxBackend:
    if settings.validation_sandbox_backend == "inprocess":
        if settings.env in {"production", "prod"}:
            raise ValidationSandboxError("in-process validation sandbox is forbidden in production")
        return InProcessSandboxBackend(scope)
    if settings.validation_sandbox_backend == "docker":
        return DockerSandboxBackend(settings)
    raise ValidationSandboxError(
        f"unknown validation sandbox backend: {settings.validation_sandbox_backend}"
    )
