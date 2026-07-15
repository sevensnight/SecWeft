from __future__ import annotations

import asyncio
import json
import os
import re
import shutil
import sys
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .audit import AuditService
from .config import Settings
from .db import Database
from .schemas import SandboxRequest
from .security import Principal


class SandboxPolicyError(ValueError):
    pass


class SandboxRuntimeError(RuntimeError):
    pass


SHELL_META = re.compile(r"[;&|<>`$]")
SAFE_PATH = re.compile(r"^[A-Za-z0-9_./\\-]+$")


class SandboxService:
    """A narrow diagnostic runner; it is deliberately not a generic shell API."""

    def __init__(self, db: Database, settings: Settings, audit: AuditService):
        self.db = db
        self.settings = settings
        self.audit = audit

    def validate_argv(self, argv: list[str]) -> list[str]:
        if any(SHELL_META.search(arg) for arg in argv):
            raise SandboxPolicyError("shell metacharacters are forbidden")
        command = Path(argv[0]).name.lower()
        if command in {"python", "python3", "python.exe"}:
            if len(argv) == 2 and argv[1] in {"--version", "-V"}:
                return argv
            if len(argv) >= 3 and argv[1:3] == ["-m", "pytest"]:
                for argument in argv[3:]:
                    if argument in {"-q", "-x", "--disable-warnings"}:
                        continue
                    if (
                        argument.startswith("-")
                        or not SAFE_PATH.fullmatch(argument)
                        or ".." in Path(argument).parts
                    ):
                        raise SandboxPolicyError(f"pytest argument is not allowed: {argument}")
                return argv
        if command in {"pytest", "pytest.exe"}:
            for argument in argv[1:]:
                if argument in {"-q", "-x", "--disable-warnings"}:
                    continue
                if (
                    argument.startswith("-")
                    or not SAFE_PATH.fullmatch(argument)
                    or ".." in Path(argument).parts
                ):
                    raise SandboxPolicyError(f"pytest argument is not allowed: {argument}")
            return argv
        raise SandboxPolicyError("only Python version checks and bounded pytest runs are allowed")

    def _task_guard(self, principal: Principal, task_id: str | None) -> None:
        if task_id is None:
            return
        row = self.db.fetch_one(
            "SELECT status,approval_status,created_by FROM tasks WHERE id=?", (task_id,)
        )
        if row is None:
            raise KeyError("task not found")
        if row["approval_status"] != "approved" or row["status"] not in {"approved", "running"}:
            raise SandboxPolicyError("sandbox runs require an approved active task")
        if principal.role.value != "admin" and row["created_by"] != principal.id:
            raise PermissionError("sandbox task belongs to another principal")

    async def run(self, principal: Principal, request: SandboxRequest) -> dict[str, Any]:
        if not bool(self.audit.verify()["valid"]):
            raise SandboxPolicyError("audit integrity check failed; sandbox execution is blocked")
        self._task_guard(principal, request.task_id)
        argv = self.validate_argv(request.argv)
        if self.settings.execution_mode == "docker":
            self._validate_image(request.image)
        run_id = str(uuid.uuid4())
        started = datetime.now(UTC).isoformat()
        mode = self.settings.execution_mode
        self.db.execute(
            """INSERT INTO sandbox_runs(id,task_id,mode,argv_json,status,started_at,created_by)
               VALUES(?,?,?,?,?,?,?)""",
            (run_id, request.task_id, mode, json.dumps(argv), "running", started, principal.id),
        )
        self.audit.record(
            principal.id,
            "sandbox.run.start",
            "sandbox_run",
            run_id,
            details={
                "task_id": request.task_id,
                "mode": mode,
                "argv": argv,
            },
        )
        result: dict[str, Any]
        try:
            if mode == "dry_run":
                result = {
                    "exit_code": None,
                    "stdout": "",
                    "stderr": "dry-run: command validated but not executed",
                    "status": "dry_run",
                }
            elif mode == "local":
                result = await self._run_local(argv, request.timeout_seconds, run_id)
            else:
                result = await self._run_docker(
                    argv, request.timeout_seconds, run_id, request.image
                )
        except Exception as exc:
            finished = datetime.now(UTC).isoformat()
            self.db.execute(
                """UPDATE sandbox_runs SET status='failed',exit_code=NULL,stdout='',stderr=?,finished_at=?
                   WHERE id=?""",
                (f"{type(exc).__name__}: sandbox runtime unavailable", finished, run_id),
            )
            self.audit.record(
                principal.id,
                "sandbox.run.finish",
                "sandbox_run",
                run_id,
                "failure",
                {
                    "error_type": type(exc).__name__,
                },
            )
            raise
        finished = datetime.now(UTC).isoformat()
        self.db.execute(
            """UPDATE sandbox_runs SET status=?,exit_code=?,stdout=?,stderr=?,finished_at=? WHERE id=?""",
            (
                result["status"],
                result["exit_code"],
                result["stdout"][:65_536],
                result["stderr"][:65_536],
                finished,
                run_id,
            ),
        )
        self.audit.record(
            principal.id,
            "sandbox.run.finish",
            "sandbox_run",
            run_id,
            result["status"],
            {
                "exit_code": result["exit_code"],
                "stdout_bytes": len(result["stdout"]),
                "stderr_bytes": len(result["stderr"]),
            },
        )
        return {"id": run_id, "mode": mode, **result}

    async def _communicate(
        self, process: asyncio.subprocess.Process, timeout: int
    ) -> dict[str, Any]:
        try:
            stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=timeout)
            return {
                "exit_code": process.returncode,
                "stdout": stdout.decode(errors="replace")[:65_536],
                "stderr": stderr.decode(errors="replace")[:65_536],
                "status": "succeeded" if process.returncode == 0 else "failed",
            }
        except TimeoutError:
            process.kill()
            stdout, stderr = await process.communicate()
            return {
                "exit_code": process.returncode,
                "stdout": stdout.decode(errors="replace")[:65_536],
                "stderr": (stderr.decode(errors="replace") + "\nexecution timed out")[:65_536],
                "status": "timeout",
            }

    async def _run_local(self, argv: list[str], timeout: int, run_id: str) -> dict[str, Any]:
        workspace = self.settings.workspace_root / run_id
        workspace.mkdir(parents=True, exist_ok=False)
        executable = (
            sys.executable
            if Path(argv[0]).name.lower().startswith("python")
            else shutil.which(argv[0])
        )
        if not executable:
            raise SandboxRuntimeError("approved executable is unavailable")
        environment = {
            "PATH": os.path.dirname(sys.executable),
            "PYTHONNOUSERSITE": "1",
            "PYTHONDONTWRITEBYTECODE": "1",
        }
        try:
            process = await asyncio.create_subprocess_exec(
                executable,
                *argv[1:],
                cwd=workspace,
                env=environment,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            return await self._communicate(process, timeout)
        finally:
            shutil.rmtree(workspace, ignore_errors=True)

    def _validate_image(self, image: str | None) -> str:
        selected_image = image or self.settings.docker_image
        if selected_image != self.settings.docker_image:
            raise SandboxPolicyError("image is outside the deployment allowlist")
        if self.settings.env in {"production", "prod"} and "@sha256:" not in selected_image:
            raise SandboxPolicyError("production sandbox images must be pinned by digest")
        return selected_image

    async def _run_docker(
        self, argv: list[str], timeout: int, run_id: str, image: str | None
    ) -> dict[str, Any]:
        selected_image = self._validate_image(image)
        docker_executable = shutil.which("docker")
        if not docker_executable:
            raise SandboxRuntimeError(
                "Docker CLI is unavailable; run the API on a dedicated runner host or keep dry_run mode"
            )
        container_name = "vulnlab-" + run_id[:12]
        command = [
            docker_executable,
            "run",
            "--rm",
            "--name",
            container_name,
            "--network",
            "none",
            "--read-only",
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges:true",
            "--pids-limit",
            "64",
            "--memory",
            "256m",
            "--cpus",
            "0.5",
            "--user",
            "65534:65534",
            "--tmpfs",
            "/tmp:rw,noexec,nosuid,size=32m",
            selected_image,
            *argv,
        ]
        started = False
        try:
            process = await asyncio.create_subprocess_exec(
                *command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            started = True
            return await self._communicate(process, timeout)
        except OSError as exc:
            raise SandboxRuntimeError("Docker sandbox process could not be started") from exc
        finally:
            if started:
                try:
                    cleanup = await asyncio.create_subprocess_exec(
                        docker_executable,
                        "rm",
                        "-f",
                        container_name,
                        stdout=asyncio.subprocess.DEVNULL,
                        stderr=asyncio.subprocess.DEVNULL,
                    )
                    await cleanup.wait()
                except OSError:
                    pass
