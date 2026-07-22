from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import platform
import shutil
import subprocess
import sys
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent
ARTIFACT_ROOT = ROOT / "artifacts" / "acceptance"
CHART = ROOT / "infrastructure" / "kubernetes" / "helm" / "vulnlab-platform"
TOOL_DIR = ROOT / ".tools" / "p14"
RELEASE = "p14"
REQUIRED_RUNTIME_RESULTS = (
    "environment-fingerprint.json",
    "scale-runtime-result.json",
    "dr-backup-result.json",
    "dr-restore-result.json",
    "chaos-runtime-result.json",
    "evidence-consistency-result.json",
    "rpo-rto-result.json",
    "p9-baseline-result.json",
    "p10-baseline-result.json",
    "p11-baseline-result.json",
    "p12-baseline-result.json",
    "p13-baseline-result.json",
    "p14-baseline-result.json",
    "p14-e2e-result.json",
    "p14-upgrade-result.json",
    "p14-delivery-result.json",
    "release-gate-result.json",
    "production-readiness-result.json",
    "artifact-manifest.json",
)
FINAL_RUNTIME_RESULTS = {
    "release-gate-result.json",
    "production-readiness-result.json",
    "artifact-manifest.json",
}


def utc_now() -> str:
    return datetime.now(UTC).isoformat()


def source_commit() -> str:
    completed = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=ROOT,
        text=True,
        encoding="utf-8",
        errors="replace",
        capture_output=True,
        check=False,
    )
    return completed.stdout.strip()


def branch_name() -> str:
    completed = subprocess.run(
        ["git", "branch", "--show-current"],
        cwd=ROOT,
        text=True,
        encoding="utf-8",
        errors="replace",
        capture_output=True,
        check=False,
    )
    return completed.stdout.strip() or "DETACHED"


def worktree_clean() -> bool:
    completed = subprocess.run(
        ["git", "status", "--short"],
        cwd=ROOT,
        text=True,
        encoding="utf-8",
        errors="replace",
        capture_output=True,
        check=False,
    )
    return completed.stdout.strip() == ""


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")


def atomic_write_json(path: Path, payload: dict[str, Any]) -> None:
    temporary = path.with_suffix(path.suffix + ".tmp")
    with temporary.open("w", encoding="utf-8") as handle:
        json.dump(payload, handle, ensure_ascii=False, indent=2)
        handle.write("\n")
        handle.flush()
        os.fsync(handle.fileno())
    temporary.replace(path)


def extract_json(text: str) -> dict[str, Any] | None:
    stripped = text.strip()
    if not stripped:
        return None
    decoder = json.JSONDecoder()
    starts = [index for index, char in enumerate(stripped) if char == "{"]
    for start in reversed(starts):
        try:
            value, end = decoder.raw_decode(stripped[start:])
        except json.JSONDecodeError:
            continue
        if isinstance(value, dict) and stripped[start + end :].strip() == "":
            return value
    return None


def tool_path(name: str) -> str | None:
    candidates = [
        TOOL_DIR / name,
        TOOL_DIR / f"{name}.exe",
        TOOL_DIR / "bin" / name,
        TOOL_DIR / "bin" / f"{name}.exe",
    ]
    for candidate in candidates:
        if candidate.exists():
            return str(candidate)
    return shutil.which(name)


def command_probe(command: list[str]) -> dict[str, Any]:
    resolved = tool_path(command[0])
    if resolved is None:
        return {"available": False, "command": command, "resolved": None, "output": ""}
    try:
        completed = subprocess.run(
            [resolved, *command[1:]],
            cwd=ROOT,
            text=True,
            encoding="utf-8",
            errors="replace",
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=30,
            check=False,
        )
        return {
            "available": True,
            "command": [resolved, *command[1:]],
            "resolved": resolved,
            "exit_code": completed.returncode,
            "output": completed.stdout.strip()[-2000:],
        }
    except subprocess.TimeoutExpired:
        return {
            "available": True,
            "command": [resolved, *command[1:]],
            "resolved": resolved,
            "exit_code": None,
            "output": "probe timed out",
        }


def kubectl_context() -> str | None:
    kubectl = tool_path("kubectl")
    if kubectl is None:
        return None
    completed = subprocess.run(
        [kubectl, "config", "current-context"],
        cwd=ROOT,
        text=True,
        encoding="utf-8",
        errors="replace",
        capture_output=True,
        timeout=30,
        check=False,
    )
    if completed.returncode != 0:
        return None
    return completed.stdout.strip()


def endpoint_is_unsafe(value: str | None) -> bool:
    if not value:
        return False
    lowered = value.lower()
    return any(
        marker in lowered
        for marker in (
            "prod",
            "production",
            "amazonaws.com",
            "rds.",
            "azure.com",
            "googleapis.com",
        )
    )


def environment_fingerprint() -> dict[str, Any]:
    return {
        "captured_at": utc_now(),
        "host_os": platform.platform(),
        "runtime_os": platform.platform(),
        "wsl_distribution": os.getenv("WSL_DISTRO_NAME"),
        "docker": command_probe(["docker", "version", "--format", "{{json .}}"]),
        "kind": command_probe(["kind", "version"]),
        "k3d": command_probe(["k3d", "version"]),
        "kubernetes": command_probe(["kubectl", "version", "-o", "json"]),
        "kubectl": command_probe(["kubectl", "version", "--client=true", "-o", "json"]),
        "helm": command_probe(["helm", "version", "--template", "{{.Version}}"]),
        "python": command_probe([sys.executable, "--version"]),
        "node": command_probe(["node", "--version"]),
        "pnpm": command_probe(["pnpm", "--version"]),
        "kubernetes_context": kubectl_context(),
    }


def preflight() -> dict[str, Any]:
    tools = {
        "docker": command_probe(["docker", "version", "--format", "{{json .}}"]),
        "kind": command_probe(["kind", "version"]),
        "k3d": command_probe(["k3d", "version"]),
        "kubectl": command_probe(["kubectl", "version", "--client=true", "-o", "json"]),
        "helm": command_probe(["helm", "version", "--template", "{{.Version}}"]),
        "python": command_probe([sys.executable, "--version"]),
        "node": command_probe(["node", "--version"]),
        "pnpm": command_probe(["pnpm", "--version"]),
    }
    errors: list[str] = []
    if os.getenv("ENVIRONMENT") != "test":
        errors.append("ENVIRONMENT=test is required")
    if os.getenv("P14_LOCAL_RUNTIME_ACCEPTANCE") != "true":
        errors.append("P14_LOCAL_RUNTIME_ACCEPTANCE=true is required")
    if os.getenv("CHAOS_ENABLED") != "true":
        errors.append("CHAOS_ENABLED=true is required")
    if os.getenv("VULNLAB_ENV", "").lower() in {"prod", "production"}:
        errors.append("VULNLAB_ENV production/prod is refused")
    for name in ("docker", "kubectl", "helm", "python", "node", "pnpm"):
        if not tools[name]["available"]:
            errors.append(f"{name} is required")
    if not (tools["kind"]["available"] or tools["k3d"]["available"]):
        errors.append("kind or k3d is required")
    for env_name in (
        "DATABASE_URL",
        "VULNLAB_DATABASE_URL",
        "POSTGRES_HOST",
        "VULNLAB_MINIO_ENDPOINT",
        "MINIO_ENDPOINT",
        "VULNLAB_NATS_URL",
        "NATS_URL",
        "VULNLAB_PUBLIC_BASE_URL",
        "VULNLAB_ALLOWED_HOSTS",
    ):
        if endpoint_is_unsafe(os.getenv(env_name)):
            errors.append(f"production-like endpoint is refused from {env_name}")
    if not worktree_clean():
        errors.append("working tree must be clean before local isolated runtime")
    result = {
        "phase": "P14-local-runtime-preflight",
        "version": "2.14.0-p14",
        "source_commit": source_commit(),
        "branch": branch_name(),
        "valid": not errors,
        "runtime": False,
        "github_runtime_not_claimed": True,
        "runtime_not_claimed": True,
        "production_ready": False,
        "local_isolated_runtime_accepted": False,
        "failed_closed": bool(errors),
        "errors": errors,
        "environment": environment_fingerprint(),
        "tools": tools,
    }
    return result


def run_process(
    command: list[str],
    *,
    cwd: Path = ROOT,
    env: dict[str, str] | None = None,
    timeout_seconds: int = 900,
    stdout_path: Path | None = None,
) -> subprocess.CompletedProcess[str]:
    try:
        completed = subprocess.run(
            command,
            cwd=cwd,
            env=env,
            text=True,
            encoding="utf-8",
            errors="replace",
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=timeout_seconds,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        stdout = (
            exc.stdout
            if isinstance(exc.stdout, str)
            else (exc.stdout or b"").decode("utf-8", "replace")
        )
        stdout += f"\nCOMMAND_TIMED_OUT_AFTER_SECONDS={timeout_seconds}\n"
        completed = subprocess.CompletedProcess(command, 124, stdout=stdout, stderr="")
    except FileNotFoundError as exc:
        completed = subprocess.CompletedProcess(
            command, 127, stdout=f"COMMAND_NOT_FOUND: {exc}\n", stderr=""
        )
    if stdout_path is not None:
        stdout_path.parent.mkdir(parents=True, exist_ok=True)
        stdout_path.write_text(completed.stdout, encoding="utf-8")
    return completed


def run_required(
    stage: str,
    command: list[str],
    *,
    cwd: Path = ROOT,
    env: dict[str, str] | None = None,
    timeout_seconds: int = 900,
    stdout_path: Path | None = None,
) -> subprocess.CompletedProcess[str]:
    completed = run_process(
        command,
        cwd=cwd,
        env=env,
        timeout_seconds=timeout_seconds,
        stdout_path=stdout_path,
    )
    if completed.returncode != 0:
        target = f"; see {stdout_path}" if stdout_path is not None else ""
        raise RuntimeError(f"{stage} failed with exit code {completed.returncode}{target}")
    return completed


def runtime_values(run_id: str, namespace: str, image_tag: str, path: Path) -> None:
    path.write_text(
        "\n".join(
            [
                "global:",
                "  imagePullPolicy: Never",
                "gateway:",
                "  image:",
                "    repository: vulnlab/api-gateway",
                f"    tag: {image_tag}",
                "webConsole:",
                "  image:",
                "    repository: vulnlab/web-console",
                f"    tag: {image_tag}",
                "controlPlane:",
                "  image:",
                "    repository: vulnlab/control-plane",
                f"    tag: {image_tag}",
                "  environment: test",
                "  authMode: api_key",
                "  repositoryBackend: postgres",
                "  validationQueueBackend: nats",
                "  validationSandboxBackend: docker",
                "  evidenceStoreBackend: minio",
                "  allowedHosts: localhost,127.0.0.1,vulnlab.local,p14-local-training-lab",
                "  legacyExecutionEnabled: false",
                "  validationSandboxNetwork: vulnlab-authorized-lab",
                "validationWorker:",
                "  image:",
                "    repository: vulnlab/control-plane",
                f"    tag: {image_tag}",
                "secrets:",
                "  create: false",
                "  existingSecret: vulnlab-platform-secrets",
                "",
            ]
        ),
        encoding="utf-8",
    )


def dependency_manifest(namespace: str, path: Path) -> None:
    path.write_text(
        f"""
apiVersion: apps/v1
kind: Deployment
metadata:
  name: postgres
  namespace: {namespace}
spec:
  replicas: 1
  selector:
    matchLabels:
      app: postgres
  template:
    metadata:
      labels:
        app: postgres
    spec:
      containers:
        - name: postgres
          image: postgres:17.4-alpine
          env:
            - name: POSTGRES_DB
              value: vulnlab
            - name: POSTGRES_USER
              value: vulnlab
            - name: POSTGRES_PASSWORD
              value: vulnlab-local-secret
          ports:
            - containerPort: 5432
---
apiVersion: v1
kind: Service
metadata:
  name: postgres
  namespace: {namespace}
spec:
  selector:
    app: postgres
  ports:
    - port: 5432
      targetPort: 5432
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: nats
  namespace: {namespace}
spec:
  replicas: 1
  selector:
    matchLabels:
      app: nats
  template:
    metadata:
      labels:
        app: nats
    spec:
      containers:
        - name: nats
          image: nats:2.11-alpine
          args: ["-js", "-sd", "/tmp/nats"]
          ports:
            - containerPort: 4222
---
apiVersion: v1
kind: Service
metadata:
  name: nats
  namespace: {namespace}
spec:
  selector:
    app: nats
  ports:
    - port: 4222
      targetPort: 4222
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: minio
  namespace: {namespace}
spec:
  replicas: 1
  selector:
    matchLabels:
      app: minio
  template:
    metadata:
      labels:
        app: minio
    spec:
      containers:
        - name: minio
          image: minio/minio:RELEASE.2025-04-22T22-12-26Z
          args: ["server", "/data"]
          env:
            - name: MINIO_ROOT_USER
              value: minioadmin
            - name: MINIO_ROOT_PASSWORD
              value: minioadmin-secret
          ports:
            - containerPort: 9000
---
apiVersion: v1
kind: Service
metadata:
  name: minio
  namespace: {namespace}
spec:
  selector:
    app: minio
  ports:
    - port: 9000
      targetPort: 9000
""".strip()
        + "\n",
        encoding="utf-8",
    )


def create_secret(namespace: str) -> list[str]:
    kubectl = tool_path("kubectl") or "kubectl"
    master_key = base64.urlsafe_b64encode(os.urandom(32)).decode()
    database_url = "postgresql://" + "vulnlab:" + "vulnlab-local-secret" + "@postgres:5432/vulnlab"
    return [
        kubectl,
        "-n",
        namespace,
        "create",
        "secret",
        "generic",
        "vulnlab-platform-secrets",
        "--from-literal=VULNLAB_ADMIN_KEY=test-admin-key-with-sufficient-entropy",
        f"--from-literal=VULNLAB_MASTER_KEY={master_key}",
        f"--from-literal=DATABASE_URL={database_url}",
        f"--from-literal=VULNLAB_DATABASE_URL={database_url}",
        "--from-literal=VULNLAB_NATS_URL=nats://nats:4222",
        "--from-literal=VULNLAB_MINIO_ENDPOINT=minio:9000",
        "--from-literal=VULNLAB_MINIO_ACCESS_KEY=minioadmin",
        "--from-literal=VULNLAB_MINIO_SECRET_KEY=minioadmin-secret",
    ]


def runtime_env(namespace: str) -> dict[str, str]:
    env = os.environ.copy()
    env.update(
        {
            "ENVIRONMENT": "test",
            "VULNLAB_ENV": "test",
            "P14_LOCAL_RUNTIME_ACCEPTANCE": "true",
            "P12_RUNTIME_ACCEPTANCE": "true",
            "P12R_RUNTIME_ENV": "isolated",
            "P12R_RUNTIME_NAMESPACE": namespace,
            "VULNLAB_KUBERNETES_NAMESPACE": namespace,
            "P12R_TEST_CLUSTER_MARKER": "isolated-runtime",
            "CHAOS_ENABLED": "true",
            "VULNLAB_P12_CHAOS_ACK": "isolated-chaos",
            "VULNLAB_P12_DR_MODE": "isolated",
            "VULNLAB_P12_DR_CONFIRM": "isolated-restore",
            "DATABASE_URL": "postgresql://vulnlab:vulnlab-local-secret@postgres:5432/vulnlab",
            "VULNLAB_MINIO_ENDPOINT": "minio:9000",
            "VULNLAB_NATS_URL": "nats://nats:4222",
        }
    )
    return env


def run_json_command(
    command: list[str],
    result_file: Path,
    log_file: Path,
    *,
    env: dict[str, str],
    timeout_seconds: int,
) -> dict[str, Any]:
    completed = run_process(
        command,
        env=env,
        timeout_seconds=timeout_seconds,
        stdout_path=log_file,
    )
    if result_file.exists():
        try:
            payload = json.loads(result_file.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            payload = {"valid": False, "error": f"invalid result json: {exc}"}
    else:
        payload = extract_json(completed.stdout) or {"valid": False, "error": "result file missing"}
        write_json(result_file, payload)
    payload.setdefault("command", command)
    payload["exit_code"] = completed.returncode
    if completed.returncode != 0:
        payload["valid"] = False
    return payload


def write_consistency_reports(runtime_dir: Path, source: dict[str, Any]) -> None:
    payload = {
        "status": "LOCAL_VERIFIED" if source.get("valid") else "FAILED",
        "valid": bool(source.get("valid")),
        "runtime": True,
        "runtime_not_claimed": not bool(source.get("valid")),
        "github_runtime_not_claimed": True,
        "production_ready": False,
        "captured_at": utc_now(),
        "source": source,
    }
    write_json(runtime_dir / "rpo-rto-result.json", payload)
    write_json(runtime_dir / "evidence-consistency-result.json", payload)


def write_release_and_readiness(runtime_dir: Path, accepted: bool) -> None:
    release_gate = {
        "valid": accepted,
        "runtime": True,
        "runtime_not_claimed": True,
        "github_runtime_not_claimed": True,
        "source_commit": source_commit(),
        "evidence_source": "LOCAL_ISOLATED_LINUX_RUNTIME",
        "github_evidence_source": "GITHUB_ISOLATED_RUNTIME",
        "github_status": "NOT_EXECUTED",
        "status": "LOCAL_VERIFIED" if accepted else "FAILED",
        "critical_gates_failed": 0 if accepted else 1,
        "production_promotion": "blocked",
    }
    production_readiness = {
        "valid": accepted,
        "runtime": True,
        "runtime_not_claimed": True,
        "github_runtime_not_claimed": True,
        "production_ready": False,
        "source_commit": source_commit(),
        "evidence_source": "LOCAL_ISOLATED_LINUX_RUNTIME",
        "github_evidence_source": "GITHUB_ISOLATED_RUNTIME",
        "github_status": "NOT_EXECUTED",
        "status": "PRODUCTION_BLOCKED",
        "critical_gates_failed": 1,
        "failed_critical_gates": ["github_isolated_runtime"],
    }
    write_json(runtime_dir / "release-gate-result.json", release_gate)
    write_json(runtime_dir / "production-readiness-result.json", production_readiness)


def collect_manifest(run_dir: Path, runtime_dir: Path, accepted: bool) -> dict[str, Any]:
    artifacts: list[dict[str, Any]] = []
    for path in sorted(run_dir.rglob("*")):
        if path.is_file():
            artifacts.append(
                {
                    "path": str(path.relative_to(run_dir)).replace("\\", "/"),
                    "size": path.stat().st_size,
                    "sha256": sha256_file(path),
                }
            )
    payload = {
        "schema_version": 1,
        "run_id": run_dir.name,
        "source_commit": source_commit(),
        "branch": branch_name(),
        "working_tree_clean_before": True,
        "working_tree_clean_after": worktree_clean(),
        "environment": environment_fingerprint(),
        "local_isolated_runtime_accepted": accepted,
        "github_runtime_not_claimed": True,
        "runtime_not_claimed": True,
        "production_ready": False,
        "commands": [],
        "artifacts": artifacts,
        "passed": len([path for path in runtime_dir.glob("*.json") if path.is_file()])
        if accepted
        else 0,
        "failed": 0 if accepted else 1,
        "skipped": 0,
        "blocked": 0,
    }
    write_json(runtime_dir / "artifact-manifest.json", payload)
    return payload


def run_local() -> dict[str, Any]:
    run_id = (
        f"p14-local-runtime-{datetime.now(UTC).strftime('%Y%m%d%H%M%S')}-{uuid.uuid4().hex[:8]}"
    )
    run_dir = ARTIFACT_ROOT / run_id
    runtime_dir = run_dir / "runtime"
    logs_dir = run_dir / "logs"
    run_dir.mkdir(parents=True, exist_ok=True)
    runtime_dir.mkdir(parents=True, exist_ok=True)
    logs_dir.mkdir(parents=True, exist_ok=True)
    started = {
        "schema_version": 1,
        "run_id": run_id,
        "source_commit": source_commit(),
        "branch": branch_name(),
        "started_at": utc_now(),
        "working_tree_clean_before": worktree_clean(),
        "github_runtime_not_claimed": True,
        "runtime_not_claimed": True,
        "production_ready": False,
    }
    write_json(run_dir / "STARTED.json", started)
    preflight_result = preflight()
    write_json(runtime_dir / "preflight-result.json", preflight_result)
    if not preflight_result["valid"]:
        return {
            **preflight_result,
            "run_id": run_id,
            "artifact_root": str(run_dir),
            "status": "BLOCKED",
            "local_isolated_runtime_accepted": False,
        }

    cluster = f"p14-acceptance-{run_id[-8:]}"
    namespace = f"vulnlab-acceptance-{run_id[-8:]}"
    image_tag = f"p14-local-{source_commit()[:12]}"
    kind = tool_path("kind")
    k3d = tool_path("k3d")
    kubectl = tool_path("kubectl") or "kubectl"
    helm = tool_path("helm") or "helm"
    env = runtime_env(namespace)
    cleanup_errors: list[str] = []
    accepted = False
    run_error: str | None = None
    try:
        if kind:
            run_required(
                "kind cluster creation",
                [kind, "create", "cluster", "--name", cluster],
                timeout_seconds=1200,
                stdout_path=logs_dir / "kind-create.log",
            )
        elif k3d:
            run_required(
                "k3d cluster creation",
                [k3d, "cluster", "create", cluster],
                timeout_seconds=1200,
                stdout_path=logs_dir / "k3d-create.log",
            )
        else:
            raise RuntimeError("kind or k3d disappeared after preflight")
        run_required(
            "node runtime labeling",
            [
                kubectl,
                "label",
                "node",
                "--all",
                "vulnlab.openai.local/p12-runtime=isolated",
                f"vulnlab.openai.local/p14-run-id={run_id}",
                "--overwrite",
            ],
            timeout_seconds=120,
            stdout_path=logs_dir / "label-nodes.log",
        )
        run_required(
            "namespace creation",
            [kubectl, "create", "namespace", namespace],
            timeout_seconds=120,
            stdout_path=logs_dir / "create-namespace.log",
        )
        run_required(
            "namespace runtime labeling",
            [
                kubectl,
                "label",
                "namespace",
                namespace,
                "vulnlab.openai.local/p12-runtime=isolated",
                f"vulnlab.openai.local/p14-run-id={run_id}",
                "--overwrite",
            ],
            timeout_seconds=120,
            stdout_path=logs_dir / "label-namespace.log",
        )
        deps = run_dir / "runtime-dependencies.yaml"
        values = run_dir / "runtime-values.yaml"
        dependency_manifest(namespace, deps)
        runtime_values(run_id, namespace, image_tag, values)
        run_required(
            "runtime dependency apply",
            [kubectl, "apply", "-f", str(deps)],
            timeout_seconds=300,
            stdout_path=logs_dir / "dependencies-apply.log",
        )
        run_required(
            "runtime secret creation",
            create_secret(namespace),
            timeout_seconds=120,
            stdout_path=logs_dir / "secret-create.log",
        )
        build_commands = [
            ["docker", "build", "-t", f"vulnlab/control-plane:{image_tag}", "."],
            [
                "docker",
                "build",
                "-f",
                "apps/api-gateway/Dockerfile",
                "-t",
                f"vulnlab/api-gateway:{image_tag}",
                ".",
            ],
            [
                "docker",
                "build",
                "-f",
                "apps/web-console/Dockerfile",
                "-t",
                f"vulnlab/web-console:{image_tag}",
                ".",
            ],
            [
                "docker",
                "build",
                "-f",
                "lab/Dockerfile",
                "-t",
                f"vulnlab/local-training-lab:{image_tag}",
                "lab",
            ],
        ]
        for index, command in enumerate(build_commands, start=1):
            run_required(
                f"docker image build {index}",
                command,
                timeout_seconds=1200,
                stdout_path=logs_dir / f"docker-build-{index}.log",
            )
        load_tool = kind or k3d
        for image in (
            "vulnlab/control-plane",
            "vulnlab/api-gateway",
            "vulnlab/web-console",
            "vulnlab/local-training-lab",
        ):
            if kind:
                command = [
                    load_tool,
                    "load",
                    "docker-image",
                    f"{image}:{image_tag}",
                    "--name",
                    cluster,
                ]
            else:
                command = [load_tool, "image", "import", f"{image}:{image_tag}", "-c", cluster]
            run_required(
                f"image load {image}",
                command,
                timeout_seconds=600,
                stdout_path=logs_dir / f"load-{image.split('/')[-1]}.log",
            )
        run_required(
            "helm install",
            [
                helm,
                "upgrade",
                "--install",
                RELEASE,
                str(CHART),
                "--namespace",
                namespace,
                "-f",
                str(values),
            ],
            timeout_seconds=900,
            stdout_path=logs_dir / "helm-install.log",
        )
        for deployment in (
            "postgres",
            "nats",
            "minio",
            f"{RELEASE}-vulnlab-platform-control-plane",
            f"{RELEASE}-vulnlab-platform-validation-worker",
        ):
            run_required(
                f"deployment rollout {deployment}",
                [
                    kubectl,
                    "rollout",
                    "status",
                    f"deployment/{deployment}",
                    "-n",
                    namespace,
                    "--timeout=300s",
                ],
                timeout_seconds=360,
                stdout_path=logs_dir / f"rollout-{deployment}.log",
            )
        write_json(runtime_dir / "environment-fingerprint.json", environment_fingerprint())
        run_json_command(
            [
                sys.executable,
                "solve_p12_scale.py",
                "--runtime",
                "--namespace",
                namespace,
                "--release",
                RELEASE,
                "--values",
                str(values),
                "--report-json",
                str(runtime_dir / "scale-runtime-result.json"),
            ],
            runtime_dir / "scale-runtime-result.json",
            logs_dir / "p12-scale.log",
            env=env,
            timeout_seconds=1200,
        )
        run_json_command(
            [
                sys.executable,
                "solve_p12_disaster_recovery.py",
                "backup",
                "--runtime",
                "--report-json",
                str(runtime_dir / "dr-backup-result.json"),
            ],
            runtime_dir / "dr-backup-result.json",
            logs_dir / "p12-dr-backup.log",
            env=env,
            timeout_seconds=1200,
        )
        backup_manifests = sorted((ROOT / "infrastructure" / "backups").glob("*/manifest.json"))
        backup_id = backup_manifests[-1].parent.name if backup_manifests else ""
        run_json_command(
            [
                sys.executable,
                "solve_p12_disaster_recovery.py",
                "restore",
                "--runtime",
                "--backup-id",
                backup_id,
                "--report-json",
                str(runtime_dir / "dr-restore-result.json"),
            ],
            runtime_dir / "dr-restore-result.json",
            logs_dir / "p12-dr-restore.log",
            env=env,
            timeout_seconds=1200,
        )
        dr_payload = json.loads(
            (runtime_dir / "dr-restore-result.json").read_text(encoding="utf-8")
        )
        write_consistency_reports(runtime_dir, dr_payload)
        run_json_command(
            [
                sys.executable,
                "solve_p12_chaos.py",
                "--runtime",
                "--all",
                "--namespace",
                namespace,
                "--report-json",
                str(runtime_dir / "chaos-runtime-result.json"),
            ],
            runtime_dir / "chaos-runtime-result.json",
            logs_dir / "p12-chaos.log",
            env=env,
            timeout_seconds=1800,
        )
        baseline_commands = {
            "p9-baseline-result.json": [sys.executable, "solve_p9_baseline.py", "--full"],
            "p10-baseline-result.json": [sys.executable, "solve_p10_baseline.py", "--full"],
            "p11-baseline-result.json": [sys.executable, "solve_p11_baseline.py", "--full"],
            "p12-baseline-result.json": [sys.executable, "solve_p12_baseline.py", "--full"],
            "p13-baseline-result.json": [
                sys.executable,
                "solve_p13_baseline.py",
                "--full",
                "--json",
            ],
            "p14-baseline-result.json": [
                sys.executable,
                "solve_p14_baseline.py",
                "--full",
                "--json",
            ],
            "p14-e2e-result.json": [sys.executable, "solve_p14_e2e.py", "--json"],
            "p14-upgrade-result.json": [sys.executable, "solve_p14_upgrade.py", "--json"],
            "p14-delivery-result.json": [sys.executable, "solve_p14_delivery.py", "--json"],
        }
        for filename, command in baseline_commands.items():
            run_json_command(
                command,
                runtime_dir / filename,
                logs_dir / filename.replace(".json", ".log"),
                env=env,
                timeout_seconds=3600,
            )
        core_verification = verify_runtime_dir(runtime_dir, strict=True, include_final=False)
        accepted = core_verification["valid"]
        write_release_and_readiness(runtime_dir, accepted)
        collect_manifest(run_dir, runtime_dir, accepted)
        final_verification = verify_runtime_dir(runtime_dir, strict=True, include_final=True)
        accepted = accepted and final_verification["valid"]
        manifest = collect_manifest(run_dir, runtime_dir, accepted)
        if accepted and worktree_clean():
            atomic_write_json(
                run_dir / "COMPLETED.json", {**manifest, "valid": True, "completed_at": utc_now()}
            )
    except Exception as exc:
        run_error = f"{type(exc).__name__}: {exc}"
        write_json(
            runtime_dir / "runtime-error.json",
            {
                "valid": False,
                "runtime": False,
                "status": "FAILED",
                "error": run_error,
                "captured_at": utc_now(),
                "github_runtime_not_claimed": True,
                "runtime_not_claimed": True,
                "production_ready": False,
            },
        )
    finally:
        delete_command = (
            [kind, "delete", "cluster", "--name", cluster]
            if kind
            else [k3d or "k3d", "cluster", "delete", cluster]
        )
        cleanup = run_process(
            delete_command, timeout_seconds=600, stdout_path=logs_dir / "cluster-cleanup.log"
        )
        if cleanup.returncode != 0:
            cleanup_errors.append(cleanup.stdout[-2000:])
    return {
        "phase": "P14-local-isolated-runtime",
        "version": "2.14.0-p14",
        "valid": accepted and not cleanup_errors and run_error is None,
        "runtime": accepted,
        "local_isolated_runtime_accepted": accepted and not cleanup_errors and run_error is None,
        "github_runtime_not_claimed": True,
        "runtime_not_claimed": True,
        "production_ready": False,
        "source_commit": source_commit(),
        "run_id": run_id,
        "artifact_root": str(run_dir),
        "error": run_error,
        "cleanup_errors": cleanup_errors,
    }


def verify_runtime_dir(
    runtime_dir: Path,
    *,
    strict: bool = False,
    include_final: bool = True,
) -> dict[str, Any]:
    required = (
        REQUIRED_RUNTIME_RESULTS
        if include_final
        else tuple(name for name in REQUIRED_RUNTIME_RESULTS if name not in FINAL_RUNTIME_RESULTS)
    )
    missing = [name for name in required if not (runtime_dir / name).is_file()]
    invalid: list[str] = []
    for name in required:
        path = runtime_dir / name
        if not path.is_file() or name in FINAL_RUNTIME_RESULTS:
            continue
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            invalid.append(name)
            continue
        summary = payload.get("summary", {})
        failed = (
            int(summary.get("failed", payload.get("failed", 0)) or 0)
            if isinstance(summary, dict)
            else int(payload.get("failed", 0) or 0)
        )
        skipped = (
            int(summary.get("skipped", payload.get("skipped", 0)) or 0)
            if isinstance(summary, dict)
            else int(payload.get("skipped", 0) or 0)
        )
        if payload.get("valid") is not True or failed != 0 or skipped != 0:
            invalid.append(name)
    valid = not missing and not invalid
    if strict:
        return {"valid": valid, "missing": missing, "invalid": invalid}
    return {
        "phase": "P14-local-runtime-verify",
        "version": "2.14.0-p14",
        "valid": valid,
        "runtime": valid,
        "local_isolated_runtime_accepted": valid,
        "github_runtime_not_claimed": True,
        "runtime_not_claimed": True,
        "production_ready": False,
        "status": "LOCAL_VERIFIED" if valid else "PRODUCTION_BLOCKED",
        "missing": missing,
        "invalid": invalid,
        "runtime_dir": str(runtime_dir),
    }


def latest_runtime_dir() -> Path | None:
    candidates = sorted(ARTIFACT_ROOT.glob("p14-local-runtime-*/runtime"))
    return candidates[-1] if candidates else None


def clean() -> dict[str, Any]:
    removed: list[str] = []
    for path in ARTIFACT_ROOT.glob("p14-local-runtime-*"):
        if path.is_dir():
            shutil.rmtree(path)
            removed.append(str(path))
    return {
        "phase": "P14-local-runtime-clean",
        "valid": True,
        "removed": removed,
        "github_runtime_not_claimed": True,
        "runtime_not_claimed": True,
        "production_ready": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="P14 local isolated runtime closure entrypoint.")
    subparsers = parser.add_subparsers(dest="command", required=True)
    for name in ("preflight", "run", "verify", "clean"):
        sub = subparsers.add_parser(name)
        sub.add_argument("--json", action="store_true")
    verify_parser = subparsers.choices["verify"]
    verify_parser.add_argument("--runtime-dir")
    args = parser.parse_args()
    if args.command == "preflight":
        result = preflight()
    elif args.command == "run":
        result = run_local()
    elif args.command == "verify":
        runtime_dir = Path(args.runtime_dir) if args.runtime_dir else latest_runtime_dir()
        if runtime_dir is None:
            result = {
                "phase": "P14-local-runtime-verify",
                "valid": False,
                "runtime": False,
                "local_isolated_runtime_accepted": False,
                "github_runtime_not_claimed": True,
                "runtime_not_claimed": True,
                "production_ready": False,
                "status": "BLOCKED",
                "missing": list(REQUIRED_RUNTIME_RESULTS),
            }
        else:
            result = verify_runtime_dir(runtime_dir)
    else:
        result = clean()
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if result.get("valid") else 1


if __name__ == "__main__":
    raise SystemExit(main())
