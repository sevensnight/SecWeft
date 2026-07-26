#!/usr/bin/env python3
"""P12 isolated failure-injection acceptance entry point."""

from __future__ import annotations

import argparse
import asyncio
import base64
import json
import os
import shutil
import socket
import subprocess
import sys
import time
import uuid
from collections.abc import Callable
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlparse, urlunparse

ROOT = Path(__file__).resolve().parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

from tools.p12.runtime_acceptance import (  # noqa: E402
    environment_fingerprint,
    require_isolated_runtime,
    runtime_claimed,
    summarize_checks,
    utc_timestamp,
    write_report,
)

ALLOWED_TARGETS = {
    "control-plane",
    "idle-worker",
    "running-worker",
    "validation-worker",
    "nats",
    "postgres",
    "minio",
    "sandbox-timeout",
    "model-timeout",
    "duplicate-message",
    "poison-message",
    "delayed-message",
    "reordered-message",
}

FULL_RUNTIME_TARGETS = [
    "control-plane",
    "idle-worker",
    "running-worker",
    "nats",
    "postgres",
    "minio",
    "sandbox-timeout",
    "duplicate-message",
    "poison-message",
]


@dataclass(frozen=True, slots=True)
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


def _run(command: list[str], *, timeout_seconds: float = 300) -> subprocess.CompletedProcess[str]:
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


def _static_matrix_check() -> tuple[str, dict[str, Any]]:
    matrix = ROOT / "docs/testing/p12-chaos-matrix.md"
    text = matrix.read_text(encoding="utf-8") if matrix.is_file() else ""
    invariants = {
        "matrix_exists": matrix.is_file(),
        "production_guard_documented": "production" in text.lower() and "refuse" in text.lower(),
        "no_unbounded_retry": "bounded retry" in text.lower(),
        "targets_documented": all(target in text for target in ALLOWED_TARGETS),
    }
    errors = sorted(name for name, valid in invariants.items() if not valid)
    return ("PASS" if not errors else "FAIL"), {"invariants": invariants, "errors": errors}


def _kubectl_json(command: list[str], *, timeout_seconds: float = 120) -> dict[str, Any]:
    completed = _run(command, timeout_seconds=timeout_seconds)
    if completed.returncode != 0:
        return {
            "ok": False,
            "command": command,
            "returncode": completed.returncode,
            "output": completed.stdout[-4000:],
        }
    try:
        parsed = json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        return {
            "ok": False,
            "command": command,
            "returncode": completed.returncode,
            "output": completed.stdout[-4000:],
            "error": f"invalid json: {exc}",
        }
    return {"ok": True, "command": command, "returncode": 0, "json": parsed}


def _delete_component_pod(
    namespace: str, *, target: str, selector: str
) -> tuple[str, dict[str, Any]]:
    pods = _kubectl_json(
        ["kubectl", "get", "pods", "-n", namespace, "-l", selector, "-o", "json"],
        timeout_seconds=120,
    )
    if not pods["ok"]:
        return "FAIL", {
            "runtime_executed": False,
            "target": target,
            "selector": selector,
            "errors": ["target_discovery_failed"],
            "probe": pods,
        }
    items = pods["json"].get("items", [])
    if not items:
        return "FAIL", {
            "runtime_executed": False,
            "target": target,
            "selector": selector,
            "errors": ["target_not_found"],
        }
    pod_name = items[0]["metadata"]["name"]
    completed = _run(
        ["kubectl", "delete", "pod", pod_name, "-n", namespace, "--wait=false"],
        timeout_seconds=120,
    )
    return ("PASS" if completed.returncode == 0 else "FAIL"), {
        "runtime_executed": True,
        "target": target,
        "selector": selector,
        "pod": pod_name,
        "command": completed.args,
        "returncode": completed.returncode,
        "output": completed.stdout[-4000:],
        "post_condition": "rerun solve_p12_scale.py --runtime and P9-P12 runtime acceptance",
    }


def _free_local_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _wait_tcp(port: int, *, timeout_seconds: float = 20) -> None:
    deadline = time.time() + timeout_seconds
    last_error: Exception | None = None
    while time.time() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=1):
                return
        except OSError as exc:
            last_error = exc
            time.sleep(0.2)
    raise RuntimeError(f"port-forward did not become ready: {last_error}")


def _runtime_secret(namespace: str) -> dict[str, str]:
    secret_name = os.getenv("P12R_RUNTIME_SECRET_NAME", "vulnlab-platform-secrets")
    completed = _run(
        ["kubectl", "get", "secret", secret_name, "-n", namespace, "-o", "json"],
        timeout_seconds=60,
    )
    if completed.returncode != 0:
        raise RuntimeError(completed.stdout[-1000:])
    data = json.loads(completed.stdout).get("data", {})
    return {
        key: base64.b64decode(value).decode("utf-8")
        for key, value in data.items()
        if key in {"VULNLAB_NATS_URL"}
    }


def _port_forward_nats(namespace: str) -> tuple[subprocess.Popen[str], str]:
    local_port = _free_local_port()
    process = subprocess.Popen(
        [
            "kubectl",
            "port-forward",
            "svc/nats",
            f"{local_port}:4222",
            "-n",
            namespace,
        ],
        cwd=ROOT,
        text=True,
        encoding="utf-8",
        errors="replace",
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    try:
        _wait_tcp(local_port)
    except Exception:
        process.terminate()
        raise
    nats_url = _runtime_secret(namespace)["VULNLAB_NATS_URL"]
    parsed = urlparse(nats_url)
    replacement = parsed._replace(
        netloc=f"{parsed.username}:{parsed.password}@127.0.0.1:{local_port}"
    )
    return process, urlunparse(replacement)


def _runtime_timeout_job(namespace: str) -> tuple[str, dict[str, Any]]:
    image_probe = _kubectl_json(
        [
            "kubectl",
            "get",
            "deployment",
            "p12-vulnlab-platform-validation-worker",
            "-n",
            namespace,
            "-o",
            "json",
        ]
    )
    if not image_probe["ok"]:
        return "FAIL", {"runtime_executed": False, "errors": ["worker_image_lookup_failed"]}
    image = image_probe["json"]["spec"]["template"]["spec"]["containers"][0]["image"]
    job_name = f"p12r-timeout-{uuid.uuid4().hex[:8]}"
    manifest = {
        "apiVersion": "batch/v1",
        "kind": "Job",
        "metadata": {"name": job_name, "namespace": namespace},
        "spec": {
            "activeDeadlineSeconds": 2,
            "backoffLimit": 0,
            "template": {
                "spec": {
                    "restartPolicy": "Never",
                    "containers": [
                        {
                            "name": "timeout",
                            "image": image,
                            "command": ["python", "-c", "import time; time.sleep(30)"],
                        }
                    ],
                }
            },
        },
    }
    create = subprocess.run(
        ["kubectl", "apply", "-f", "-"],
        cwd=ROOT,
        input=json.dumps(manifest),
        text=True,
        encoding="utf-8",
        errors="replace",
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
        timeout=60,
    )
    failed = _run(
        [
            "kubectl",
            "wait",
            "--for=condition=failed",
            f"job/{job_name}",
            "-n",
            namespace,
            "--timeout=60s",
        ],
        timeout_seconds=90,
    )
    delete = _run(
        ["kubectl", "delete", "job", job_name, "-n", namespace, "--ignore-not-found=true"],
        timeout_seconds=60,
    )
    ok = create.returncode == 0 and failed.returncode == 0 and delete.returncode == 0
    return ("PASS" if ok else "FAIL"), {
        "runtime_executed": True,
        "target": "sandbox-timeout",
        "job": job_name,
        "image": image,
        "deadline_seconds": 2,
        "create_returncode": create.returncode,
        "wait_failed_returncode": failed.returncode,
        "delete_returncode": delete.returncode,
        "errors": [] if ok else ["timeout_job_did_not_fail_closed"],
    }


async def _nats_duplicate_probe(nats_url: str) -> dict[str, Any]:
    import nats
    from nats.js.api import StorageType, StreamConfig

    nc = await nats.connect(nats_url)
    js = nc.jetstream()
    suffix = uuid.uuid4().hex
    stream = f"P12R_DUP_{suffix}"
    subject = f"p12r.duplicate.{suffix}"
    await js.add_stream(
        config=StreamConfig(
            name=stream,
            subjects=[subject],
            storage=StorageType.MEMORY,
            duplicate_window=120,
        )
    )
    msg_id = f"p12r-duplicate-{suffix}"
    first = await js.publish(subject, b'{"runtime":"duplicate"}', headers={"Nats-Msg-Id": msg_id})
    second = await js.publish(subject, b'{"runtime":"duplicate"}', headers={"Nats-Msg-Id": msg_id})
    info = await js.stream_info(stream)
    await js.delete_stream(stream)
    await nc.close()
    return {
        "first_duplicate": bool(getattr(first, "duplicate", False)),
        "second_duplicate": bool(getattr(second, "duplicate", False)),
        "messages": int(info.state.messages),
    }


async def _nats_poison_probe(nats_url: str) -> dict[str, Any]:
    import nats
    from nats.js.api import AckPolicy, ConsumerConfig, StorageType, StreamConfig

    nc = await nats.connect(nats_url)
    js = nc.jetstream()
    suffix = uuid.uuid4().hex
    stream = f"P12R_POISON_{suffix}"
    subject = f"p12r.poison.{suffix}"
    durable = f"p12r-poison-{suffix[:8]}"
    await js.add_stream(
        config=StreamConfig(name=stream, subjects=[subject], storage=StorageType.MEMORY)
    )
    await js.add_consumer(
        stream,
        config=ConsumerConfig(durable_name=durable, ack_policy=AckPolicy.EXPLICIT, max_deliver=1),
    )
    await js.publish(subject, b"{not-json", headers={"Nats-Msg-Id": f"p12r-poison-{suffix}"})
    sub = await js.pull_subscribe(subject, durable=durable, stream=stream)
    poison = (await sub.fetch(1, timeout=5))[0]
    await poison.term()
    await js.publish(subject, b'{"replay":true}', headers={"Nats-Msg-Id": f"p12r-replay-{suffix}"})
    replay = (await sub.fetch(1, timeout=5))[0]
    await replay.ack()
    info = await js.consumer_info(stream, durable)
    await js.delete_stream(stream)
    await nc.close()
    return {
        "poison_terminated": True,
        "manual_replay_acked": True,
        "num_redelivered": int(info.num_redelivered),
    }


def _runtime_nats_probe(namespace: str, target: str) -> tuple[str, dict[str, Any]]:
    process: subprocess.Popen[str] | None = None
    try:
        process, nats_url = _port_forward_nats(namespace)
        if target == "duplicate-message":
            details = asyncio.run(_nats_duplicate_probe(nats_url))
            ok = details["second_duplicate"] is True and details["messages"] == 1
        else:
            details = asyncio.run(_nats_poison_probe(nats_url))
            ok = details["poison_terminated"] and details["manual_replay_acked"]
        return ("PASS" if ok else "FAIL"), {
            "runtime_executed": True,
            "target": target,
            "details": details,
            "errors": [] if ok else [f"{target}_probe_failed"],
        }
    except Exception as exc:
        return "FAIL", {
            "runtime_executed": True,
            "target": target,
            "errors": [f"{type(exc).__name__}: {exc}"],
        }
    finally:
        if process is not None:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()


def _runtime_guard(target: str | None, namespace: str) -> tuple[str, dict[str, Any]]:
    isolation_ok, isolation = require_isolated_runtime(chaos=True)
    if not isolation_ok:
        return "FAIL", {
            **isolation,
            "errors": ["runtime_precondition_failed", *isolation["errors"]],
        }
    if not target or target not in ALLOWED_TARGETS:
        return "FAIL", {
            "runtime_executed": False,
            "errors": [
                "runtime_precondition_failed",
                f"--target must be one of {sorted(ALLOWED_TARGETS)}",
            ],
        }
    if shutil.which("kubectl") is None:
        return "FAIL", {
            "runtime_executed": False,
            "errors": ["runtime_precondition_failed", "kubectl is required for runtime chaos"],
        }
    pod_targets = {
        "control-plane": "app.kubernetes.io/component=control-plane",
        "validation-worker": "app.kubernetes.io/component=validation-worker",
        "idle-worker": "app.kubernetes.io/component=validation-worker",
        "running-worker": "app.kubernetes.io/component=validation-worker",
        "nats": "app.kubernetes.io/name=nats",
        "postgres": "app.kubernetes.io/name=postgresql",
        "minio": "app.kubernetes.io/name=minio",
    }
    if target in pod_targets:
        return _delete_component_pod(namespace, target=target, selector=pod_targets[target])
    if target == "sandbox-timeout":
        return _runtime_timeout_job(namespace)
    if target in {"duplicate-message", "poison-message"}:
        return _runtime_nats_probe(namespace, target)
    return "FAIL", {
        "runtime_executed": False,
        "target": target,
        "errors": [
            "dedicated_runtime_workload_required",
            "this target requires live workload/NATS/sandbox injection; no implicit static pass is allowed",
        ],
    }


def _target_check_name(target: str) -> str:
    return f"chaos_runtime_{target.replace('-', '_')}"


def run(*, runtime: bool, target: str | None, namespace: str, all_targets: bool) -> dict[str, Any]:
    started_at = utc_timestamp()
    checks = [_timed("chaos_static_matrix", _static_matrix_check)]
    if runtime:
        selected_targets = FULL_RUNTIME_TARGETS if all_targets else [target]
        for selected in selected_targets:
            checks.append(
                _timed(
                    _target_check_name(str(selected)),
                    lambda selected=selected: _runtime_guard(selected, namespace),
                )
            )
    else:
        checks.append(
            CheckResult(
                name="chaos_runtime_not_claimed",
                status="PASS",
                duration_ms=0,
                details={
                    "runtime_not_claimed": True,
                    "how_to_run": (
                        "set CHAOS_ENABLED=true, ENVIRONMENT=test, "
                        "P12R_RUNTIME_ENV=isolated, "
                        "P12R_TEST_CLUSTER_MARKER=isolated-runtime, "
                        "VULNLAB_P12_CHAOS_ACK=isolated-chaos and run "
                        "python solve_p12_chaos.py --runtime --all"
                    ),
                },
            )
        )
    summary = summarize_checks(checks)
    claimed = runtime_claimed(runtime, checks)
    return {
        "phase": "P12-chaos",
        "version": "2.14.0-p14",
        "runtime": runtime,
        "runtime_not_claimed": not claimed,
        "started_at": started_at,
        "finished_at": utc_timestamp(),
        "environment": environment_fingerprint(),
        "valid": summary["failed"] == 0 and summary["skipped"] == 0,
        "summary": summary,
        "checks": [asdict(check) for check in checks],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runtime", action="store_true")
    parser.add_argument("--target", choices=sorted(ALLOWED_TARGETS))
    parser.add_argument("--all", action="store_true", help="run all P12-R chaos targets")
    parser.add_argument("--namespace", default="vulnlab")
    parser.add_argument("--report-json")
    args = parser.parse_args()
    result = run(
        runtime=args.runtime,
        target=args.target,
        namespace=args.namespace,
        all_targets=args.all,
    )
    write_report(args.report_json, result)
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if result["valid"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
