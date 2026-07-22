from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import re
import shutil
import subprocess
import sys
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent
ARTIFACT_ROOT = ROOT / "artifacts" / "acceptance"
FORBIDDEN_SECRET_PATTERNS = (
    re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    re.compile(
        r"(?:VULNLAB_MASTER_KEY|MINIO_SECRET_KEY|NATS_PASSWORD)\s*=\s*[\"']?[A-Za-z0-9+/_=-]{20,}"
    ),
    re.compile(r"DATABASE_URL\s*=\s*[\"']?postgres(?:ql)?://[^:@\s]+:[^@\s]+@"),
    re.compile(r"\bsk-[A-Za-z0-9_-]{20,}\b"),
)


@dataclass(frozen=True)
class CommandSpec:
    command_id: str
    command: list[str]
    timeout_seconds: int = 900
    parse_json: bool = True


def utc_now() -> str:
    return datetime.now(UTC).isoformat()


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


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
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    with temporary.open("w", encoding="utf-8") as handle:
        json.dump(payload, handle, ensure_ascii=False, indent=2)
        handle.write("\n")
        handle.flush()
        os.fsync(handle.fileno())
    temporary.replace(path)


def run_git(args: list[str]) -> str:
    completed = subprocess.run(
        ["git", *args],
        cwd=ROOT,
        text=True,
        encoding="utf-8",
        errors="replace",
        capture_output=True,
        check=False,
    )
    return completed.stdout.strip()


def source_commit() -> str:
    return run_git(["rev-parse", "HEAD"])


def branch_name() -> str:
    branch = run_git(["branch", "--show-current"])
    return branch or "DETACHED"


def worktree_clean() -> bool:
    return run_git(["status", "--short"]) == ""


def probe(command: list[str]) -> dict[str, Any]:
    executable = shutil.which(command[0])
    if executable is None:
        return {"available": False, "command": command, "resolved": None, "output": ""}
    try:
        completed = subprocess.run(
            [executable, *command[1:]],
            cwd=ROOT,
            text=True,
            encoding="utf-8",
            errors="replace",
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=20,
            check=False,
        )
        output = completed.stdout.strip()[-2000:]
        return {
            "available": True,
            "command": [executable, *command[1:]],
            "resolved": executable,
            "exit_code": completed.returncode,
            "output": output,
        }
    except subprocess.TimeoutExpired:
        return {
            "available": True,
            "command": [executable, *command[1:]],
            "resolved": executable,
            "exit_code": None,
            "output": "probe timed out",
        }


def environment_fingerprint() -> dict[str, Any]:
    return {
        "captured_at": utc_now(),
        "host_os": platform.platform(),
        "runtime_os": platform.platform(),
        "wsl_distribution": os.getenv("WSL_DISTRO_NAME"),
        "docker": probe(["docker", "version", "--format", "{{json .}}"]),
        "kind_or_k3d": {
            "kind": probe(["kind", "version"]),
            "k3d": probe(["k3d", "version"]),
        },
        "kubernetes": probe(["kubectl", "version", "-o", "json"]),
        "kubectl": probe(["kubectl", "version", "--client=true", "-o", "json"]),
        "helm": probe(["helm", "version", "--template", "{{.Version}}"]),
        "python": probe([sys.executable, "--version"]),
        "node": probe(["node", "--version"]),
        "pnpm": probe(["pnpm", "--version"]),
    }


def command_specs(full: bool) -> list[CommandSpec]:
    python = sys.executable
    specs = [
        CommandSpec("p0_baseline", [python, "solve_p0_baseline.py"], 600),
        CommandSpec("p1_baseline", [python, "solve_p1_baseline.py"], 600),
        CommandSpec("p2_baseline", [python, "solve_p2_baseline.py"], 600),
        CommandSpec("p3_baseline", [python, "solve_p3_baseline.py"], 600),
        CommandSpec("p4_baseline", [python, "solve_p4_baseline.py"], 600),
        CommandSpec("p5_baseline", [python, "solve_p5_baseline.py"], 600),
        CommandSpec("p6_baseline", [python, "solve_p6_baseline.py"], 600),
        CommandSpec("p7_baseline", [python, "solve_p7_baseline.py"], 600),
        CommandSpec("p8_baseline", [python, "solve_p8_baseline.py"], 600),
        CommandSpec("p9_baseline_full", [python, "solve_p9_baseline.py", "--full"], 1800),
        CommandSpec("p9_runtime", [python, "solve_p9_runtime.py"], 1800),
        CommandSpec("p9_hardening", [python, "solve_p9_hardening.py"], 1800),
        CommandSpec("p10_baseline_full", [python, "solve_p10_baseline.py", "--full"], 1800),
        CommandSpec("p11_baseline_full", [python, "solve_p11_baseline.py", "--full"], 1800),
        CommandSpec("p12_baseline_full", [python, "solve_p12_baseline.py", "--full"], 2400),
        CommandSpec(
            "p13_baseline_full",
            [python, "solve_p13_baseline.py", "--full", "--json"],
            2400,
        ),
        CommandSpec(
            "p14_baseline_full",
            [python, "solve_p14_baseline.py", "--full", "--json"],
            3600,
        ),
        CommandSpec("p14_e2e", [python, "solve_p14_e2e.py", "--json"], 900),
        CommandSpec("p14_upgrade", [python, "solve_p14_upgrade.py", "--json"], 600),
        CommandSpec("p14_delivery", [python, "solve_p14_delivery.py", "--json"], 600),
        CommandSpec("pytest", [python, "-m", "pytest", "-q", "-rs"], 2400, False),
        CommandSpec("mypy", [python, "-m", "mypy", "apps/control-plane/src"], 600, False),
        CommandSpec("ruff_format", [python, "-m", "ruff", "format", "--check", "."], 600, False),
        CommandSpec("ruff_check", [python, "-m", "ruff", "check", "."], 600, False),
        CommandSpec("pnpm_lint", ["pnpm", "lint"], 1200, False),
        CommandSpec("pnpm_typecheck", ["pnpm", "typecheck"], 1200, False),
        CommandSpec("pnpm_test", ["pnpm", "test"], 1200, False),
        CommandSpec("pnpm_build", ["pnpm", "build"], 1200, False),
        CommandSpec(
            "openapi_runtime_snapshot",
            [python, "tools/contracts/openapi_snapshot.py", "check", "--runtime"],
            600,
        ),
        CommandSpec("migration_check", [python, "tools/contracts/check_migrations.py"], 600),
        CommandSpec(
            "helm_lint",
            ["helm", "lint", "infrastructure/kubernetes/helm/vulnlab-platform", "--strict"],
            600,
            False,
        ),
        CommandSpec(
            "helm_template",
            [
                "helm",
                "template",
                "p14",
                "infrastructure/kubernetes/helm/vulnlab-platform",
                "--namespace",
                "vulnlab",
                "--set",
                "global.imagePullPolicy=Never",
            ],
            600,
            False,
        ),
        CommandSpec("git_diff_check", ["git", "diff", "--check"], 600, False),
    ]
    if not full:
        return specs[:10]
    return specs


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


def result_counts(parsed: dict[str, Any] | None) -> tuple[int, int, int]:
    if not parsed:
        return (0, 0, 0)
    summary = parsed.get("summary")
    if isinstance(summary, dict):
        return (
            int(summary.get("passed", 0) or summary.get("total", 0) or 0),
            int(summary.get("failed", 0) or 0),
            int(summary.get("skipped", 0) or 0),
        )
    return (
        int(parsed.get("passed", 0) or 0),
        int(parsed.get("failed", 0) or 0),
        int(parsed.get("skipped", 0) or 0),
    )


def classify_command(
    *,
    exit_code: int | None,
    timed_out: bool,
    parsed: dict[str, Any] | None,
    executable_available: bool,
) -> str:
    if not executable_available:
        return "BLOCKED"
    if timed_out:
        return "FAILED"
    if exit_code != 0:
        return "FAILED"
    if parsed is not None:
        _, failed, skipped = result_counts(parsed)
        if parsed.get("valid") is False or failed > 0 or skipped > 0:
            return "FAILED"
    return "VERIFIED"


def run_command(spec: CommandSpec, run_dir: Path) -> dict[str, Any]:
    command_dir = run_dir / "commands" / spec.command_id
    command_dir.mkdir(parents=True, exist_ok=True)
    stdout_path = command_dir / "stdout.txt"
    stderr_path = command_dir / "stderr.txt"
    result_path = command_dir / "result.json"
    started_at = utc_now()
    resolved = shutil.which(spec.command[0])
    if resolved is None and Path(spec.command[0]).exists():
        resolved = spec.command[0]
    executable_available = resolved is not None
    command = [resolved, *spec.command[1:]] if resolved is not None else spec.command
    exit_code: int | None = None
    timed_out = False
    stdout = ""
    stderr = ""
    if executable_available:
        try:
            completed = subprocess.run(
                command,
                cwd=ROOT,
                text=True,
                encoding="utf-8",
                errors="replace",
                capture_output=True,
                timeout=spec.timeout_seconds,
                check=False,
            )
            exit_code = completed.returncode
            stdout = completed.stdout
            stderr = completed.stderr
        except subprocess.TimeoutExpired as exc:
            timed_out = True
            stdout = (
                exc.stdout
                if isinstance(exc.stdout, str)
                else (exc.stdout or b"").decode("utf-8", "replace")
            )
            stderr = (
                exc.stderr
                if isinstance(exc.stderr, str)
                else (exc.stderr or b"").decode("utf-8", "replace")
            )
        except FileNotFoundError as exc:
            executable_available = False
            stderr = f"COMMAND_NOT_FOUND: {exc}\n"
    else:
        stderr = f"COMMAND_NOT_FOUND: {spec.command[0]}\n"
    finished_at = utc_now()
    stdout_path.write_text(stdout, encoding="utf-8")
    stderr_path.write_text(stderr, encoding="utf-8")
    parsed = extract_json(stdout) if spec.parse_json else None
    if parsed is not None:
        write_json(result_path, parsed)
    status = classify_command(
        exit_code=exit_code,
        timed_out=timed_out,
        parsed=parsed,
        executable_available=executable_available,
    )
    record = {
        "command_id": spec.command_id,
        "command": command,
        "requested_command": spec.command,
        "working_directory": str(ROOT),
        "started_at": started_at,
        "finished_at": finished_at,
        "duration_ms": int(
            (
                datetime.fromisoformat(finished_at) - datetime.fromisoformat(started_at)
            ).total_seconds()
            * 1000
        ),
        "exit_code": exit_code,
        "signal": exit_code if isinstance(exit_code, int) and exit_code < 0 else None,
        "timed_out": timed_out,
        "stdout_path": str(stdout_path.relative_to(run_dir)),
        "stderr_path": str(stderr_path.relative_to(run_dir)),
        "result_path": str(result_path.relative_to(run_dir)) if parsed is not None else None,
        "sha256": {
            "stdout": sha256_file(stdout_path),
            "stderr": sha256_file(stderr_path),
            "result": sha256_file(result_path) if parsed is not None else None,
        },
        "status": status,
    }
    write_json(command_dir / "command.json", record)
    return record


def secret_scan(run_dir: Path) -> dict[str, Any]:
    started_at = utc_now()
    report_path = run_dir / "reports" / "secret-scan-result.json"
    hits: list[dict[str, str]] = []
    scanned_suffixes = {".py", ".ts", ".tsx", ".js", ".json", ".yaml", ".yml", ".md", ".toml"}
    ignored_parts = {
        ".git",
        ".venv",
        "node_modules",
        ".turbo",
        "artifacts",
        "work",
        "dist",
        "build",
        ".tools",
        "tests",
    }
    for path in ROOT.rglob("*"):
        if not path.is_file() or path.suffix.lower() not in scanned_suffixes:
            continue
        relative_parts = set(path.relative_to(ROOT).parts)
        if relative_parts & ignored_parts:
            continue
        text = path.read_text(encoding="utf-8", errors="ignore")
        for pattern in FORBIDDEN_SECRET_PATTERNS:
            if pattern.search(text):
                hits.append({"path": str(path.relative_to(ROOT)), "pattern": pattern.pattern})
    payload = {
        "valid": not hits,
        "failed": len(hits),
        "skipped": 0,
        "hits": hits,
        "scanned_at": utc_now(),
    }
    write_json(report_path, payload)
    finished_at = utc_now()
    return {
        "command_id": "secret_scan",
        "command": ["internal:secret_scan"],
        "working_directory": str(ROOT),
        "started_at": started_at,
        "finished_at": finished_at,
        "duration_ms": int(
            (
                datetime.fromisoformat(finished_at) - datetime.fromisoformat(started_at)
            ).total_seconds()
            * 1000
        ),
        "exit_code": 0 if payload["valid"] else 1,
        "signal": None,
        "timed_out": False,
        "stdout_path": None,
        "stderr_path": None,
        "result_path": str(report_path.relative_to(run_dir)),
        "sha256": {"result": sha256_file(report_path)},
        "status": "VERIFIED" if payload["valid"] else "FAILED",
    }


def artifact_records(run_dir: Path) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for path in sorted(run_dir.rglob("*")):
        if not path.is_file():
            continue
        relative = str(path.relative_to(run_dir)).replace("\\", "/")
        if relative == "COMPLETED.json":
            continue
        records.append(
            {
                "path": relative,
                "size": path.stat().st_size,
                "sha256": sha256_file(path),
            }
        )
    return records


def run(full: bool, output: str | None = None) -> dict[str, Any]:
    run_id = f"p14-local-{datetime.now(UTC).strftime('%Y%m%d%H%M%S')}-{uuid.uuid4().hex[:8]}"
    run_dir = ARTIFACT_ROOT / run_id
    for subdir in ("commands", "reports", "runtime", "delivery", "logs"):
        (run_dir / subdir).mkdir(parents=True, exist_ok=True)
    commit = source_commit()
    started = {
        "schema_version": 1,
        "run_id": run_id,
        "source_commit": commit,
        "branch": branch_name(),
        "started_at": utc_now(),
        "working_tree_clean_before": worktree_clean(),
        "github_runtime_not_claimed": True,
        "runtime_not_claimed": True,
        "production_ready": False,
    }
    write_json(run_dir / "STARTED.json", started)
    commands: list[dict[str, Any]] = []
    for spec in command_specs(full):
        commands.append(run_command(spec, run_dir))
    commands.append(secret_scan(run_dir))
    clean_after = worktree_clean()
    counts = {
        "passed": sum(1 for command in commands if command["status"] == "VERIFIED"),
        "failed": sum(1 for command in commands if command["status"] == "FAILED"),
        "skipped": 0,
        "blocked": sum(1 for command in commands if command["status"] == "BLOCKED"),
    }
    manifest = {
        "schema_version": 1,
        "run_id": run_id,
        "source_commit": commit,
        "branch": branch_name(),
        "working_tree_clean_before": started["working_tree_clean_before"],
        "working_tree_clean_after": clean_after,
        "environment": environment_fingerprint(),
        "local_isolated_runtime_accepted": False,
        "github_runtime_not_claimed": True,
        "runtime_not_claimed": True,
        "production_ready": False,
        "commands": commands,
        "artifacts": [],
        **counts,
    }
    manifest["artifacts"] = artifact_records(run_dir)
    write_json(run_dir / "artifact-manifest.json", manifest)
    valid = (
        counts["failed"] == 0
        and counts["blocked"] == 0
        and counts["skipped"] == 0
        and started["working_tree_clean_before"] is True
        and clean_after is True
    )
    completed = {
        **manifest,
        "valid": valid,
        "status": "VERIFIED" if valid else "FAILED",
        "completed_at": utc_now(),
    }
    if valid:
        atomic_write_json(run_dir / "COMPLETED.json", completed)
    if output:
        target = Path(output)
        if not target.is_absolute():
            target = ROOT / target
        write_json(target, completed)
    return completed


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Run P0-P14 from-scratch deterministic verification."
    )
    parser.add_argument(
        "--full", action="store_true", help="run the full required P0-P14 command matrix"
    )
    parser.add_argument("--json", action="store_true", help="emit JSON")
    parser.add_argument("--output", help="write the final manifest to a specific path")
    args = parser.parse_args()
    result = run(full=args.full, output=args.output)
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if result["valid"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
