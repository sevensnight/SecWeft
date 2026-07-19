#!/usr/bin/env python3
"""P12 backup, restore, and disaster-recovery acceptance entry point."""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import time
from collections.abc import Callable
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

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


def _run(command: list[str], *, timeout_seconds: float = 900) -> subprocess.CompletedProcess[str]:
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


def _required_files() -> tuple[str, dict[str, Any]]:
    required = [
        "infrastructure/scripts/backup.sh",
        "infrastructure/scripts/restore.sh",
        "infrastructure/scripts/backup.ps1",
        "infrastructure/scripts/restore.ps1",
        "docs/operations/p12-backup-restore-runbook.md",
        "docs/operations/p12-disaster-recovery-runbook.md",
        "docs/acceptance/p12-acceptance-report.md",
    ]
    missing = [path for path in required if not (ROOT / path).is_file()]
    return ("PASS" if not missing else "FAIL"), {"required": required, "missing": missing}


def _backup_manifest_check() -> tuple[str, dict[str, Any]]:
    root = ROOT / "infrastructure/backups"
    manifests = sorted(root.glob("*/manifest.json")) if root.is_dir() else []
    latest = manifests[-1] if manifests else None
    parsed: dict[str, Any] | None = None
    if latest is not None:
        parsed = json.loads(latest.read_text(encoding="utf-8").lstrip("\ufeff"))
    valid_latest = parsed is None or (
        parsed.get("schema_version") == 1
        and parsed.get("platform") == "vulnlab-platform"
        and isinstance(parsed.get("files"), list)
    )
    return ("PASS" if valid_latest else "FAIL"), {
        "manifest_count": len(manifests),
        "latest_manifest": str(latest.relative_to(ROOT)).replace("\\", "/") if latest else None,
        "latest_valid": valid_latest,
        "rpo_target_minutes": 15,
        "rto_target_minutes": 60,
        "sla_claimed": False,
    }


def _runtime_backup() -> tuple[str, dict[str, Any]]:
    isolation_ok, isolation = require_isolated_runtime()
    if not isolation_ok:
        return "FAIL", {
            **isolation,
            "errors": ["runtime_precondition_failed", *isolation["errors"]],
        }
    if os.getenv("VULNLAB_P12_DR_MODE") != "isolated":
        return "FAIL", {
            "runtime_executed": False,
            "errors": [
                "runtime_precondition_failed",
                "VULNLAB_P12_DR_MODE=isolated is required for runtime backup drills",
            ],
        }
    if shutil.which("docker") is None:
        return "FAIL", {
            "runtime_executed": False,
            "errors": ["runtime_precondition_failed", "docker is required for the runtime drill"],
        }
    if shutil.which("sh") is None:
        return "FAIL", {
            "runtime_executed": False,
            "errors": ["runtime_precondition_failed", "POSIX sh is required for Linux runtime"],
        }
    backup_root = os.getenv("VULNLAB_P12_DR_BACKUP_ROOT", "infrastructure/backups")
    started_at = utc_timestamp()
    timer = time.perf_counter()
    completed = _run(["sh", "infrastructure/scripts/backup.sh", backup_root], timeout_seconds=1200)
    elapsed_ms = round((time.perf_counter() - timer) * 1000)
    return ("PASS" if completed.returncode == 0 else "FAIL"), {
        "runtime_executed": True,
        "command": "sh infrastructure/scripts/backup.sh",
        "returncode": completed.returncode,
        "output": completed.stdout[-12000:],
        "rpo_target_minutes": 15,
        "started_at": started_at,
        "finished_at": utc_timestamp(),
        "measured_backup_elapsed_ms": elapsed_ms,
        "rpo_sla_claimed": False,
    }


def _runtime_restore(backup_id: str | None) -> tuple[str, dict[str, Any]]:
    isolation_ok, isolation = require_isolated_runtime()
    if not isolation_ok:
        return "FAIL", {
            **isolation,
            "errors": ["runtime_precondition_failed", *isolation["errors"]],
        }
    if os.getenv("VULNLAB_P12_DR_MODE") != "isolated":
        return "FAIL", {
            "runtime_executed": False,
            "errors": [
                "runtime_precondition_failed",
                "VULNLAB_P12_DR_MODE=isolated is required for runtime restore drills",
            ],
        }
    if os.getenv("VULNLAB_P12_DR_CONFIRM") != "isolated-restore":
        return "FAIL", {
            "runtime_executed": False,
            "errors": [
                "runtime_precondition_failed",
                "VULNLAB_P12_DR_CONFIRM=isolated-restore is required for restore",
            ],
        }
    if not backup_id:
        return "FAIL", {
            "runtime_executed": False,
            "errors": ["runtime_precondition_failed", "--backup-id is required for restore"],
        }
    if shutil.which("sh") is None:
        return "FAIL", {
            "runtime_executed": False,
            "errors": ["runtime_precondition_failed", "POSIX sh is required for Linux runtime"],
        }
    backup_root = Path(os.getenv("VULNLAB_P12_DR_BACKUP_ROOT", "infrastructure/backups"))
    backup_dir = backup_root / backup_id
    if not backup_dir.is_dir():
        return "FAIL", {
            "runtime_executed": False,
            "errors": ["runtime_precondition_failed", f"backup directory not found: {backup_dir}"],
        }
    started_at = utc_timestamp()
    timer = time.perf_counter()
    completed = _run(["sh", "infrastructure/scripts/restore.sh", "--yes", str(backup_dir)])
    elapsed_ms = round((time.perf_counter() - timer) * 1000)
    baseline = (
        _run([sys.executable, "solve_p12_baseline.py", "--full"], timeout_seconds=1800)
        if completed.returncode == 0
        else None
    )
    restore_passed = completed.returncode == 0 and baseline is not None and baseline.returncode == 0
    return ("PASS" if restore_passed else "FAIL"), {
        "runtime_executed": True,
        "command": "sh infrastructure/scripts/restore.sh --yes",
        "returncode": completed.returncode,
        "output": completed.stdout[-12000:],
        "baseline_after_restore": {
            "command": [sys.executable, "solve_p12_baseline.py", "--full"],
            "returncode": baseline.returncode if baseline is not None else None,
            "output": baseline.stdout[-12000:] if baseline is not None else "",
        }
        if completed.returncode == 0
        else None,
        "restore_passed": restore_passed,
        "rto_target_minutes": 60,
        "started_at": started_at,
        "finished_at": utc_timestamp(),
        "measured_restore_elapsed_ms": elapsed_ms,
        "rto_sla_claimed": False,
    }


def run(command: str, *, runtime: bool, backup_id: str | None) -> dict[str, Any]:
    started_at = utc_timestamp()
    checks = [
        _timed("dr_required_files", _required_files),
        _timed("dr_backup_manifest_readiness", _backup_manifest_check),
    ]
    if command == "backup":
        checks.append(
            _timed(
                "runtime_backup_drill" if runtime else "backup_runtime_not_claimed",
                _runtime_backup
                if runtime
                else lambda: (
                    "PASS",
                    {
                        "runtime_not_claimed": True,
                        "how_to_run": (
                            "set VULNLAB_P12_DR_MODE=isolated and run "
                            "python solve_p12_disaster_recovery.py backup --runtime"
                        ),
                    },
                ),
            )
        )
    elif command == "restore":
        checks.append(
            _timed(
                "runtime_restore_drill" if runtime else "restore_runtime_not_claimed",
                (lambda: _runtime_restore(backup_id))
                if runtime
                else lambda: (
                    "PASS",
                    {
                        "runtime_not_claimed": True,
                        "how_to_run": (
                            "set VULNLAB_P12_DR_MODE=isolated and "
                            "VULNLAB_P12_DR_CONFIRM=isolated-restore, then run restore --runtime"
                        ),
                    },
                ),
            )
        )
    else:
        checks.append(
            CheckResult(
                name="dr_runtime_not_claimed",
                status="PASS",
                duration_ms=0,
                details={
                    "runtime_not_claimed": True,
                    "rpo_target_minutes": 15,
                    "rto_target_minutes": 60,
                },
            )
        )
    summary = summarize_checks(checks)
    claimed = runtime_claimed(runtime, checks)
    return {
        "phase": "P12-DR",
        "version": "2.14.0-p14",
        "command": command,
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
    parser.add_argument(
        "command", nargs="?", choices=("check", "backup", "restore"), default="check"
    )
    parser.add_argument("--runtime", action="store_true", help="execute an isolated runtime drill")
    parser.add_argument("--backup-id")
    parser.add_argument("--report-json")
    args = parser.parse_args()
    result = run(args.command, runtime=args.runtime, backup_id=args.backup_id)
    write_report(args.report_json, result)
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if result["valid"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
