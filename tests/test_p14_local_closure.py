from __future__ import annotations

import json
from pathlib import Path

from solve_all_from_scratch import command_specs, extract_json
from solve_p14_local_authoritative import (
    FINAL_RUNTIME_RESULTS,
    REQUIRED_RUNTIME_RESULTS,
    verify_runtime_dir,
    write_json,
)

ROOT = Path(__file__).resolve().parents[1]


def test_p14_all_from_scratch_matrix_has_no_remote_mutation() -> None:
    specs = command_specs(full=True)
    command_ids = {spec.command_id for spec in specs}
    assert {
        "p9_baseline_full",
        "p10_baseline_full",
        "p11_baseline_full",
        "p12_baseline_full",
        "p13_baseline_full",
        "p14_baseline_full",
        "p14_e2e",
        "p14_upgrade",
        "p14_delivery",
        "helm_lint",
        "helm_template",
        "git_diff_check",
    } <= command_ids

    rendered = "\n".join(" ".join(spec.command) for spec in specs)
    forbidden = ("workflow_dispatch", "git push", "git tag", "gh workflow", "gh run")
    assert not any(marker in rendered for marker in forbidden)


def test_p14_all_from_scratch_extracts_terminal_json() -> None:
    payload = {"valid": True, "summary": {"failed": 0, "skipped": 0}}
    text = "prelude\n" + json.dumps(payload, ensure_ascii=False)
    assert extract_json(text) == payload


def test_p14_local_runtime_verify_requires_final_artifacts(tmp_path: Path) -> None:
    runtime_dir = tmp_path / "runtime"
    runtime_dir.mkdir()

    missing = verify_runtime_dir(runtime_dir)
    assert missing["valid"] is False
    assert missing["github_runtime_not_claimed"] is True
    assert missing["runtime_not_claimed"] is True
    assert missing["production_ready"] is False

    for name in REQUIRED_RUNTIME_RESULTS:
        if name in FINAL_RUNTIME_RESULTS:
            continue
        write_json(runtime_dir / name, {"valid": True, "failed": 0, "skipped": 0})

    core = verify_runtime_dir(runtime_dir, strict=True, include_final=False)
    assert core == {"valid": True, "missing": [], "invalid": []}
    final_missing = verify_runtime_dir(runtime_dir, strict=True, include_final=True)
    assert final_missing["valid"] is False
    assert set(final_missing["missing"]) == FINAL_RUNTIME_RESULTS

    write_json(runtime_dir / "release-gate-result.json", {"valid": True})
    write_json(runtime_dir / "production-readiness-result.json", {"production_ready": False})
    write_json(runtime_dir / "artifact-manifest.json", {"schema_version": 1})
    final = verify_runtime_dir(runtime_dir, strict=True, include_final=True)
    assert final == {"valid": True, "missing": [], "invalid": []}


def test_p14_evidence_sources_are_explicit_and_production_blocked() -> None:
    release = (ROOT / "apps/control-plane/src/vulnlab/release_governance.py").read_text(
        encoding="utf-8"
    )
    local_runtime = (ROOT / "solve_p14_local_authoritative.py").read_text(encoding="utf-8")
    workflow = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")

    for marker in (
        "GITHUB_ISOLATED_RUNTIME",
        "LOCAL_ISOLATED_LINUX_RUNTIME",
        "DETERMINISTIC_BASELINE",
    ):
        assert marker in release

    assert "production requires GitHub isolated authoritative runtime acceptance" in release
    assert '"github_runtime_not_claimed": True' in local_runtime
    assert '"runtime_not_claimed": True' in local_runtime
    assert '"production_ready": False' in local_runtime
    assert "production-readiness-result.json" in workflow
    assert "release-gate-result.json" in workflow
