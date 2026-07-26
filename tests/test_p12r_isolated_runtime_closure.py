from __future__ import annotations

import argparse
from pathlib import Path

import yaml

from tools.p12 import p12r_runtime
from tools.p12.runtime_acceptance import (
    _in_cluster_service_endpoint,
    _localhost_endpoint,
    _public_ip_endpoint,
    _unsafe_endpoint,
)

ROOT = Path(__file__).resolve().parents[1]
VALUES = ROOT / "infrastructure/kubernetes/acceptance/p12r/runtime-values.yaml"
CHART = ROOT / "infrastructure/kubernetes/helm/vulnlab-platform"
WORKFLOW = ROOT / ".github/workflows/ci.yml"


def test_p12r_acceptance_values_are_non_secret_test_runtime() -> None:
    values = yaml.safe_load(VALUES.read_text(encoding="utf-8"))
    assert values["controlPlane"]["environment"] == "test"
    assert values["controlPlane"]["replicaCount"] >= 3
    assert values["controlPlane"]["autoscaling"]["minReplicas"] >= 3
    assert values["validationWorker"]["replicaCount"] >= 3
    assert values["validationWorker"]["autoscaling"]["minReplicas"] >= 3
    assert values["runtimeSecrets"]["existingSecret"] == "vulnlab-platform-secrets"

    flattened = "\n".join(p12r_runtime._flatten_strings(values))
    forbidden = ("CHANGE_ME", "TODO", "example-password", "localhost", "127.0.0.1")
    assert not any(marker.lower() in flattened.lower() for marker in forbidden)
    for secret_marker in ("PASSWORD", "SECRET_KEY", "ACCESS_KEY", "GITHUB_TOKEN"):
        assert secret_marker not in flattened


def test_p12r_chart_uses_explicit_secret_key_refs() -> None:
    required = {
        "VULNLAB_ADMIN_KEY",
        "VULNLAB_MASTER_KEY",
        "DATABASE_URL",
        "VULNLAB_DATABASE_URL",
        "VULNLAB_NATS_URL",
        "VULNLAB_MINIO_ENDPOINT",
        "VULNLAB_MINIO_ACCESS_KEY",
        "VULNLAB_MINIO_SECRET_KEY",
    }
    control_plane = (CHART / "templates/deployment-control-plane.yaml").read_text(encoding="utf-8")
    worker = (CHART / "templates/deployment-validation-worker.yaml").read_text(encoding="utf-8")
    combined = control_plane + "\n" + worker
    assert "secretKeyRef" in combined
    assert "secretRef:" not in combined
    for key in required:
        assert f"key: {key}" in combined


def test_p12r_chart_sets_initial_replicas_even_with_hpa() -> None:
    control_plane = (CHART / "templates/deployment-control-plane.yaml").read_text(encoding="utf-8")
    worker = (CHART / "templates/deployment-validation-worker.yaml").read_text(encoding="utf-8")
    assert "replicas: {{ .Values.controlPlane.replicaCount }}" in control_plane
    assert "replicas: {{ .Values.validationWorker.replicaCount }}" in worker
    assert "if not .Values.controlPlane.autoscaling.enabled" not in control_plane
    assert "if not .Values.validationWorker.autoscaling.enabled" not in worker


def test_p12r_workflow_no_longer_requires_values_secret() -> None:
    workflow = WORKFLOW.read_text(encoding="utf-8")
    assert "P12R_RUNTIME_VALUES_B64 must contain" not in workflow
    assert "Decode optional runtime override values" in workflow
    assert "tools/p12/p12r_runtime.py write-inputs" in workflow
    assert "dependency-readiness-result.json" in workflow
    assert "artifact-secret-scan-result.json" in workflow
    assert "cleanup-result.json" in workflow


def test_p12r_values_schema_covers_runtime_inputs() -> None:
    schema = (CHART / "values.schema.json").read_text(encoding="utf-8")
    assert "runtimeSecrets" in schema
    assert "trainingLab" in schema
    assert "compatibility" in schema
    assert "oidc" in schema


def test_p12r_endpoint_guards_reject_external_or_local_targets() -> None:
    assert _unsafe_endpoint("postgres.production.example")
    assert _localhost_endpoint("http://localhost:9000")
    assert _localhost_endpoint("nats://127.0.0.1:4222")
    assert _public_ip_endpoint("postgresql://vulnlab@8.8.8.8:5432/vulnlab")
    assert _in_cluster_service_endpoint("postgres.vulnlab-1.svc.cluster.local:5432", "postgres")
    assert _in_cluster_service_endpoint("nats://nats:4222", "nats")
    assert not _in_cluster_service_endpoint("postgres.external.internal:5432", "postgres")


def test_p12r_artifact_scan_detects_runtime_secret_leak(tmp_path: Path) -> None:
    secret = tmp_path / "runtime-secret.yaml"
    artifact_dir = tmp_path / "artifacts"
    artifact_dir.mkdir()
    secret.write_text(
        yaml.safe_dump(
            {
                "apiVersion": "v1",
                "kind": "Secret",
                "stringData": {
                    "VULNLAB_ADMIN_KEY": "admin_test_secret_value",
                    "POSTGRES_PASSWORD": "pg_test_secret_value",
                    "POSTGRES_USER": "vulnlab",
                },
            }
        ),
        encoding="utf-8",
    )
    (artifact_dir / "safe.json").write_text('{"valid": true}', encoding="utf-8")
    report = artifact_dir / "artifact-secret-scan-result.json"
    rc = p12r_runtime.scan_artifacts(
        argparse.Namespace(
            artifact_dir=str(artifact_dir),
            secret_manifest=str(secret),
            report_json=str(report),
        )
    )
    assert rc == 0

    (artifact_dir / "leaky.log").write_text("admin_test_secret_value", encoding="utf-8")
    rc = p12r_runtime.scan_artifacts(
        argparse.Namespace(
            artifact_dir=str(artifact_dir),
            secret_manifest=str(secret),
            report_json=str(report),
        )
    )
    result = yaml.safe_load(report.read_text(encoding="utf-8"))
    assert rc == 1
    assert result["valid"] is False
    assert result["leaks"] == [{"path": "leaky.log", "secret_key": "VULNLAB_ADMIN_KEY"}]
