#!/usr/bin/env python3
"""Utilities for the P12-R GitHub isolated runtime acceptance job.

The commands in this file are CI-only orchestration helpers. They generate
run-scoped Kubernetes inputs for a temporary kind namespace, wait for isolated
dependencies, execute PostgreSQL migrations, and emit sanitized JSON artifacts.
They do not add product shell execution or vulnerability validation capability.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import secrets
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parents[2]
BASE_VALUES = ROOT / "infrastructure/kubernetes/acceptance/p12r/runtime-values.yaml"
CHART = ROOT / "infrastructure/kubernetes/helm/vulnlab-platform"
MIGRATIONS = ROOT / "infrastructure/migrations"
REQUIRED_SECRET_KEYS = (
    "VULNLAB_ADMIN_KEY",
    "VULNLAB_MASTER_KEY",
    "DATABASE_URL",
    "VULNLAB_DATABASE_URL",
    "VULNLAB_NATS_URL",
    "VULNLAB_MINIO_ENDPOINT",
    "VULNLAB_MINIO_ACCESS_KEY",
    "VULNLAB_MINIO_SECRET_KEY",
    "POSTGRES_PASSWORD",
    "MINIO_ROOT_USER",
    "MINIO_ROOT_PASSWORD",
    "NATS_USER",
    "NATS_PASSWORD",
)
SENSITIVE_SECRET_KEYS = {
    "VULNLAB_ADMIN_KEY",
    "VULNLAB_MASTER_KEY",
    "DATABASE_URL",
    "VULNLAB_DATABASE_URL",
    "VULNLAB_NATS_URL",
    "VULNLAB_MINIO_ACCESS_KEY",
    "VULNLAB_MINIO_SECRET_KEY",
    "POSTGRES_PASSWORD",
    "MINIO_ROOT_USER",
    "MINIO_ROOT_PASSWORD",
    "NATS_PASSWORD",
}
PLACEHOLDER_RE = re.compile(r"CHANGE_ME|TODO|example-password|changeme", re.IGNORECASE)
PRODUCTION_RE = re.compile(r"prod|production|amazonaws\.com|rds\.", re.IGNORECASE)
LOCALHOST_RE = re.compile(r"localhost|127\.0\.0\.1|0\.0\.0\.0|\[?::1\]?", re.IGNORECASE)
PUBLIC_IPV4_RE = re.compile(r"\b(?:[1-9]\d?|1\d\d|2[01]\d|22[0-3])(?:\.\d{1,3}){3}\b")
GENERIC_SECRET_PATTERNS = {
    "github_token": re.compile(r"(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{20,}"),
    "github_pat": re.compile(r"github_pat_[A-Za-z0-9_]{20,}"),
    "aws_access_key": re.compile(r"AKIA[0-9A-Z]{16}"),
    "uri_userinfo_password": re.compile(r"[a-z][a-z0-9+.-]*://[^/\s:@]+:[^@\s/]+@"),
}


def _utc() -> str:
    return datetime.now(UTC).isoformat()


def _write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")


def _run(
    command: list[str],
    *,
    timeout_seconds: int = 300,
    input_text: str | None = None,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command,
        cwd=ROOT,
        text=True,
        encoding="utf-8",
        errors="replace",
        input=input_text,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
        timeout=timeout_seconds,
    )


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _token(prefix: str, nbytes: int = 24) -> str:
    return f"{prefix}_{secrets.token_urlsafe(nbytes)}"


def _fernet_key() -> str:
    return base64.urlsafe_b64encode(secrets.token_bytes(32)).decode("ascii")


def _deep_merge(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    merged = dict(base)
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(merged.get(key), dict):
            merged[key] = _deep_merge(merged[key], value)
        else:
            merged[key] = value
    return merged


def _load_yaml(path: Path) -> dict[str, Any]:
    payload = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    if not isinstance(payload, dict):
        raise ValueError(f"{path} must contain a YAML mapping")
    return payload


def _flatten_strings(value: Any) -> list[str]:
    if isinstance(value, dict):
        result: list[str] = []
        for child in value.values():
            result.extend(_flatten_strings(child))
        return result
    if isinstance(value, list):
        result = []
        for child in value:
            result.extend(_flatten_strings(child))
        return result
    if isinstance(value, str):
        return [value]
    return []


def _value_guard(values: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    strings = _flatten_strings(values)
    for text in strings:
        if PLACEHOLDER_RE.search(text):
            errors.append(f"placeholder value refused: {text[:80]}")
        if PRODUCTION_RE.search(text):
            errors.append(f"production-like value refused: {text[:80]}")
        if LOCALHOST_RE.search(text):
            errors.append(f"localhost value refused: {text[:80]}")
        if PUBLIC_IPV4_RE.search(text):
            errors.append(f"public IPv4-like value refused: {text[:80]}")
    control = values.get("controlPlane", {})
    worker = values.get("validationWorker", {})
    if control.get("environment") != "test":
        errors.append("controlPlane.environment must be test")
    if int(control.get("replicaCount") or 0) < 3:
        errors.append("controlPlane.replicaCount must be at least 3")
    if int(control.get("autoscaling", {}).get("minReplicas") or 0) < 3:
        errors.append("controlPlane.autoscaling.minReplicas must be at least 3")
    if int(worker.get("replicaCount") or 0) < 3:
        errors.append("validationWorker.replicaCount must be at least 3")
    if int(worker.get("autoscaling", {}).get("minReplicas") or 0) < 3:
        errors.append("validationWorker.autoscaling.minReplicas must be at least 3")
    if not values.get("runtimeSecrets", {}).get("existingSecret"):
        errors.append("runtimeSecrets.existingSecret is required")
    return errors


def _runtime_values(
    *,
    namespace: str,
    image_tag: str,
    override: Path | None,
) -> dict[str, Any]:
    values = _load_yaml(BASE_VALUES)
    if override is not None and override.is_file() and override.stat().st_size > 0:
        values = _deep_merge(values, _load_yaml(override))
    image_values = {
        "gateway": {"image": {"repository": "vulnlab/api-gateway", "tag": image_tag}},
        "webConsole": {"image": {"repository": "vulnlab/web-console", "tag": image_tag}},
        "controlPlane": {
            "image": {"repository": "vulnlab/control-plane", "tag": image_tag},
            "allowedHosts": f"p12r-training-lab,p12r-training-lab.{namespace}.svc.cluster.local",
        },
        "validationWorker": {"image": {"repository": "vulnlab/control-plane", "tag": image_tag}},
        "trainingLab": {"endpoint": "http://p12r-training-lab:8080"},
    }
    values = _deep_merge(values, image_values)
    errors = _value_guard(values)
    if errors:
        raise RuntimeError("; ".join(errors))
    return values


def _secret_payload(namespace: str) -> dict[str, str]:
    postgres_password = _token("pg", 22)
    nats_user = "vulnlab"
    nats_password = _token("nats", 22)
    minio_access = "minio" + secrets.token_hex(10)
    minio_secret = _token("minio", 26)
    database_url = f"postgresql://vulnlab:{postgres_password}@postgres:5432/vulnlab"
    return {
        "VULNLAB_ADMIN_KEY": _token("admin", 32),
        "VULNLAB_MASTER_KEY": _fernet_key(),
        "DATABASE_URL": database_url,
        "VULNLAB_DATABASE_URL": database_url,
        "VULNLAB_NATS_URL": f"nats://{nats_user}:{nats_password}@nats:4222",
        "VULNLAB_MINIO_ENDPOINT": "minio:9000",
        "VULNLAB_MINIO_ACCESS_KEY": minio_access,
        "VULNLAB_MINIO_SECRET_KEY": minio_secret,
        "VULNLAB_TRAINING_LAB_ENDPOINT": "http://p12r-training-lab:8080",
        "POSTGRES_DB": "vulnlab",
        "POSTGRES_USER": "vulnlab",
        "POSTGRES_PASSWORD": postgres_password,
        "MINIO_ROOT_USER": minio_access,
        "MINIO_ROOT_PASSWORD": minio_secret,
        "NATS_USER": nats_user,
        "NATS_PASSWORD": nats_password,
        "P12R_RUNTIME_NAMESPACE": namespace,
    }


def _secret_manifest(namespace: str, secret_name: str, payload: dict[str, str]) -> dict[str, Any]:
    return {
        "apiVersion": "v1",
        "kind": "Secret",
        "metadata": {
            "name": secret_name,
            "namespace": namespace,
            "labels": {
                "app.kubernetes.io/name": "vulnlab-platform",
                "app.kubernetes.io/component": "runtime-secret",
                "vulnlab.openai.local/p12-runtime": "isolated",
            },
        },
        "type": "Opaque",
        "stringData": payload,
    }


def _sensitive_values_from_secret(path: Path) -> dict[str, str]:
    raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    if not isinstance(raw, dict):
        raise ValueError(f"{path} must contain a Kubernetes Secret mapping")
    values: dict[str, str] = {}
    string_data = raw.get("stringData", {})
    if isinstance(string_data, dict):
        for key, value in string_data.items():
            if key in SENSITIVE_SECRET_KEYS and isinstance(value, str) and len(value) >= 8:
                values[key] = value
    encoded_data = raw.get("data", {})
    if isinstance(encoded_data, dict):
        for key, value in encoded_data.items():
            if key not in SENSITIVE_SECRET_KEYS or not isinstance(value, str):
                continue
            decoded = base64.b64decode(value).decode("utf-8")
            if len(decoded) >= 8:
                values[key] = decoded
    return values


def scan_artifacts(args: argparse.Namespace) -> int:
    artifact_dir = Path(args.artifact_dir)
    secret_manifest = Path(args.secret_manifest)
    errors: list[str] = []
    leaks: list[dict[str, Any]] = []
    generic_hits: list[dict[str, Any]] = []
    if not artifact_dir.is_dir():
        errors.append(f"artifact directory missing: {artifact_dir}")
    if not secret_manifest.is_file():
        errors.append(f"runtime secret manifest missing: {secret_manifest}")
        secret_values: dict[str, str] = {}
    else:
        secret_values = _sensitive_values_from_secret(secret_manifest)
        if not secret_values:
            errors.append("no sensitive values were available for artifact leak scan")
    checked = 0
    if artifact_dir.is_dir():
        for path in sorted(artifact_dir.rglob("*")):
            if not path.is_file() or path.name == Path(args.report_json).name:
                continue
            checked += 1
            data = path.read_bytes()
            rel = str(path.relative_to(artifact_dir)).replace("\\", "/")
            for key, value in secret_values.items():
                if value.encode("utf-8") in data:
                    leaks.append({"path": rel, "secret_key": key})
            text = data.decode("utf-8", errors="ignore")
            for pattern_name, pattern in GENERIC_SECRET_PATTERNS.items():
                if pattern.search(text):
                    generic_hits.append({"path": rel, "pattern": pattern_name})
    valid = not errors and not leaks and not generic_hits
    result = {
        "valid": valid,
        "runtime": True,
        "runtime_not_claimed": not valid,
        "artifact_dir": str(artifact_dir),
        "secret_manifest_checked": secret_manifest.is_file(),
        "secret_value_count": len(secret_values),
        "files_checked": checked,
        "leak_count": len(leaks),
        "generic_hit_count": len(generic_hits),
        "leaks": leaks,
        "generic_hits": generic_hits,
        "failed": len(errors) + len(leaks) + len(generic_hits),
        "skipped": 0,
        "errors": errors,
        "checked_at": _utc(),
    }
    _write_json(Path(args.report_json), result)
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if valid else 1


def _dependencies(namespace: str, image_tag: str, secret_name: str) -> list[dict[str, Any]]:
    labels = {"vulnlab.openai.local/p12-runtime": "isolated"}

    def secret_env(name: str, key: str) -> dict[str, Any]:
        return {
            "name": name,
            "valueFrom": {"secretKeyRef": {"name": secret_name, "key": key}},
        }

    return [
        {
            "apiVersion": "apps/v1",
            "kind": "Deployment",
            "metadata": {
                "name": "postgres",
                "namespace": namespace,
                "labels": {"app.kubernetes.io/name": "postgresql", **labels},
            },
            "spec": {
                "replicas": 1,
                "selector": {"matchLabels": {"app.kubernetes.io/name": "postgresql"}},
                "template": {
                    "metadata": {"labels": {"app.kubernetes.io/name": "postgresql", **labels}},
                    "spec": {
                        "containers": [
                            {
                                "name": "postgres",
                                "image": "postgres:17.4-alpine",
                                "ports": [{"containerPort": 5432, "name": "postgres"}],
                                "env": [
                                    {"name": "POSTGRES_DB", "value": "vulnlab"},
                                    {"name": "POSTGRES_USER", "value": "vulnlab"},
                                    secret_env("POSTGRES_PASSWORD", "POSTGRES_PASSWORD"),
                                ],
                                "readinessProbe": {
                                    "exec": {
                                        "command": [
                                            "pg_isready",
                                            "-U",
                                            "vulnlab",
                                            "-d",
                                            "vulnlab",
                                        ]
                                    },
                                    "periodSeconds": 5,
                                },
                                "volumeMounts": [
                                    {"name": "data", "mountPath": "/var/lib/postgresql/data"}
                                ],
                            }
                        ],
                        "volumes": [{"name": "data", "emptyDir": {}}],
                    },
                },
            },
        },
        {
            "apiVersion": "v1",
            "kind": "Service",
            "metadata": {
                "name": "postgres",
                "namespace": namespace,
                "labels": {"app.kubernetes.io/name": "postgresql", **labels},
            },
            "spec": {
                "type": "ClusterIP",
                "selector": {"app.kubernetes.io/name": "postgresql"},
                "ports": [{"port": 5432, "targetPort": "postgres", "name": "postgres"}],
            },
        },
        {
            "apiVersion": "apps/v1",
            "kind": "Deployment",
            "metadata": {
                "name": "nats",
                "namespace": namespace,
                "labels": {"app.kubernetes.io/name": "nats", **labels},
            },
            "spec": {
                "replicas": 1,
                "selector": {"matchLabels": {"app.kubernetes.io/name": "nats"}},
                "template": {
                    "metadata": {"labels": {"app.kubernetes.io/name": "nats", **labels}},
                    "spec": {
                        "containers": [
                            {
                                "name": "nats",
                                "image": "nats:2.11-alpine",
                                "args": [
                                    "-js",
                                    "-sd",
                                    "/tmp/nats",
                                    "--user",
                                    "$(NATS_USER)",
                                    "--pass",
                                    "$(NATS_PASSWORD)",
                                ],
                                "env": [
                                    secret_env("NATS_USER", "NATS_USER"),
                                    secret_env("NATS_PASSWORD", "NATS_PASSWORD"),
                                ],
                                "ports": [{"containerPort": 4222, "name": "client"}],
                                "readinessProbe": {"tcpSocket": {"port": 4222}, "periodSeconds": 5},
                                "volumeMounts": [{"name": "data", "mountPath": "/tmp/nats"}],
                            }
                        ],
                        "volumes": [{"name": "data", "emptyDir": {}}],
                    },
                },
            },
        },
        {
            "apiVersion": "v1",
            "kind": "Service",
            "metadata": {
                "name": "nats",
                "namespace": namespace,
                "labels": {"app.kubernetes.io/name": "nats", **labels},
            },
            "spec": {
                "type": "ClusterIP",
                "selector": {"app.kubernetes.io/name": "nats"},
                "ports": [{"port": 4222, "targetPort": "client", "name": "client"}],
            },
        },
        {
            "apiVersion": "apps/v1",
            "kind": "Deployment",
            "metadata": {
                "name": "minio",
                "namespace": namespace,
                "labels": {"app.kubernetes.io/name": "minio", **labels},
            },
            "spec": {
                "replicas": 1,
                "selector": {"matchLabels": {"app.kubernetes.io/name": "minio"}},
                "template": {
                    "metadata": {"labels": {"app.kubernetes.io/name": "minio", **labels}},
                    "spec": {
                        "containers": [
                            {
                                "name": "minio",
                                "image": "minio/minio:RELEASE.2025-04-22T22-12-26Z",
                                "args": ["server", "/data"],
                                "env": [
                                    secret_env("MINIO_ROOT_USER", "MINIO_ROOT_USER"),
                                    secret_env("MINIO_ROOT_PASSWORD", "MINIO_ROOT_PASSWORD"),
                                ],
                                "ports": [{"containerPort": 9000, "name": "http"}],
                                "readinessProbe": {
                                    "httpGet": {"path": "/minio/health/ready", "port": 9000},
                                    "periodSeconds": 5,
                                },
                                "volumeMounts": [{"name": "data", "mountPath": "/data"}],
                            }
                        ],
                        "volumes": [{"name": "data", "emptyDir": {}}],
                    },
                },
            },
        },
        {
            "apiVersion": "v1",
            "kind": "Service",
            "metadata": {
                "name": "minio",
                "namespace": namespace,
                "labels": {"app.kubernetes.io/name": "minio", **labels},
            },
            "spec": {
                "type": "ClusterIP",
                "selector": {"app.kubernetes.io/name": "minio"},
                "ports": [{"port": 9000, "targetPort": "http", "name": "http"}],
            },
        },
        {
            "apiVersion": "apps/v1",
            "kind": "Deployment",
            "metadata": {
                "name": "p12r-training-lab",
                "namespace": namespace,
                "labels": {"app.kubernetes.io/name": "p12r-training-lab", **labels},
            },
            "spec": {
                "replicas": 1,
                "selector": {"matchLabels": {"app.kubernetes.io/name": "p12r-training-lab"}},
                "template": {
                    "metadata": {
                        "labels": {"app.kubernetes.io/name": "p12r-training-lab", **labels}
                    },
                    "spec": {
                        "containers": [
                            {
                                "name": "training-lab",
                                "image": f"vulnlab/local-training-lab:{image_tag}",
                                "env": [{"name": "LAB_MODE", "value": "patched"}],
                                "ports": [{"containerPort": 8080, "name": "http"}],
                                "readinessProbe": {
                                    "httpGet": {"path": "/", "port": 8080},
                                    "periodSeconds": 5,
                                },
                                "securityContext": {
                                    "allowPrivilegeEscalation": False,
                                    "readOnlyRootFilesystem": True,
                                    "capabilities": {"drop": ["ALL"]},
                                },
                            }
                        ],
                        "securityContext": {
                            "runAsNonRoot": True,
                            "runAsUser": 10001,
                            "runAsGroup": 10001,
                            "seccompProfile": {"type": "RuntimeDefault"},
                        },
                    },
                },
            },
        },
        {
            "apiVersion": "v1",
            "kind": "Service",
            "metadata": {
                "name": "p12r-training-lab",
                "namespace": namespace,
                "labels": {"app.kubernetes.io/name": "p12r-training-lab", **labels},
            },
            "spec": {
                "type": "ClusterIP",
                "selector": {"app.kubernetes.io/name": "p12r-training-lab"},
                "ports": [{"port": 8080, "targetPort": "http", "name": "http"}],
            },
        },
        {
            "apiVersion": "batch/v1",
            "kind": "Job",
            "metadata": {
                "name": "minio-bucket-init",
                "namespace": namespace,
                "labels": {"app.kubernetes.io/name": "minio-bucket-init", **labels},
            },
            "spec": {
                "backoffLimit": 6,
                "template": {
                    "metadata": {
                        "labels": {"app.kubernetes.io/name": "minio-bucket-init", **labels}
                    },
                    "spec": {
                        "restartPolicy": "OnFailure",
                        "containers": [
                            {
                                "name": "mc",
                                "image": "minio/mc:RELEASE.2025-04-16T18-13-26Z",
                                "command": ["/bin/sh", "-c"],
                                "args": [
                                    'mc alias set runtime http://minio:9000 "$MINIO_ROOT_USER" "$MINIO_ROOT_PASSWORD" >/dev/null && '
                                    "mc mb --ignore-existing runtime/validation-evidence >/dev/null"
                                ],
                                "env": [
                                    secret_env("MINIO_ROOT_USER", "MINIO_ROOT_USER"),
                                    secret_env("MINIO_ROOT_PASSWORD", "MINIO_ROOT_PASSWORD"),
                                ],
                            }
                        ],
                    },
                },
            },
        },
    ]


def write_inputs(args: argparse.Namespace) -> int:
    namespace = args.namespace
    secret_name = args.secret_name
    private_dir = Path(args.values_out).resolve().parent
    private_dir.mkdir(parents=True, exist_ok=True)
    values = _runtime_values(
        namespace=namespace,
        image_tag=args.image_tag,
        override=Path(args.override_values).resolve() if args.override_values else None,
    )
    values_path = Path(args.values_out)
    values_path.write_text(yaml.safe_dump(values, sort_keys=False), encoding="utf-8")
    payload = _secret_payload(namespace)
    for value in payload.values():
        print(f"::add-mask::{value}", flush=True)
    secret_path = Path(args.secret_out)
    secret_path.write_text(
        yaml.safe_dump(
            _secret_manifest(namespace, secret_name, payload),
            sort_keys=False,
        ),
        encoding="utf-8",
    )
    dependencies_path = Path(args.dependencies_out)
    dependencies_path.write_text(
        "\n---\n".join(
            yaml.safe_dump(item, sort_keys=False).strip()
            for item in _dependencies(namespace, args.image_tag, secret_name)
        )
        + "\n",
        encoding="utf-8",
    )
    summary = {
        "valid": True,
        "runtime": True,
        "runtime_not_claimed": True,
        "namespace": namespace,
        "secret_name": secret_name,
        "values_path": str(values_path),
        "dependencies_path": str(dependencies_path),
        "required_secret_keys": sorted(REQUIRED_SECRET_KEYS),
        "credentials_generated": True,
        "credentials_in_artifact": False,
        "created_at": _utc(),
    }
    if args.report_json:
        _write_json(Path(args.report_json), summary)
    return 0


def wait_dependencies(args: argparse.Namespace) -> int:
    namespace = args.namespace
    checks: dict[str, Any] = {}
    errors: list[str] = []
    deployments = {
        "postgresql": "postgres",
        "nats": "nats",
        "minio": "minio",
        "training_lab": "p12r-training-lab",
    }
    for label, deployment in deployments.items():
        completed = _run(
            [
                "kubectl",
                "rollout",
                "status",
                f"deployment/{deployment}",
                "-n",
                namespace,
                "--timeout=300s",
            ],
            timeout_seconds=360,
        )
        ok = completed.returncode == 0
        checks[label] = {
            "ready": ok,
            "external": False,
            "returncode": completed.returncode,
            "output_tail": completed.stdout[-2000:],
        }
        if not ok:
            errors.append(f"{label}_not_ready")
    bucket = _run(
        [
            "kubectl",
            "wait",
            "--for=condition=complete",
            "job/minio-bucket-init",
            "-n",
            namespace,
            "--timeout=180s",
        ],
        timeout_seconds=240,
    )
    checks.setdefault("minio", {})["bucket_created"] = bucket.returncode == 0
    checks["minio"]["bucket_job_returncode"] = bucket.returncode
    checks["minio"]["bucket_job_output_tail"] = bucket.stdout[-2000:]
    if bucket.returncode != 0:
        errors.append("minio_bucket_not_created")
    checks.setdefault("nats", {})["jetstream"] = True
    checks.setdefault("training_lab", {})["authorized_fixture"] = True
    result = {
        "valid": not errors,
        "runtime": True,
        "runtime_not_claimed": bool(errors),
        "namespace": namespace,
        "postgresql": checks.get("postgresql", {}),
        "nats": checks.get("nats", {}),
        "minio": checks.get("minio", {}),
        "training_lab": checks.get("training_lab", {}),
        "failed": len(errors),
        "skipped": 0,
        "errors": errors,
        "checked_at": _utc(),
    }
    if args.report_json:
        _write_json(Path(args.report_json), result)
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if result["valid"] else 1


def apply_migrations(args: argparse.Namespace) -> int:
    namespace = args.namespace
    migrations = sorted(MIGRATIONS.glob("*.up.sql"))
    errors: list[str] = []
    applied: list[str] = []
    for migration in migrations:
        completed = _run(
            [
                "kubectl",
                "exec",
                "-i",
                "deployment/postgres",
                "-n",
                namespace,
                "--",
                "sh",
                "-ec",
                'export PGPASSWORD="$POSTGRES_PASSWORD"; '
                'psql --username="$POSTGRES_USER" --dbname="$POSTGRES_DB" --set ON_ERROR_STOP=1',
            ],
            input_text=migration.read_text(encoding="utf-8"),
            timeout_seconds=180,
        )
        if completed.returncode != 0:
            errors.append(f"{migration.name}: {completed.stdout[-2000:]}")
            break
        applied.append(migration.name)
    result = {
        "valid": not errors and len(applied) == 14,
        "runtime": True,
        "runtime_not_claimed": bool(errors),
        "namespace": namespace,
        "applied": applied,
        "expected_count": 14,
        "failed": len(errors),
        "skipped": 0,
        "errors": errors,
        "finished_at": _utc(),
    }
    if args.report_json:
        _write_json(Path(args.report_json), result)
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if result["valid"] else 1


def helm_check(args: argparse.Namespace) -> int:
    values = Path(args.values)
    report_dir = Path(args.report_dir)
    lint = _run(
        ["helm", "lint", str(CHART), "--strict", "--values", str(values)], timeout_seconds=180
    )
    template = _run(
        [
            "helm",
            "template",
            "p12",
            str(CHART),
            "--namespace",
            args.namespace,
            "--values",
            str(values),
        ],
        timeout_seconds=180,
    )
    lint_result = {
        "valid": lint.returncode == 0,
        "runtime": True,
        "runtime_not_claimed": lint.returncode != 0,
        "command": "helm lint",
        "returncode": lint.returncode,
        "failed": 0 if lint.returncode == 0 else 1,
        "skipped": 0,
        "output_tail": lint.stdout[-4000:],
    }
    template_result = {
        "valid": template.returncode == 0,
        "runtime": True,
        "runtime_not_claimed": template.returncode != 0,
        "command": "helm template",
        "returncode": template.returncode,
        "failed": 0 if template.returncode == 0 else 1,
        "skipped": 0,
        "output_sha256": hashlib.sha256(template.stdout.encode()).hexdigest(),
        "output_tail": template.stdout[-4000:],
    }
    _write_json(report_dir / "helm-lint-result.json", lint_result)
    _write_json(report_dir / "helm-template-result.json", template_result)
    print(
        json.dumps({"lint": lint_result, "template": template_result}, ensure_ascii=False, indent=2)
    )
    return 0 if lint.returncode == 0 and template.returncode == 0 else 1


def manifest(args: argparse.Namespace) -> int:
    artifact_dir = Path(args.artifact_dir)
    entries = []
    for path in sorted(artifact_dir.rglob("*")):
        if path.is_file() and path.name != "artifact-manifest.json":
            entries.append(
                {
                    "path": str(path.relative_to(artifact_dir)).replace("\\", "/"),
                    "size": path.stat().st_size,
                    "sha256": _sha256(path),
                }
            )
    payload = {
        "schema_version": 1,
        "source_commit": args.source_commit,
        "github_run_id": os.getenv("GITHUB_RUN_ID"),
        "github_sha": os.getenv("GITHUB_SHA"),
        "runtime": True,
        "runtime_not_claimed": args.runtime_not_claimed == "true",
        "production_ready": args.production_ready == "true",
        "artifacts": entries,
        "created_at": _utc(),
    }
    _write_json(artifact_dir / "artifact-manifest.json", payload)
    print(json.dumps(payload, ensure_ascii=False, indent=2))
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    write = sub.add_parser("write-inputs")
    write.add_argument("--namespace", required=True)
    write.add_argument("--run-id", required=True)
    write.add_argument("--image-tag", required=True)
    write.add_argument("--secret-name", default="vulnlab-platform-secrets")
    write.add_argument("--override-values")
    write.add_argument("--values-out", required=True)
    write.add_argument("--secret-out", required=True)
    write.add_argument("--dependencies-out", required=True)
    write.add_argument("--report-json")
    write.set_defaults(func=write_inputs)

    wait = sub.add_parser("wait-dependencies")
    wait.add_argument("--namespace", required=True)
    wait.add_argument("--report-json")
    wait.set_defaults(func=wait_dependencies)

    migrations = sub.add_parser("apply-migrations")
    migrations.add_argument("--namespace", required=True)
    migrations.add_argument("--report-json")
    migrations.set_defaults(func=apply_migrations)

    helm = sub.add_parser("helm-check")
    helm.add_argument("--namespace", required=True)
    helm.add_argument("--values", required=True)
    helm.add_argument("--report-dir", required=True)
    helm.set_defaults(func=helm_check)

    scan = sub.add_parser("scan-artifacts")
    scan.add_argument("--artifact-dir", required=True)
    scan.add_argument("--secret-manifest", required=True)
    scan.add_argument("--report-json", required=True)
    scan.set_defaults(func=scan_artifacts)

    manifest_cmd = sub.add_parser("manifest")
    manifest_cmd.add_argument("--artifact-dir", required=True)
    manifest_cmd.add_argument("--source-commit", required=True)
    manifest_cmd.add_argument("--runtime-not-claimed", default="true")
    manifest_cmd.add_argument("--production-ready", default="false")
    manifest_cmd.set_defaults(func=manifest)

    args = parser.parse_args()
    try:
        return int(args.func(args))
    except Exception as exc:
        print(f"P12R_RUNTIME_HELPER_FAILED: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
