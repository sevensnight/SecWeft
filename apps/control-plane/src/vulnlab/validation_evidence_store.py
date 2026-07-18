from __future__ import annotations

import hashlib
from dataclasses import dataclass
from io import BytesIO
from pathlib import Path
from typing import Protocol

from .config import Settings


class EvidenceStoreError(RuntimeError):
    pass


@dataclass(frozen=True, slots=True)
class StoredEvidence:
    artifact_ref: str
    object_key: str
    content_sha256: str
    size: int
    content_type: str
    backend: str
    local_path: str | None = None


class EvidenceStore(Protocol):
    def put_json(
        self,
        *,
        tenant_id: str,
        project_id: str | None,
        execution_id: str,
        evidence_id: str,
        content: str,
    ) -> StoredEvidence: ...


def _object_key(
    *,
    tenant_id: str,
    project_id: str | None,
    execution_id: str,
    evidence_id: str,
) -> str:
    project = project_id or "default-project"
    return f"tenant={tenant_id}/project={project}/execution={execution_id}/{evidence_id}.json"


class FilesystemEvidenceStore:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings

    def put_json(
        self,
        *,
        tenant_id: str,
        project_id: str | None,
        execution_id: str,
        evidence_id: str,
        content: str,
    ) -> StoredEvidence:
        encoded = content.encode()
        digest = hashlib.sha256(encoded).hexdigest()
        key = _object_key(
            tenant_id=tenant_id,
            project_id=project_id,
            execution_id=execution_id,
            evidence_id=evidence_id,
        )
        # Keep the logical object key fully tenant/project/execution scoped, but avoid
        # expanding that long key into the local filesystem path. Windows test runners
        # can otherwise exceed MAX_PATH when pytest's temp directory is already deep.
        local_name = hashlib.sha256(key.encode()).hexdigest()
        path = (
            Path(self.settings.workspace_root)
            / "validation-evidence"
            / "blobs"
            / local_name[:2]
            / f"{local_name}.json"
        )
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(encoded)
        verify_digest = hashlib.sha256(path.read_bytes()).hexdigest()
        if verify_digest != digest:
            raise EvidenceStoreError("filesystem evidence SHA-256 verification failed")
        return StoredEvidence(
            artifact_ref=f"minio://validation-evidence/{key}",
            object_key=key,
            content_sha256=digest,
            size=len(encoded),
            content_type="application/json",
            backend="filesystem",
            local_path=str(path),
        )


class MinioEvidenceStore:
    def __init__(self, settings: Settings) -> None:
        if not settings.minio_endpoint:
            raise EvidenceStoreError("VULNLAB_MINIO_ENDPOINT is required")
        if not settings.minio_access_key or not settings.minio_secret_key:
            raise EvidenceStoreError("MinIO credentials are required")
        try:
            from minio import Minio
        except ImportError as exc:  # pragma: no cover - packaging guard.
            raise EvidenceStoreError("minio package is required for MinIO evidence store") from exc
        self.settings = settings
        self.client = Minio(
            settings.minio_endpoint,
            access_key=settings.minio_access_key,
            secret_key=settings.minio_secret_key,
            secure=settings.minio_secure,
        )

    def _ensure_bucket(self) -> None:
        if not self.client.bucket_exists(self.settings.minio_bucket):
            self.client.make_bucket(self.settings.minio_bucket)

    def put_json(
        self,
        *,
        tenant_id: str,
        project_id: str | None,
        execution_id: str,
        evidence_id: str,
        content: str,
    ) -> StoredEvidence:
        encoded = content.encode()
        digest = hashlib.sha256(encoded).hexdigest()
        key = _object_key(
            tenant_id=tenant_id,
            project_id=project_id,
            execution_id=execution_id,
            evidence_id=evidence_id,
        )
        self._ensure_bucket()
        self.client.put_object(
            self.settings.minio_bucket,
            key,
            BytesIO(encoded),
            length=len(encoded),
            content_type="application/json",
        )
        response = self.client.get_object(self.settings.minio_bucket, key)
        try:
            downloaded = response.read()
        finally:
            response.close()
            response.release_conn()
        verify_digest = hashlib.sha256(downloaded).hexdigest()
        if verify_digest != digest:
            raise EvidenceStoreError("MinIO evidence SHA-256 verification failed")
        return StoredEvidence(
            artifact_ref=f"minio://{self.settings.minio_bucket}/{key}",
            object_key=key,
            content_sha256=digest,
            size=len(encoded),
            content_type="application/json",
            backend="minio",
        )


def build_evidence_store(settings: Settings) -> EvidenceStore:
    if settings.evidence_store_backend == "filesystem":
        if settings.env in {"production", "prod"}:
            raise EvidenceStoreError("filesystem evidence store is forbidden in production")
        return FilesystemEvidenceStore(settings)
    if settings.evidence_store_backend == "minio":
        return MinioEvidenceStore(settings)
    raise EvidenceStoreError(f"unknown evidence store backend: {settings.evidence_store_backend}")
