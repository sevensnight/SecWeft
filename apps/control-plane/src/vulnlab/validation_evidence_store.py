from __future__ import annotations

import hashlib
import json
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


@dataclass(frozen=True, slots=True)
class EvidenceObjectInfo:
    object_key: str
    exists: bool
    content_sha256: str | None = None
    size: int | None = None
    content_type: str | None = None
    backend: str = "unknown"


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

    def inspect_json(self, object_key: str) -> EvidenceObjectInfo: ...

    def list_json_objects(self, prefix: str | None = None) -> list[EvidenceObjectInfo]: ...


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

    def _path_for_key(self, key: str) -> Path:
        local_name = hashlib.sha256(key.encode()).hexdigest()
        return (
            Path(self.settings.workspace_root)
            / "validation-evidence"
            / "blobs"
            / local_name[:2]
            / f"{local_name}.json"
        )

    def _manifest_path_for_key(self, key: str) -> Path:
        return self._path_for_key(key).with_suffix(".manifest.json")

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
        path = self._path_for_key(key)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(encoded)
        verify_digest = hashlib.sha256(path.read_bytes()).hexdigest()
        if verify_digest != digest:
            raise EvidenceStoreError("filesystem evidence SHA-256 verification failed")
        self._manifest_path_for_key(key).write_text(
            json.dumps(
                {
                    "object_key": key,
                    "content_sha256": digest,
                    "size": len(encoded),
                    "content_type": "application/json",
                    "backend": "filesystem",
                },
                ensure_ascii=False,
                sort_keys=True,
            ),
            encoding="utf-8",
        )
        return StoredEvidence(
            artifact_ref=f"minio://validation-evidence/{key}",
            object_key=key,
            content_sha256=digest,
            size=len(encoded),
            content_type="application/json",
            backend="filesystem",
            local_path=str(path),
        )

    def inspect_json(self, object_key: str) -> EvidenceObjectInfo:
        path = self._path_for_key(object_key)
        if not path.is_file():
            return EvidenceObjectInfo(
                object_key=object_key,
                exists=False,
                backend="filesystem",
            )
        content = path.read_bytes()
        return EvidenceObjectInfo(
            object_key=object_key,
            exists=True,
            content_sha256=hashlib.sha256(content).hexdigest(),
            size=len(content),
            content_type="application/json",
            backend="filesystem",
        )

    def list_json_objects(self, prefix: str | None = None) -> list[EvidenceObjectInfo]:
        root = Path(self.settings.workspace_root) / "validation-evidence" / "blobs"
        if not root.is_dir():
            return []
        objects: list[EvidenceObjectInfo] = []
        for manifest in sorted(root.glob("*/*.manifest.json")):
            try:
                metadata = json.loads(manifest.read_text(encoding="utf-8"))
            except json.JSONDecodeError:
                continue
            key = str(metadata.get("object_key", ""))
            if not key or (prefix and not key.startswith(prefix)):
                continue
            objects.append(self.inspect_json(key))
        return objects


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

    def inspect_json(self, object_key: str) -> EvidenceObjectInfo:
        try:
            stat = self.client.stat_object(self.settings.minio_bucket, object_key)
            response = self.client.get_object(self.settings.minio_bucket, object_key)
        except Exception:
            return EvidenceObjectInfo(object_key=object_key, exists=False, backend="minio")
        try:
            content = response.read()
        finally:
            response.close()
            response.release_conn()
        return EvidenceObjectInfo(
            object_key=object_key,
            exists=True,
            content_sha256=hashlib.sha256(content).hexdigest(),
            size=len(content),
            content_type=stat.content_type or "application/octet-stream",
            backend="minio",
        )

    def list_json_objects(self, prefix: str | None = None) -> list[EvidenceObjectInfo]:
        try:
            items = self.client.list_objects(
                self.settings.minio_bucket,
                prefix=prefix,
                recursive=True,
            )
            return [self.inspect_json(item.object_name) for item in items]
        except Exception as exc:
            raise EvidenceStoreError("MinIO evidence inventory failed") from exc


def build_evidence_store(settings: Settings) -> EvidenceStore:
    if settings.evidence_store_backend == "filesystem":
        if settings.env in {"production", "prod"}:
            raise EvidenceStoreError("filesystem evidence store is forbidden in production")
        return FilesystemEvidenceStore(settings)
    if settings.evidence_store_backend == "minio":
        return MinioEvidenceStore(settings)
    raise EvidenceStoreError(f"unknown evidence store backend: {settings.evidence_store_backend}")
