from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, Depends, Header, HTTPException, Query, status

from ...policy import PolicyDenied
from ...release_governance import (
    ReleaseGovernanceError,
    ReleaseIsolationError,
    ReleaseStateError,
)
from ...schemas import (
    CompliancePackageResponse,
    DeploymentRecordResponse,
    DriftDetectionResultResponse,
    EnvironmentPromotionCreate,
    EnvironmentPromotionResultResponse,
    ReleaseApprovalCreate,
    ReleaseApprovalResponse,
    ReleaseArtifactCreate,
    ReleaseArtifactDetailResponse,
    ReleaseArtifactResponse,
    ReleaseCandidateCreate,
    ReleaseCandidateDetailResponse,
    ReleaseCandidateResponse,
    ReleaseExceptionCreate,
    ReleaseExceptionResponse,
    ReleaseGateEvaluationRequest,
    ReleaseGateResultResponse,
    RollbackCreate,
    RollbackRecordResponse,
)
from ...security import Principal
from ..dependencies import ServicesDep, require

router = APIRouter(tags=["releases"])


def _handle_release_error(exc: Exception) -> HTTPException:
    if isinstance(exc, KeyError):
        return HTTPException(status_code=404, detail=str(exc))
    if isinstance(exc, ReleaseIsolationError):
        return HTTPException(status_code=404, detail="resource not found")
    if isinstance(exc, (PolicyDenied, PermissionError)):
        return HTTPException(status_code=403, detail=str(exc))
    if isinstance(exc, ReleaseStateError | ReleaseGovernanceError | ValueError):
        return HTTPException(status_code=409, detail=str(exc))
    return HTTPException(status_code=500, detail=type(exc).__name__)


@router.post(
    "/api/v1/release-artifacts",
    status_code=status.HTTP_201_CREATED,
    response_model=ReleaseArtifactDetailResponse,
)
def register_release_artifact(
    value: ReleaseArtifactCreate,
    services: ServicesDep,
    current: Annotated[Principal, Depends(require("release:artifact:register"))],
    idempotency_key: Annotated[str | None, Header(alias="Idempotency-Key")] = None,
) -> dict[str, Any]:
    try:
        return services.releases.register_artifact(
            current,
            value,
            idempotency_key=idempotency_key,
        )
    except Exception as exc:
        raise _handle_release_error(exc) from exc


@router.get("/api/v1/release-artifacts", response_model=list[ReleaseArtifactResponse])
def list_release_artifacts(
    services: ServicesDep,
    current: Annotated[Principal, Depends(require("release:read"))],
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> list[dict[str, Any]]:
    return services.releases.list_artifacts(current, limit=limit, offset=offset)


@router.get(
    "/api/v1/release-artifacts/{artifact_id}",
    response_model=ReleaseArtifactDetailResponse,
)
def get_release_artifact(
    artifact_id: str,
    services: ServicesDep,
    current: Annotated[Principal, Depends(require("release:read"))],
) -> dict[str, Any]:
    try:
        return services.releases.get_artifact(current, artifact_id)
    except Exception as exc:
        raise _handle_release_error(exc) from exc


@router.post(
    "/api/v1/release-candidates",
    status_code=status.HTTP_201_CREATED,
    response_model=ReleaseCandidateDetailResponse,
)
def create_release_candidate(
    value: ReleaseCandidateCreate,
    services: ServicesDep,
    current: Annotated[Principal, Depends(require("release:candidate:create"))],
    idempotency_key: Annotated[str | None, Header(alias="Idempotency-Key")] = None,
) -> dict[str, Any]:
    try:
        return services.releases.create_candidate(
            current,
            value,
            idempotency_key=idempotency_key,
        )
    except Exception as exc:
        raise _handle_release_error(exc) from exc


@router.get("/api/v1/release-candidates", response_model=list[ReleaseCandidateResponse])
def list_release_candidates(
    services: ServicesDep,
    current: Annotated[Principal, Depends(require("release:read"))],
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> list[dict[str, Any]]:
    return services.releases.list_candidates(current, limit=limit, offset=offset)


@router.get(
    "/api/v1/release-candidates/{candidate_id}",
    response_model=ReleaseCandidateDetailResponse,
)
def get_release_candidate(
    candidate_id: str,
    services: ServicesDep,
    current: Annotated[Principal, Depends(require("release:read"))],
) -> dict[str, Any]:
    try:
        return services.releases.get_candidate(current, candidate_id)
    except Exception as exc:
        raise _handle_release_error(exc) from exc


@router.post(
    "/api/v1/release-candidates/{candidate_id}/evaluate",
    response_model=list[ReleaseGateResultResponse],
)
def evaluate_release_candidate(
    candidate_id: str,
    value: ReleaseGateEvaluationRequest,
    services: ServicesDep,
    current: Annotated[Principal, Depends(require("release:gate:evaluate"))],
    idempotency_key: Annotated[str | None, Header(alias="Idempotency-Key")] = None,
) -> list[dict[str, Any]]:
    try:
        return services.releases.evaluate_candidate(
            current,
            candidate_id,
            value,
            idempotency_key=idempotency_key,
        )
    except Exception as exc:
        raise _handle_release_error(exc) from exc


@router.get(
    "/api/v1/release-candidates/{candidate_id}/gates",
    response_model=list[ReleaseGateResultResponse],
)
def list_release_candidate_gates(
    candidate_id: str,
    services: ServicesDep,
    current: Annotated[Principal, Depends(require("release:read"))],
) -> list[dict[str, Any]]:
    try:
        return services.releases.list_gates(current, candidate_id)
    except Exception as exc:
        raise _handle_release_error(exc) from exc


@router.post(
    "/api/v1/release-candidates/{candidate_id}/approvals",
    status_code=status.HTTP_201_CREATED,
    response_model=ReleaseApprovalResponse,
)
def approve_release_candidate(
    candidate_id: str,
    value: ReleaseApprovalCreate,
    services: ServicesDep,
    current: Annotated[Principal, Depends(require("release:approve"))],
    idempotency_key: Annotated[str | None, Header(alias="Idempotency-Key")] = None,
) -> dict[str, Any]:
    try:
        return services.releases.approve_candidate(
            current,
            candidate_id,
            value,
            idempotency_key=idempotency_key,
        )
    except Exception as exc:
        raise _handle_release_error(exc) from exc


@router.post(
    "/api/v1/release-candidates/{candidate_id}/exceptions",
    status_code=status.HTTP_201_CREATED,
    response_model=ReleaseExceptionResponse,
)
def request_release_exception(
    candidate_id: str,
    value: ReleaseExceptionCreate,
    services: ServicesDep,
    current: Annotated[Principal, Depends(require("release:exception:request"))],
    idempotency_key: Annotated[str | None, Header(alias="Idempotency-Key")] = None,
) -> dict[str, Any]:
    try:
        return services.releases.request_exception(
            current,
            candidate_id,
            value,
            idempotency_key=idempotency_key,
        )
    except Exception as exc:
        raise _handle_release_error(exc) from exc


@router.post(
    "/api/v1/release-candidates/{candidate_id}/promotions",
    status_code=status.HTTP_201_CREATED,
    response_model=EnvironmentPromotionResultResponse,
)
def promote_release_candidate(
    candidate_id: str,
    value: EnvironmentPromotionCreate,
    services: ServicesDep,
    current: Annotated[Principal, Depends(require("release:promote"))],
    idempotency_key: Annotated[str | None, Header(alias="Idempotency-Key")] = None,
) -> dict[str, Any]:
    try:
        return services.releases.promote_candidate(
            current,
            candidate_id,
            value,
            idempotency_key=idempotency_key,
        )
    except Exception as exc:
        raise _handle_release_error(exc) from exc


@router.get(
    "/api/v1/deployments/{deployment_id}",
    response_model=DeploymentRecordResponse,
)
def get_deployment_record(
    deployment_id: str,
    services: ServicesDep,
    current: Annotated[Principal, Depends(require("release:read"))],
) -> dict[str, Any]:
    try:
        return services.releases.get_deployment(current, deployment_id)
    except Exception as exc:
        raise _handle_release_error(exc) from exc


@router.post(
    "/api/v1/deployments/{deployment_id}/rollback",
    status_code=status.HTTP_201_CREATED,
    response_model=RollbackRecordResponse,
)
def rollback_deployment_record(
    deployment_id: str,
    value: RollbackCreate,
    services: ServicesDep,
    current: Annotated[Principal, Depends(require("release:rollback"))],
    idempotency_key: Annotated[str | None, Header(alias="Idempotency-Key")] = None,
) -> dict[str, Any]:
    try:
        return services.releases.rollback_deployment(
            current,
            deployment_id,
            value,
            idempotency_key=idempotency_key,
        )
    except Exception as exc:
        raise _handle_release_error(exc) from exc


@router.get(
    "/api/v1/deployments/{deployment_id}/drift",
    response_model=DriftDetectionResultResponse,
)
def detect_deployment_drift(
    deployment_id: str,
    services: ServicesDep,
    current: Annotated[Principal, Depends(require("release:drift:review"))],
) -> dict[str, Any]:
    try:
        return services.releases.detect_drift(current, deployment_id)
    except Exception as exc:
        raise _handle_release_error(exc) from exc


@router.post(
    "/api/v1/release-candidates/{candidate_id}/compliance-package",
    status_code=status.HTTP_201_CREATED,
    response_model=CompliancePackageResponse,
)
def generate_release_compliance_package(
    candidate_id: str,
    services: ServicesDep,
    current: Annotated[Principal, Depends(require("release:compliance:generate"))],
    idempotency_key: Annotated[str | None, Header(alias="Idempotency-Key")] = None,
) -> dict[str, Any]:
    try:
        return services.releases.generate_compliance_package(
            current,
            candidate_id,
            idempotency_key=idempotency_key,
        )
    except Exception as exc:
        raise _handle_release_error(exc) from exc
