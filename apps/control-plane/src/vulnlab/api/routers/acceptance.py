from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, Depends, Header, HTTPException, status

from ...enterprise_acceptance import (
    AcceptanceIsolationError,
    AcceptanceStateError,
    EnterpriseAcceptanceError,
)
from ...policy import PolicyDenied
from ...schemas import (
    AcceptanceRunCreate,
    AcceptanceRunResponse,
    AcceptanceStatusResponse,
    ComplianceControlResponse,
    ComplianceEvidencePackageCreate,
    ComplianceEvidencePackageResponse,
    DataDeletionRequestCreate,
    DataDeletionRequestResponse,
    DataExportCreate,
    DataExportResponse,
    DeliveryPackageCreate,
    DeliveryPackageResponse,
    LegalHoldCreate,
    LegalHoldResponse,
    ProductionReadinessResponse,
    RequirementTraceabilityItem,
)
from ...security import Principal
from ..dependencies import ServicesDep, require

router = APIRouter(tags=["acceptance"])


def _handle_acceptance_error(exc: Exception) -> HTTPException:
    if isinstance(exc, KeyError | AcceptanceIsolationError):
        return HTTPException(status_code=404, detail="resource not found")
    if isinstance(exc, (PolicyDenied, PermissionError)):
        return HTTPException(status_code=403, detail=str(exc))
    if isinstance(exc, (AcceptanceStateError, EnterpriseAcceptanceError, ValueError)):
        return HTTPException(status_code=409, detail=str(exc))
    return HTTPException(status_code=500, detail=type(exc).__name__)


@router.get(
    "/api/v1/acceptance/requirements",
    response_model=list[RequirementTraceabilityItem],
)
def acceptance_requirements(
    services: ServicesDep,
    current: Annotated[Principal, Depends(require("acceptance:read"))],
) -> list[dict[str, Any]]:
    return services.acceptance.requirements(current)


@router.get("/api/v1/acceptance/status", response_model=AcceptanceStatusResponse)
def acceptance_status(
    services: ServicesDep,
    current: Annotated[Principal, Depends(require("acceptance:read"))],
) -> dict[str, Any]:
    return services.acceptance.status(current)


@router.post(
    "/api/v1/acceptance/runs",
    status_code=status.HTTP_202_ACCEPTED,
    response_model=AcceptanceRunResponse,
)
def run_acceptance(
    value: AcceptanceRunCreate,
    services: ServicesDep,
    current: Annotated[Principal, Depends(require("acceptance:run"))],
    idempotency_key: Annotated[str | None, Header(alias="Idempotency-Key")] = None,
) -> dict[str, Any]:
    try:
        return services.acceptance.run_acceptance(
            current,
            value,
            idempotency_key=idempotency_key,
        )
    except Exception as exc:
        raise _handle_acceptance_error(exc) from exc


@router.get(
    "/api/v1/acceptance/runs/{run_id}",
    response_model=AcceptanceRunResponse,
)
def get_acceptance_run(
    run_id: str,
    services: ServicesDep,
    current: Annotated[Principal, Depends(require("acceptance:read"))],
) -> dict[str, Any]:
    try:
        return services.acceptance.get_acceptance_run(current, run_id)
    except Exception as exc:
        raise _handle_acceptance_error(exc) from exc


@router.post(
    "/api/v1/delivery-packages",
    status_code=status.HTTP_202_ACCEPTED,
    response_model=DeliveryPackageResponse,
)
def generate_delivery_package(
    value: DeliveryPackageCreate,
    services: ServicesDep,
    current: Annotated[Principal, Depends(require("delivery:generate"))],
    idempotency_key: Annotated[str | None, Header(alias="Idempotency-Key")] = None,
) -> dict[str, Any]:
    try:
        return services.acceptance.generate_delivery_package(
            current,
            value,
            idempotency_key=idempotency_key,
        )
    except Exception as exc:
        raise _handle_acceptance_error(exc) from exc


@router.get(
    "/api/v1/delivery-packages/{package_id}",
    response_model=DeliveryPackageResponse,
)
def get_delivery_package(
    package_id: str,
    services: ServicesDep,
    current: Annotated[Principal, Depends(require("delivery:read"))],
) -> dict[str, Any]:
    try:
        return services.acceptance.get_delivery_package(current, package_id)
    except Exception as exc:
        raise _handle_acceptance_error(exc) from exc


@router.get("/api/v1/compliance/controls", response_model=list[ComplianceControlResponse])
def compliance_controls(
    services: ServicesDep,
    current: Annotated[Principal, Depends(require("compliance:read"))],
) -> list[dict[str, Any]]:
    return services.acceptance.compliance_controls(current)


@router.post(
    "/api/v1/compliance/evidence-packages",
    status_code=status.HTTP_202_ACCEPTED,
    response_model=ComplianceEvidencePackageResponse,
)
def generate_compliance_evidence_package(
    value: ComplianceEvidencePackageCreate,
    services: ServicesDep,
    current: Annotated[Principal, Depends(require("compliance:generate"))],
    idempotency_key: Annotated[str | None, Header(alias="Idempotency-Key")] = None,
) -> dict[str, Any]:
    try:
        return services.acceptance.generate_compliance_package(
            current,
            value,
            idempotency_key=idempotency_key,
        )
    except Exception as exc:
        raise _handle_acceptance_error(exc) from exc


@router.post(
    "/api/v1/data-governance/export",
    status_code=status.HTTP_202_ACCEPTED,
    response_model=DataExportResponse,
)
def export_tenant_data(
    value: DataExportCreate,
    services: ServicesDep,
    current: Annotated[Principal, Depends(require("data:export"))],
    idempotency_key: Annotated[str | None, Header(alias="Idempotency-Key")] = None,
) -> dict[str, Any]:
    try:
        return services.acceptance.export_tenant_data(
            current,
            value,
            idempotency_key=idempotency_key,
        )
    except Exception as exc:
        raise _handle_acceptance_error(exc) from exc


@router.post(
    "/api/v1/data-governance/deletion-requests",
    status_code=status.HTTP_202_ACCEPTED,
    response_model=DataDeletionRequestResponse,
)
def request_data_deletion(
    value: DataDeletionRequestCreate,
    services: ServicesDep,
    current: Annotated[Principal, Depends(require("data:delete:request"))],
    idempotency_key: Annotated[str | None, Header(alias="Idempotency-Key")] = None,
) -> dict[str, Any]:
    try:
        return services.acceptance.request_deletion(
            current,
            value,
            idempotency_key=idempotency_key,
        )
    except Exception as exc:
        raise _handle_acceptance_error(exc) from exc


@router.post(
    "/api/v1/data-governance/legal-holds",
    status_code=status.HTTP_202_ACCEPTED,
    response_model=LegalHoldResponse,
)
def create_legal_hold(
    value: LegalHoldCreate,
    services: ServicesDep,
    current: Annotated[Principal, Depends(require("legal-hold:create"))],
    idempotency_key: Annotated[str | None, Header(alias="Idempotency-Key")] = None,
) -> dict[str, Any]:
    try:
        return services.acceptance.create_legal_hold(
            current,
            value,
            idempotency_key=idempotency_key,
        )
    except Exception as exc:
        raise _handle_acceptance_error(exc) from exc


@router.get("/api/v1/readiness/production", response_model=ProductionReadinessResponse)
def production_readiness(
    services: ServicesDep,
    current: Annotated[Principal, Depends(require("readiness:read"))],
) -> dict[str, Any]:
    return services.acceptance.production_readiness(current)
