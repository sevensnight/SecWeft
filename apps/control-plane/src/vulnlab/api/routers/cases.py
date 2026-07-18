from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request, status

from ...case_management import CaseIsolationError, CaseStateError
from ...policy import PolicyDenied
from ...schemas import (
    CaseCloseRequest,
    CaseDispositionCreate,
    CaseDispositionResponse,
    CaseFindingCreate,
    CaseFindingResponse,
    CaseReportCreate,
    CaseReportResponse,
    RemediationDecisionCreate,
    RemediationDecisionResponse,
    RemediationImplementationCreate,
    RemediationImplementationResponse,
    RemediationProposalCreate,
    RemediationProposalResponse,
    RetestRequestCreate,
    RetestRequestResponse,
    ValidationComparisonResponse,
    VulnerabilityCaseCreate,
    VulnerabilityCaseDetailResponse,
    VulnerabilityCasePatch,
    VulnerabilityCaseResponse,
)
from ...security import Principal
from ...validation_execution import ValidationExecutionStateError, ValidationTemplateError
from ..dependencies import ServicesDep, require

router = APIRouter(tags=["vulnerability-cases"])


def _handle_case_error(exc: Exception) -> HTTPException:
    if isinstance(exc, KeyError):
        return HTTPException(status_code=404, detail=str(exc))
    if isinstance(exc, CaseIsolationError):
        return HTTPException(status_code=404, detail="resource not found")
    if isinstance(exc, (PolicyDenied, PermissionError)):
        return HTTPException(status_code=403, detail=str(exc))
    if isinstance(exc, ValidationTemplateError):
        return HTTPException(status_code=400, detail=str(exc))
    if isinstance(exc, ValidationExecutionStateError | CaseStateError | ValueError):
        return HTTPException(status_code=409, detail=str(exc))
    return HTTPException(status_code=500, detail=type(exc).__name__)


@router.post(
    "/api/v1/vulnerability-cases",
    status_code=status.HTTP_201_CREATED,
    response_model=VulnerabilityCaseResponse,
)
def create_vulnerability_case(
    value: VulnerabilityCaseCreate,
    services: ServicesDep,
    current: Annotated[Principal, Depends(require("case:create"))],
    idempotency_key: Annotated[str | None, Header(alias="Idempotency-Key")] = None,
) -> dict[str, Any]:
    try:
        return services.cases.create_case(
            current,
            value,
            idempotency_key=idempotency_key,
        )
    except Exception as exc:
        raise _handle_case_error(exc) from exc


@router.get("/api/v1/vulnerability-cases", response_model=list[VulnerabilityCaseResponse])
def list_vulnerability_cases(
    services: ServicesDep,
    current: Annotated[Principal, Depends(require("case:read"))],
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
    project_id: Annotated[str | None, Query(max_length=120)] = None,
    status_filter: Annotated[str | None, Query(alias="status", max_length=40)] = None,
) -> list[dict[str, Any]]:
    return services.cases.list_cases(
        current,
        limit=limit,
        project_id=project_id,
        status=status_filter,
    )


@router.get(
    "/api/v1/vulnerability-cases/{case_id}",
    response_model=VulnerabilityCaseDetailResponse,
)
def get_vulnerability_case(
    case_id: str,
    services: ServicesDep,
    current: Annotated[Principal, Depends(require("case:read"))],
) -> dict[str, Any]:
    try:
        return services.cases.get_case_detail(current, case_id)
    except Exception as exc:
        raise _handle_case_error(exc) from exc


@router.patch(
    "/api/v1/vulnerability-cases/{case_id}",
    response_model=VulnerabilityCaseResponse,
)
def update_vulnerability_case(
    case_id: str,
    value: VulnerabilityCasePatch,
    services: ServicesDep,
    current: Annotated[Principal, Depends(require("case:update"))],
    idempotency_key: Annotated[str | None, Header(alias="Idempotency-Key")] = None,
) -> dict[str, Any]:
    try:
        return services.cases.update_case(
            current,
            case_id,
            value,
            idempotency_key=idempotency_key,
        )
    except Exception as exc:
        raise _handle_case_error(exc) from exc


@router.post(
    "/api/v1/vulnerability-cases/{case_id}/findings",
    status_code=status.HTTP_201_CREATED,
    response_model=CaseFindingResponse,
)
def create_case_finding(
    case_id: str,
    value: CaseFindingCreate,
    services: ServicesDep,
    current: Annotated[Principal, Depends(require("case:update"))],
    idempotency_key: Annotated[str | None, Header(alias="Idempotency-Key")] = None,
) -> dict[str, Any]:
    try:
        return services.cases.create_finding(
            current,
            case_id,
            value,
            idempotency_key=idempotency_key,
        )
    except Exception as exc:
        raise _handle_case_error(exc) from exc


@router.get(
    "/api/v1/vulnerability-cases/{case_id}/findings",
    response_model=list[CaseFindingResponse],
)
def list_case_findings(
    case_id: str,
    services: ServicesDep,
    current: Annotated[Principal, Depends(require("case:read"))],
) -> list[dict[str, Any]]:
    try:
        return services.cases.list_findings(current, case_id)
    except Exception as exc:
        raise _handle_case_error(exc) from exc


@router.post(
    "/api/v1/vulnerability-cases/{case_id}/remediation-proposals",
    status_code=status.HTTP_201_CREATED,
    response_model=RemediationProposalResponse,
)
def create_remediation_proposal(
    case_id: str,
    value: RemediationProposalCreate,
    services: ServicesDep,
    current: Annotated[Principal, Depends(require("remediation:propose"))],
    idempotency_key: Annotated[str | None, Header(alias="Idempotency-Key")] = None,
) -> dict[str, Any]:
    try:
        return services.cases.create_proposal(
            current,
            case_id,
            value,
            idempotency_key=idempotency_key,
        )
    except Exception as exc:
        raise _handle_case_error(exc) from exc


@router.get(
    "/api/v1/vulnerability-cases/{case_id}/remediation-proposals",
    response_model=list[RemediationProposalResponse],
)
def list_remediation_proposals(
    case_id: str,
    services: ServicesDep,
    current: Annotated[Principal, Depends(require("case:read"))],
) -> list[dict[str, Any]]:
    try:
        return services.cases.list_proposals(current, case_id)
    except Exception as exc:
        raise _handle_case_error(exc) from exc


@router.post(
    "/api/v1/remediation-proposals/{proposal_id}/decisions",
    status_code=status.HTTP_201_CREATED,
    response_model=RemediationDecisionResponse,
)
def decide_remediation_proposal(
    proposal_id: str,
    value: RemediationDecisionCreate,
    services: ServicesDep,
    current: Annotated[Principal, Depends(require("remediation:approve"))],
    idempotency_key: Annotated[str | None, Header(alias="Idempotency-Key")] = None,
) -> dict[str, Any]:
    try:
        return services.cases.decide_proposal(
            current,
            proposal_id,
            value,
            idempotency_key=idempotency_key,
        )
    except Exception as exc:
        raise _handle_case_error(exc) from exc


@router.post(
    "/api/v1/remediation-decisions/{decision_id}/implementations",
    status_code=status.HTTP_201_CREATED,
    response_model=RemediationImplementationResponse,
)
def create_remediation_implementation(
    decision_id: str,
    value: RemediationImplementationCreate,
    services: ServicesDep,
    current: Annotated[Principal, Depends(require("remediation:implement"))],
    idempotency_key: Annotated[str | None, Header(alias="Idempotency-Key")] = None,
) -> dict[str, Any]:
    try:
        return services.cases.create_implementation(
            current,
            decision_id,
            value,
            idempotency_key=idempotency_key,
        )
    except Exception as exc:
        raise _handle_case_error(exc) from exc


@router.post(
    "/api/v1/vulnerability-cases/{case_id}/retests",
    status_code=status.HTTP_202_ACCEPTED,
    response_model=RetestRequestResponse,
)
def create_case_retest(
    case_id: str,
    value: RetestRequestCreate,
    request: Request,
    services: ServicesDep,
    current: Annotated[Principal, Depends(require("validation:retest"))],
    idempotency_key: Annotated[str | None, Header(alias="Idempotency-Key")] = None,
) -> dict[str, Any]:
    try:
        return services.cases.create_retest(
            current,
            case_id,
            value,
            idempotency_key=idempotency_key,
            request_id=request.state.request_id,
        )
    except Exception as exc:
        raise _handle_case_error(exc) from exc


@router.get("/api/v1/retests/{retest_id}", response_model=RetestRequestResponse)
def get_retest(
    retest_id: str,
    services: ServicesDep,
    current: Annotated[Principal, Depends(require("case:read"))],
) -> dict[str, Any]:
    try:
        return services.cases.get_retest(current, retest_id)
    except Exception as exc:
        raise _handle_case_error(exc) from exc


@router.get(
    "/api/v1/retests/{retest_id}/comparison",
    response_model=ValidationComparisonResponse,
)
def get_retest_comparison(
    retest_id: str,
    services: ServicesDep,
    current: Annotated[Principal, Depends(require("comparison:review"))],
) -> dict[str, Any]:
    try:
        return services.cases.get_comparison(current, retest_id)
    except Exception as exc:
        raise _handle_case_error(exc) from exc


@router.post(
    "/api/v1/vulnerability-cases/{case_id}/disposition",
    status_code=status.HTTP_201_CREATED,
    response_model=CaseDispositionResponse,
)
def create_case_disposition(
    case_id: str,
    value: CaseDispositionCreate,
    services: ServicesDep,
    current: Annotated[Principal, Depends(require("case:disposition"))],
    idempotency_key: Annotated[str | None, Header(alias="Idempotency-Key")] = None,
) -> dict[str, Any]:
    try:
        return services.cases.create_disposition(
            current,
            case_id,
            value,
            idempotency_key=idempotency_key,
        )
    except Exception as exc:
        raise _handle_case_error(exc) from exc


@router.post(
    "/api/v1/vulnerability-cases/{case_id}/close",
    response_model=VulnerabilityCaseResponse,
)
def close_vulnerability_case(
    case_id: str,
    value: CaseCloseRequest,
    services: ServicesDep,
    current: Annotated[Principal, Depends(require("case:close"))],
    idempotency_key: Annotated[str | None, Header(alias="Idempotency-Key")] = None,
) -> dict[str, Any]:
    try:
        return services.cases.close_case(
            current,
            case_id,
            expected_version=value.expected_version,
            idempotency_key=idempotency_key,
        )
    except Exception as exc:
        raise _handle_case_error(exc) from exc


@router.post(
    "/api/v1/vulnerability-cases/{case_id}/reports",
    status_code=status.HTTP_201_CREATED,
    response_model=CaseReportResponse,
)
def generate_case_report(
    case_id: str,
    value: CaseReportCreate,
    services: ServicesDep,
    current: Annotated[Principal, Depends(require("report:generate"))],
    idempotency_key: Annotated[str | None, Header(alias="Idempotency-Key")] = None,
) -> dict[str, Any]:
    try:
        return services.cases.generate_report(
            current,
            case_id,
            value,
            idempotency_key=idempotency_key,
        )
    except Exception as exc:
        raise _handle_case_error(exc) from exc
