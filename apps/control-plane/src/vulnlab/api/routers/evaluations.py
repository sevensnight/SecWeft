from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, Depends, Header, HTTPException, Query, status

from ...evaluation_governance import (
    EvaluationGovernanceError,
    EvaluationIsolationError,
    EvaluationStateError,
)
from ...policy import PolicyDenied
from ...schemas import (
    EvaluationCaseCreate,
    EvaluationCaseResponse,
    EvaluationComparisonCreate,
    EvaluationComparisonResponse,
    EvaluationDatasetCreate,
    EvaluationDatasetDetailResponse,
    EvaluationFailureResponse,
    EvaluationResultResponse,
    EvaluationReviewCreate,
    EvaluationReviewResponse,
    EvaluationRunCreate,
    EvaluationRunDetailResponse,
    EvaluationRunResponse,
    EvaluationSuiteCreate,
    EvaluationSuiteResponse,
    MetricResultResponse,
    PromotionDecisionCreate,
    PromotionDecisionResponse,
)
from ...security import Principal
from ..dependencies import ServicesDep, require

router = APIRouter(tags=["evaluations"])


def _handle_evaluation_error(exc: Exception) -> HTTPException:
    if isinstance(exc, KeyError):
        return HTTPException(status_code=404, detail=str(exc))
    if isinstance(exc, EvaluationIsolationError):
        return HTTPException(status_code=404, detail="resource not found")
    if isinstance(exc, (PolicyDenied, PermissionError)):
        return HTTPException(status_code=403, detail=str(exc))
    if isinstance(exc, EvaluationStateError | EvaluationGovernanceError | ValueError):
        return HTTPException(status_code=409, detail=str(exc))
    return HTTPException(status_code=500, detail=type(exc).__name__)


@router.post(
    "/api/v1/evaluation-suites",
    status_code=status.HTTP_201_CREATED,
    response_model=EvaluationSuiteResponse,
)
def create_evaluation_suite(
    value: EvaluationSuiteCreate,
    services: ServicesDep,
    current: Annotated[Principal, Depends(require("evaluation:suite:create"))],
    idempotency_key: Annotated[str | None, Header(alias="Idempotency-Key")] = None,
) -> dict[str, Any]:
    try:
        return services.evaluations.create_suite(
            current,
            value,
            idempotency_key=idempotency_key,
        )
    except Exception as exc:
        raise _handle_evaluation_error(exc) from exc


@router.get("/api/v1/evaluation-suites", response_model=list[EvaluationSuiteResponse])
def list_evaluation_suites(
    services: ServicesDep,
    current: Annotated[Principal, Depends(require("evaluation:read"))],
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
    project_id: Annotated[str | None, Query(max_length=120)] = None,
) -> list[dict[str, Any]]:
    return services.evaluations.list_suites(current, project_id=project_id, limit=limit)


@router.get(
    "/api/v1/evaluation-suites/{suite_id}",
    response_model=EvaluationSuiteResponse,
)
def get_evaluation_suite(
    suite_id: str,
    services: ServicesDep,
    current: Annotated[Principal, Depends(require("evaluation:read"))],
) -> dict[str, Any]:
    try:
        return services.evaluations.get_suite(current, suite_id)
    except Exception as exc:
        raise _handle_evaluation_error(exc) from exc


@router.post(
    "/api/v1/evaluation-datasets",
    status_code=status.HTTP_201_CREATED,
    response_model=EvaluationDatasetDetailResponse,
)
def create_evaluation_dataset(
    value: EvaluationDatasetCreate,
    services: ServicesDep,
    current: Annotated[Principal, Depends(require("evaluation:dataset:manage"))],
    idempotency_key: Annotated[str | None, Header(alias="Idempotency-Key")] = None,
) -> dict[str, Any]:
    try:
        return services.evaluations.create_dataset(
            current,
            value,
            idempotency_key=idempotency_key,
        )
    except Exception as exc:
        raise _handle_evaluation_error(exc) from exc


@router.get(
    "/api/v1/evaluation-datasets/{dataset_id}",
    response_model=EvaluationDatasetDetailResponse,
)
def get_evaluation_dataset(
    dataset_id: str,
    services: ServicesDep,
    current: Annotated[Principal, Depends(require("evaluation:read"))],
) -> dict[str, Any]:
    try:
        return services.evaluations.get_dataset(current, dataset_id)
    except Exception as exc:
        raise _handle_evaluation_error(exc) from exc


@router.post(
    "/api/v1/evaluation-datasets/{dataset_id}/cases",
    status_code=status.HTTP_201_CREATED,
    response_model=EvaluationCaseResponse,
)
def create_evaluation_case(
    dataset_id: str,
    value: EvaluationCaseCreate,
    services: ServicesDep,
    current: Annotated[Principal, Depends(require("evaluation:dataset:manage"))],
    idempotency_key: Annotated[str | None, Header(alias="Idempotency-Key")] = None,
) -> dict[str, Any]:
    try:
        return services.evaluations.add_case(
            current,
            dataset_id,
            value,
            idempotency_key=idempotency_key,
        )
    except Exception as exc:
        raise _handle_evaluation_error(exc) from exc


@router.post(
    "/api/v1/evaluation-runs",
    status_code=status.HTTP_202_ACCEPTED,
    response_model=EvaluationRunDetailResponse,
)
def create_evaluation_run(
    value: EvaluationRunCreate,
    services: ServicesDep,
    current: Annotated[Principal, Depends(require("evaluation:run"))],
    idempotency_key: Annotated[str | None, Header(alias="Idempotency-Key")] = None,
) -> dict[str, Any]:
    try:
        return services.evaluations.create_run(
            current,
            value,
            idempotency_key=idempotency_key,
        )
    except Exception as exc:
        raise _handle_evaluation_error(exc) from exc


@router.get("/api/v1/evaluation-runs", response_model=list[EvaluationRunResponse])
def list_evaluation_runs(
    services: ServicesDep,
    current: Annotated[Principal, Depends(require("evaluation:read"))],
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
    project_id: Annotated[str | None, Query(max_length=120)] = None,
) -> list[dict[str, Any]]:
    return services.evaluations.list_runs(current, project_id=project_id, limit=limit)


@router.get(
    "/api/v1/evaluation-runs/{run_id}",
    response_model=EvaluationRunDetailResponse,
)
def get_evaluation_run(
    run_id: str,
    services: ServicesDep,
    current: Annotated[Principal, Depends(require("evaluation:read"))],
) -> dict[str, Any]:
    try:
        return services.evaluations.get_run(current, run_id)
    except Exception as exc:
        raise _handle_evaluation_error(exc) from exc


@router.post(
    "/api/v1/evaluation-runs/{run_id}/cancel",
    response_model=EvaluationRunResponse,
)
def cancel_evaluation_run(
    run_id: str,
    services: ServicesDep,
    current: Annotated[Principal, Depends(require("evaluation:cancel"))],
    idempotency_key: Annotated[str | None, Header(alias="Idempotency-Key")] = None,
) -> dict[str, Any]:
    try:
        return services.evaluations.cancel_run(
            current,
            run_id,
            idempotency_key=idempotency_key,
        )
    except Exception as exc:
        raise _handle_evaluation_error(exc) from exc


@router.get(
    "/api/v1/evaluation-runs/{run_id}/results",
    response_model=list[EvaluationResultResponse],
)
def list_evaluation_results(
    run_id: str,
    services: ServicesDep,
    current: Annotated[Principal, Depends(require("evaluation:read"))],
) -> list[dict[str, Any]]:
    try:
        return services.evaluations.list_results(current, run_id)
    except Exception as exc:
        raise _handle_evaluation_error(exc) from exc


@router.get(
    "/api/v1/evaluation-runs/{run_id}/metrics",
    response_model=list[MetricResultResponse],
)
def list_evaluation_metrics(
    run_id: str,
    services: ServicesDep,
    current: Annotated[Principal, Depends(require("evaluation:read"))],
) -> list[dict[str, Any]]:
    try:
        return services.evaluations.list_metrics(current, run_id)
    except Exception as exc:
        raise _handle_evaluation_error(exc) from exc


@router.get(
    "/api/v1/evaluation-runs/{run_id}/failures",
    response_model=list[EvaluationFailureResponse],
)
def list_evaluation_failures(
    run_id: str,
    services: ServicesDep,
    current: Annotated[Principal, Depends(require("evaluation:read"))],
) -> list[dict[str, Any]]:
    try:
        return services.evaluations.list_failures(current, run_id)
    except Exception as exc:
        raise _handle_evaluation_error(exc) from exc


@router.post(
    "/api/v1/evaluation-comparisons",
    status_code=status.HTTP_201_CREATED,
    response_model=EvaluationComparisonResponse,
)
def create_evaluation_comparison(
    value: EvaluationComparisonCreate,
    services: ServicesDep,
    current: Annotated[Principal, Depends(require("evaluation:compare"))],
    idempotency_key: Annotated[str | None, Header(alias="Idempotency-Key")] = None,
) -> dict[str, Any]:
    try:
        return services.evaluations.create_comparison(
            current,
            value,
            idempotency_key=idempotency_key,
        )
    except Exception as exc:
        raise _handle_evaluation_error(exc) from exc


@router.get(
    "/api/v1/evaluation-comparisons/{comparison_id}",
    response_model=EvaluationComparisonResponse,
)
def get_evaluation_comparison(
    comparison_id: str,
    services: ServicesDep,
    current: Annotated[Principal, Depends(require("evaluation:read"))],
) -> dict[str, Any]:
    try:
        return services.evaluations.get_comparison(current, comparison_id)
    except Exception as exc:
        raise _handle_evaluation_error(exc) from exc


@router.post(
    "/api/v1/evaluation-runs/{run_id}/reviews",
    status_code=status.HTTP_201_CREATED,
    response_model=EvaluationReviewResponse,
)
def create_evaluation_review(
    run_id: str,
    value: EvaluationReviewCreate,
    services: ServicesDep,
    current: Annotated[Principal, Depends(require("evaluation:review"))],
    idempotency_key: Annotated[str | None, Header(alias="Idempotency-Key")] = None,
) -> dict[str, Any]:
    try:
        return services.evaluations.create_review(
            current,
            run_id,
            value,
            idempotency_key=idempotency_key,
        )
    except Exception as exc:
        raise _handle_evaluation_error(exc) from exc


@router.post(
    "/api/v1/evaluation-runs/{run_id}/promotion-decisions",
    status_code=status.HTTP_201_CREATED,
    response_model=PromotionDecisionResponse,
)
def create_promotion_decision(
    run_id: str,
    value: PromotionDecisionCreate,
    services: ServicesDep,
    current: Annotated[Principal, Depends(require("evaluation:promote"))],
    idempotency_key: Annotated[str | None, Header(alias="Idempotency-Key")] = None,
) -> dict[str, Any]:
    try:
        return services.evaluations.create_promotion_decision(
            current,
            run_id,
            value,
            idempotency_key=idempotency_key,
        )
    except Exception as exc:
        raise _handle_evaluation_error(exc) from exc
