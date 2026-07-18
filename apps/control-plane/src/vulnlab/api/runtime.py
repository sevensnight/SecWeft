from __future__ import annotations

import sqlite3
import time
import uuid
from collections.abc import Callable, Mapping
from contextlib import suppress
from typing import Any

from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from psycopg import Error as PsycopgError
from psycopg.errors import ForeignKeyViolation, UniqueViolation

from ..enterprise.errors import EnterpriseError
from ..model_gateway import ModelGatewayError, ProviderConfigurationError, RateLimitError
from ..observability import request_logger
from ..operational_resilience import (
    OperationalDependencyUnavailable,
    OperationalQueueSaturated,
    OperationalQuotaExceeded,
    OperationalRateLimited,
)
from ..orchestrator import TaskStateError
from ..sandbox import SandboxPolicyError, SandboxRuntimeError
from ..scope import ScopeViolation
from ..security import AuthenticationError
from .services import Services


def install_runtime(app: FastAPI, services: Services) -> None:
    logger = request_logger()
    app.add_middleware(
        CORSMiddleware,
        allow_origins=[],
        allow_credentials=False,
        allow_methods=["GET", "POST", "PUT", "PATCH"],
        allow_headers=[
            "Accept",
            "Authorization",
            "Content-Type",
            "Idempotency-Key",
            "Last-Event-ID",
            "traceparent",
            "tracestate",
            "X-API-Key",
            "X-Project-ID",
            "X-Provider-API-Key",
            "X-Request-ID",
            "X-Trace-ID",
        ],
    )

    @app.middleware("http")
    async def request_metadata(request: Request, call_next: Callable[..., Any]) -> Response:
        started = time.perf_counter()
        supplied_request_id = request.headers.get("X-Request-ID")
        try:
            request_id = (
                str(uuid.UUID(supplied_request_id)) if supplied_request_id else str(uuid.uuid4())
            )
        except ValueError:
            request_id = str(uuid.uuid4())
        traceparent = request.headers.get("traceparent", "")
        trace_parts = traceparent.split("-")
        supplied_trace_id = request.headers.get("X-Trace-ID", "")
        if (
            len(trace_parts) == 4
            and len(trace_parts[1]) == 32
            and trace_parts[1] != "0" * 32
            and all(char in "0123456789abcdefABCDEF" for char in trace_parts[1])
        ):
            trace_id = trace_parts[1].lower()
        elif 16 <= len(supplied_trace_id) <= 64 and all(
            char in "0123456789abcdefABCDEF" for char in supplied_trace_id
        ):
            trace_id = supplied_trace_id.lower()
        else:
            trace_id = uuid.uuid4().hex
        request.state.request_id = request_id
        request.state.trace_id = trace_id
        if (
            services.settings.auth_mode == "compatibility"
            and request.method not in {"GET", "HEAD", "OPTIONS"}
            and not bool(services.audit.verify()["valid"])
        ):
            return JSONResponse(
                status_code=503,
                content={
                    "detail": "audit integrity check failed; state-changing operations are blocked",
                    "code": "audit_integrity_failed",
                    "request_id": request_id,
                    "trace_id": trace_id,
                },
                headers={
                    "X-Request-ID": request_id,
                    "X-Trace-ID": trace_id,
                    "Cache-Control": "no-store",
                },
            )
        response = await call_next(request)
        response.headers["X-Request-ID"] = request_id
        response.headers["X-Trace-ID"] = trace_id
        response.headers["X-Content-Type-Options"] = "nosniff"
        if response.media_type == "text/event-stream":
            response.headers["Cache-Control"] = "no-cache, no-transform"
        else:
            response.headers["Cache-Control"] = "no-store"
        response.headers["Content-Security-Policy"] = "default-src 'none'; frame-ancestors 'none'"
        logger.info(
            "request.completed",
            extra={
                "request_id": request_id,
                "trace_id": trace_id,
                "method": request.method,
                "path": request.url.path,
                "status_code": response.status_code,
                "duration_ms": round((time.perf_counter() - started) * 1000, 3),
                "tenant_id": getattr(request.state, "tenant_id", None),
                "project_id": getattr(request.state, "project_id", None),
                "user_id": getattr(request.state, "user_id", None),
            },
        )
        return response

    def problem(
        request: Request,
        *,
        status_code: int,
        detail: str,
        code: str,
        headers: Mapping[str, str] | None = None,
        errors: list[dict[str, Any]] | None = None,
    ) -> JSONResponse:
        content: dict[str, Any] = {
            "detail": detail,
            "code": code,
            "request_id": getattr(request.state, "request_id", None),
            "trace_id": getattr(request.state, "trace_id", None),
        }
        if errors:
            content["errors"] = errors
        response_headers = {
            "X-Request-ID": str(content["request_id"] or ""),
            "X-Trace-ID": str(content["trace_id"] or ""),
            "X-Content-Type-Options": "nosniff",
            "Cache-Control": "no-store",
        }
        if headers:
            response_headers.update(headers)
        return JSONResponse(status_code=status_code, content=content, headers=response_headers)

    def audit_rejected_request(request: Request, code: str, detail: str) -> None:
        if services.settings.auth_mode != "compatibility":
            return
        if not bool(services.audit.verify()["valid"]):
            return
        actor_id = "anonymous"
        with suppress(AuthenticationError):
            actor_id = services.security.authenticate(request.headers.get("X-API-Key")).id
        services.audit.record(
            actor_id,
            "request.denied",
            "api_route",
            request.url.path,
            "denied",
            {"method": request.method, "code": code, "detail": detail},
        )

    @app.exception_handler(ScopeViolation)
    async def scope_error(request: Request, exc: ScopeViolation) -> JSONResponse:
        audit_rejected_request(request, "scope_violation", str(exc))
        return problem(request, status_code=422, detail=str(exc), code="scope_violation")

    @app.exception_handler(TaskStateError)
    async def state_error(request: Request, exc: TaskStateError) -> JSONResponse:
        audit_rejected_request(request, "invalid_task_state", str(exc))
        return problem(request, status_code=409, detail=str(exc), code="invalid_task_state")

    @app.exception_handler(SandboxPolicyError)
    async def sandbox_error(request: Request, exc: SandboxPolicyError) -> JSONResponse:
        audit_rejected_request(request, "sandbox_policy_denied", str(exc))
        return problem(request, status_code=422, detail=str(exc), code="sandbox_policy_denied")

    @app.exception_handler(SandboxRuntimeError)
    async def sandbox_runtime_error(request: Request, exc: SandboxRuntimeError) -> JSONResponse:
        return problem(
            request, status_code=503, detail=str(exc), code="sandbox_runtime_unavailable"
        )

    @app.exception_handler(RateLimitError)
    async def model_rate_limit_error(request: Request, exc: RateLimitError) -> JSONResponse:
        return problem(request, status_code=429, detail=str(exc), code="model_rate_limited")

    @app.exception_handler(OperationalRateLimited)
    async def operational_rate_limited(
        request: Request, exc: OperationalRateLimited
    ) -> JSONResponse:
        return problem(request, status_code=429, detail=str(exc), code="rate_limited")

    @app.exception_handler(OperationalQuotaExceeded)
    async def operational_quota_exceeded(
        request: Request, exc: OperationalQuotaExceeded
    ) -> JSONResponse:
        return problem(request, status_code=429, detail=str(exc), code="quota_exceeded")

    @app.exception_handler(OperationalQueueSaturated)
    async def operational_queue_saturated(
        request: Request, exc: OperationalQueueSaturated
    ) -> JSONResponse:
        return problem(request, status_code=503, detail=str(exc), code="queue_saturated")

    @app.exception_handler(OperationalDependencyUnavailable)
    async def operational_dependency_unavailable(
        request: Request, exc: OperationalDependencyUnavailable
    ) -> JSONResponse:
        return problem(
            request,
            status_code=503,
            detail=str(exc),
            code="dependency_unavailable",
        )

    @app.exception_handler(ModelGatewayError)
    async def gateway_error(request: Request, exc: ModelGatewayError) -> JSONResponse:
        return problem(request, status_code=503, detail=str(exc), code="model_gateway_unavailable")

    @app.exception_handler(ProviderConfigurationError)
    async def provider_configuration_error(
        request: Request, exc: ProviderConfigurationError
    ) -> JSONResponse:
        audit_rejected_request(request, "provider_configuration_invalid", str(exc))
        return problem(
            request, status_code=422, detail=str(exc), code="provider_configuration_invalid"
        )

    @app.exception_handler(PermissionError)
    async def permission_error(request: Request, exc: PermissionError) -> JSONResponse:
        audit_rejected_request(request, "permission_denied", str(exc))
        return problem(request, status_code=403, detail=str(exc), code="permission_denied")

    @app.exception_handler(sqlite3.IntegrityError)
    async def conflict_error(request: Request, __: sqlite3.IntegrityError) -> JSONResponse:
        return problem(
            request,
            status_code=409,
            detail="resource conflicts with existing data",
            code="conflict",
        )

    @app.exception_handler(EnterpriseError)
    async def enterprise_error(request: Request, exc: EnterpriseError) -> JSONResponse:
        headers = {"WWW-Authenticate": 'Bearer realm="vulnlab"'} if exc.status_code == 401 else None
        return problem(
            request,
            status_code=exc.status_code,
            detail=exc.detail,
            code=exc.code,
            headers=headers,
        )

    @app.exception_handler(UniqueViolation)
    async def postgres_unique_violation(request: Request, __: UniqueViolation) -> JSONResponse:
        return problem(
            request,
            status_code=409,
            detail="resource conflicts with existing data",
            code="conflict",
        )

    @app.exception_handler(ForeignKeyViolation)
    async def postgres_foreign_key_violation(
        request: Request, __: ForeignKeyViolation
    ) -> JSONResponse:
        return problem(
            request,
            status_code=409,
            detail="resource references missing or conflicting data",
            code="conflict",
        )

    @app.exception_handler(HTTPException)
    async def http_error(request: Request, exc: HTTPException) -> JSONResponse:
        code_by_status = {
            401: "authentication_failed",
            429: "rate_limited",
            403: "permission_denied",
            404: "resource_not_found",
            409: "conflict",
            503: "dependency_unavailable",
        }
        detail = exc.detail if isinstance(exc.detail, str) else "request failed"
        return problem(
            request,
            status_code=exc.status_code,
            detail=detail,
            code=code_by_status.get(exc.status_code, "http_error"),
            headers=exc.headers,
        )

    @app.exception_handler(RequestValidationError)
    async def validation_error(request: Request, exc: RequestValidationError) -> JSONResponse:
        errors = [
            {
                "location": [str(part) for part in error.get("loc", ())],
                "message": str(error.get("msg", "invalid value")),
                "type": str(error.get("type", "validation_error")),
            }
            for error in exc.errors()
        ]
        return problem(
            request,
            status_code=422,
            detail="request validation failed",
            code="invalid_request",
            errors=errors,
        )

    @app.exception_handler(PsycopgError)
    async def database_error(request: Request, exc: PsycopgError) -> JSONResponse:
        logger.error(
            "request.database_error",
            extra={
                "request_id": getattr(request.state, "request_id", None),
                "trace_id": getattr(request.state, "trace_id", None),
                "method": request.method,
                "path": request.url.path,
                "error_type": type(exc).__name__,
            },
        )
        return problem(
            request,
            status_code=503,
            detail="enterprise data service is unavailable",
            code="enterprise_service_unavailable",
        )

    @app.exception_handler(Exception)
    async def unexpected_error(request: Request, exc: Exception) -> JSONResponse:
        logger.error(
            "request.unexpected_error",
            exc_info=(type(exc), exc, exc.__traceback__),
            extra={
                "request_id": getattr(request.state, "request_id", None),
                "trace_id": getattr(request.state, "trace_id", None),
                "method": request.method,
                "path": request.url.path,
                "error_type": type(exc).__name__,
            },
        )
        return problem(
            request,
            status_code=500,
            detail="an unexpected server error occurred",
            code="internal_error",
        )
