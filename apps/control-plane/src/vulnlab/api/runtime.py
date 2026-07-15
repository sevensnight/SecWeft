from __future__ import annotations

import sqlite3
import uuid
from collections.abc import Callable
from contextlib import suppress
from typing import Any

from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from ..model_gateway import ModelGatewayError, ProviderConfigurationError
from ..orchestrator import TaskStateError
from ..sandbox import SandboxPolicyError, SandboxRuntimeError
from ..scope import ScopeViolation
from ..security import AuthenticationError
from .services import Services


def install_runtime(app: FastAPI, services: Services) -> None:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=[],
        allow_credentials=False,
        allow_methods=["GET", "POST", "PUT", "PATCH"],
        allow_headers=[
            "Accept",
            "Content-Type",
            "Last-Event-ID",
            "X-API-Key",
            "X-Provider-API-Key",
            "X-Request-ID",
        ],
    )

    @app.middleware("http")
    async def request_metadata(request: Request, call_next: Callable[..., Any]) -> Response:
        request_id = request.headers.get("X-Request-ID") or str(uuid.uuid4())
        request.state.request_id = request_id
        if request.method not in {"GET", "HEAD", "OPTIONS"} and not bool(
            services.audit.verify()["valid"]
        ):
            return JSONResponse(
                status_code=503,
                content={
                    "detail": "audit integrity check failed; state-changing operations are blocked",
                    "code": "audit_integrity_failed",
                    "request_id": request_id,
                },
                headers={"X-Request-ID": request_id, "Cache-Control": "no-store"},
            )
        response = await call_next(request)
        response.headers["X-Request-ID"] = request_id
        response.headers["X-Content-Type-Options"] = "nosniff"
        if response.media_type == "text/event-stream":
            response.headers["Cache-Control"] = "no-cache, no-transform"
        else:
            response.headers["Cache-Control"] = "no-store"
        response.headers["Content-Security-Policy"] = "default-src 'none'; frame-ancestors 'none'"
        return response

    def audit_rejected_request(request: Request, code: str, detail: str) -> None:
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
        return JSONResponse(
            status_code=422, content={"detail": str(exc), "code": "scope_violation"}
        )

    @app.exception_handler(TaskStateError)
    async def state_error(request: Request, exc: TaskStateError) -> JSONResponse:
        audit_rejected_request(request, "invalid_task_state", str(exc))
        return JSONResponse(
            status_code=409, content={"detail": str(exc), "code": "invalid_task_state"}
        )

    @app.exception_handler(SandboxPolicyError)
    async def sandbox_error(request: Request, exc: SandboxPolicyError) -> JSONResponse:
        audit_rejected_request(request, "sandbox_policy_denied", str(exc))
        return JSONResponse(
            status_code=422, content={"detail": str(exc), "code": "sandbox_policy_denied"}
        )

    @app.exception_handler(SandboxRuntimeError)
    async def sandbox_runtime_error(_: Request, exc: SandboxRuntimeError) -> JSONResponse:
        return JSONResponse(
            status_code=503, content={"detail": str(exc), "code": "sandbox_runtime_unavailable"}
        )

    @app.exception_handler(ModelGatewayError)
    async def gateway_error(_: Request, exc: ModelGatewayError) -> JSONResponse:
        return JSONResponse(
            status_code=503, content={"detail": str(exc), "code": "model_gateway_unavailable"}
        )

    @app.exception_handler(ProviderConfigurationError)
    async def provider_configuration_error(
        request: Request, exc: ProviderConfigurationError
    ) -> JSONResponse:
        audit_rejected_request(request, "provider_configuration_invalid", str(exc))
        return JSONResponse(
            status_code=422, content={"detail": str(exc), "code": "provider_configuration_invalid"}
        )

    @app.exception_handler(PermissionError)
    async def permission_error(request: Request, exc: PermissionError) -> JSONResponse:
        audit_rejected_request(request, "permission_denied", str(exc))
        return JSONResponse(
            status_code=403, content={"detail": str(exc), "code": "permission_denied"}
        )

    @app.exception_handler(sqlite3.IntegrityError)
    async def conflict_error(_: Request, __: sqlite3.IntegrityError) -> JSONResponse:
        return JSONResponse(
            status_code=409,
            content={"detail": "resource conflicts with existing data", "code": "conflict"},
        )
