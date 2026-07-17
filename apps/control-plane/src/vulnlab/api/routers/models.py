from __future__ import annotations

import json
from typing import Annotated, Any

from fastapi import APIRouter, Depends, Header, HTTPException
from fastapi.responses import StreamingResponse

from ...schemas import ModelRequest, ProviderCreate
from ...security import Principal
from ..dependencies import ServicesDep, require

router = APIRouter(tags=["models"])


@router.post("/api/v1/providers", status_code=201)
def create_provider(
    value: ProviderCreate,
    services: ServicesDep,
    current: Annotated[Principal, Depends(require("provider:create"))],
) -> dict[str, Any]:
    return services.providers.create(current, value)


@router.get("/api/v1/providers")
def list_providers(
    services: ServicesDep,
    _: Annotated[Principal, Depends(require("provider:read"))],
) -> list[dict[str, Any]]:
    return services.providers.list()


@router.get("/api/v1/providers/health")
def provider_health(
    services: ServicesDep,
    _: Annotated[Principal, Depends(require("provider:read"))],
) -> list[dict[str, Any]]:
    return services.gateway.health()


@router.put("/api/v1/providers/{provider_id}/secret")
def rotate_provider_secret(
    provider_id: str,
    services: ServicesDep,
    current: Annotated[Principal, Depends(require("provider:update"))],
    api_key: Annotated[str | None, Header(alias="X-Provider-API-Key")] = None,
) -> dict[str, Any]:
    try:
        return services.providers.rotate_key(current, provider_id, api_key)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.post("/api/v1/providers/{provider_id}/enabled")
def toggle_provider(
    provider_id: str,
    enabled: bool,
    services: ServicesDep,
    current: Annotated[Principal, Depends(require("provider:update"))],
) -> dict[str, Any]:
    try:
        return services.providers.set_enabled(current, provider_id, enabled)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.get("/api/v1/models/catalog")
def model_catalog(
    services: ServicesDep,
    _: Annotated[Principal, Depends(require("provider:read"))],
) -> list[dict[str, Any]]:
    return services.gateway.catalog()


@router.get("/api/v1/models/invocations")
def model_invocations(
    services: ServicesDep,
    current: Annotated[Principal, Depends(require("provider:read"))],
    limit: int = 100,
) -> list[dict[str, Any]]:
    return services.gateway.invocations(current, limit)


@router.post("/api/v1/models/complete")
async def model_complete(
    value: ModelRequest,
    services: ServicesDep,
    current: Annotated[Principal, Depends(require("task:create"))],
) -> dict[str, Any]:
    return await services.gateway.complete(
        current,
        [message.model_dump() for message in value.messages],
        value.purpose,
        value.max_tokens,
        value.response_format.type,
        [tool.model_dump() for tool in value.tools],
    )


@router.post("/api/v1/models/stream")
async def model_stream(
    value: ModelRequest,
    services: ServicesDep,
    current: Annotated[Principal, Depends(require("task:create"))],
) -> StreamingResponse:
    async def events() -> Any:
        result = await services.gateway.complete(
            current,
            [message.model_dump() for message in value.messages],
            value.purpose,
            value.max_tokens,
            value.response_format.type,
            [tool.model_dump() for tool in value.tools],
        )
        content = str(result.pop("content"))
        for index, start in enumerate(range(0, len(content), 64), start=1):
            payload = {"index": index, "delta": content[start : start + 64]}
            yield f"event: delta\ndata: {json.dumps(payload, ensure_ascii=False)}\n\n"
        yield f"event: done\ndata: {json.dumps(result, ensure_ascii=False)}\n\n"

    return StreamingResponse(events(), media_type="text/event-stream")
