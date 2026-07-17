from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException

from ...schemas import AssetProbeRequest, PolicyEvaluationRequest, SandboxRequest
from ...scope import parse_target
from ...security import Principal
from ..dependencies import ServicesDep, owned_scope, require

router = APIRouter(tags=["execution"])


@router.post("/api/v1/assets/probe")
async def asset_probe(
    value: AssetProbeRequest,
    services: ServicesDep,
    current: Annotated[Principal, Depends(require("asset:probe"))],
) -> dict[str, Any]:
    policy_request = PolicyEvaluationRequest(
        action="asset.probe",
        resource_type="scope",
        resource_id=value.scope_id,
        scope_id=value.scope_id,
        target=value.target,
        ports=value.ports,
        metadata={"timeout_seconds": value.timeout_seconds},
    )
    if not services.settings.legacy_execution_enabled:
        services.policy.evaluate(current, policy_request, enforced=True)
        raise HTTPException(
            status_code=503,
            detail="asset probing is disabled during the P0/P1 enterprise migration",
        )
    owned_scope(services, value.scope_id, current)
    services.policy.enforce(current, policy_request)
    result = await services.scope.probe(
        value.target,
        value.scope_id,
        value.ports,
        value.timeout_seconds,
    )
    services.audit.record(
        current.id,
        "asset.probe",
        "scope",
        value.scope_id,
        details={
            "target": parse_target(value.target).host,
            "ports": value.ports,
            "result_summary": [
                {"port": item["port"], "status": item["status"]} for item in result["results"]
            ],
        },
    )
    return result


@router.post("/api/v1/sandbox/runs", status_code=201)
async def sandbox_run(
    value: SandboxRequest,
    services: ServicesDep,
    current: Annotated[Principal, Depends(require("sandbox:execute"))],
) -> dict[str, Any]:
    policy_request = PolicyEvaluationRequest(
        action="sandbox.run",
        resource_type="task" if value.task_id else "sandbox_run",
        resource_id=value.task_id or "ad-hoc",
        task_id=value.task_id,
        argv=value.argv,
        metadata={"timeout_seconds": value.timeout_seconds, "image": value.image},
    )
    if not services.settings.legacy_execution_enabled:
        services.policy.evaluate(current, policy_request, enforced=True)
        raise HTTPException(
            status_code=503,
            detail="sandbox execution is disabled during the P0/P1 enterprise migration",
        )
    services.policy.enforce(current, policy_request)
    return await services.sandbox.run(current, value)
