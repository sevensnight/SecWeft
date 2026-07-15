from __future__ import annotations

import ipaddress
import json
import uuid
from datetime import UTC, datetime
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException

from ...schemas import ApprovalRequest, ScopeCreate, TargetProfileCreate
from ...scope import parse_target, row_scope_hash, scope_hash
from ...security import Principal
from ..dependencies import ServicesDep, owned_scope, require
from ..serializers import serialize_profile, serialize_scope

router = APIRouter(tags=["authorization"])


@router.post("/api/v1/scopes", status_code=201)
def create_scope(
    value: ScopeCreate,
    services: ServicesDep,
    current: Annotated[Principal, Depends(require("scope:create"))],
) -> dict[str, Any]:
    if value.approved:
        raise HTTPException(
            status_code=422,
            detail="scope creation and approval must be separate operations",
        )
    if "*" in value.target_pattern:
        raise HTTPException(
            status_code=422,
            detail="wildcard scopes are forbidden; use an explicit host or CIDR",
        )
    if "/" in value.target_pattern:
        try:
            normalized_pattern = str(ipaddress.ip_network(value.target_pattern, strict=False))
        except ValueError as exc:
            raise HTTPException(status_code=422, detail="invalid CIDR scope") from exc
    else:
        normalized_pattern = parse_target(value.target_pattern).host
    scope_id = str(uuid.uuid4())
    created_at = datetime.now(UTC).isoformat()
    expires = value.expires_at.astimezone(UTC).isoformat() if value.expires_at else None
    digest = scope_hash(normalized_pattern, value.protocols, value.ports, expires)
    services.db.execute(
        """INSERT INTO scopes(id,name,target_pattern,protocols_json,ports_json,expires_at,approved,
           approved_by,approved_at,approval_reason,resolved_ips_json,scope_hash,created_by,created_at)
           VALUES(?,?,?,?,?,?,0,NULL,NULL,NULL,'[]',?,?,?)""",
        (
            scope_id,
            value.name,
            normalized_pattern,
            json.dumps(value.protocols),
            json.dumps(value.ports),
            expires,
            digest,
            current.id,
            created_at,
        ),
    )
    services.audit.record(
        current.id,
        "scope.create",
        "scope",
        scope_id,
        details={
            "target_pattern": normalized_pattern,
            "protocols": value.protocols,
            "ports": value.ports,
            "expires_at": expires,
            "scope_hash": digest,
        },
    )
    return serialize_scope(services.db.fetch_one("SELECT * FROM scopes WHERE id=?", (scope_id,)))


@router.get("/api/v1/scopes")
def list_scopes(
    services: ServicesDep,
    current: Annotated[Principal, Depends(require("scope:read"))],
) -> list[dict[str, Any]]:
    if current.role.value == "admin":
        rows = services.db.fetch_all("SELECT * FROM scopes ORDER BY created_at DESC")
    else:
        rows = services.db.fetch_all(
            "SELECT * FROM scopes WHERE created_by=? ORDER BY created_at DESC",
            (current.id,),
        )
    return [serialize_scope(row) for row in rows]


@router.post("/api/v1/scopes/{scope_id}/approve")
def approve_scope(
    scope_id: str,
    value: ApprovalRequest,
    services: ServicesDep,
    current: Annotated[Principal, Depends(require("scope:approve"))],
) -> dict[str, Any]:
    row = services.db.fetch_one("SELECT * FROM scopes WHERE id=?", (scope_id,))
    if row is None:
        raise HTTPException(status_code=404, detail="scope not found")
    if value.approved and row["created_by"] == current.id:
        raise HTTPException(status_code=403, detail="scope creators cannot approve their own scope")
    if row["scope_hash"] != row_scope_hash(row):
        raise HTTPException(
            status_code=409,
            detail="scope content changed; recreate it before approval",
        )
    now = datetime.now(UTC).isoformat()
    resolved_ips = services.scope.approval_snapshot(row["target_pattern"]) if value.approved else []
    signed_hash = scope_hash(
        row["target_pattern"],
        json.loads(row["protocols_json"]),
        json.loads(row["ports_json"]),
        row["expires_at"],
        resolved_ips,
    )
    services.db.execute(
        """UPDATE scopes SET approved=?,approved_by=?,approved_at=?,approval_reason=?,
           resolved_ips_json=?,scope_hash=? WHERE id=?""",
        (
            int(value.approved),
            current.id,
            now,
            value.reason,
            json.dumps(resolved_ips),
            signed_hash,
            scope_id,
        ),
    )
    services.audit.record(
        current.id,
        "scope.approve" if value.approved else "scope.reject",
        "scope",
        scope_id,
        details={"reason": value.reason, "scope_hash": signed_hash, "resolved_ips": resolved_ips},
    )
    return serialize_scope(services.db.fetch_one("SELECT * FROM scopes WHERE id=?", (scope_id,)))


@router.post("/api/v1/target-profiles", status_code=201)
def create_profile(
    value: TargetProfileCreate,
    services: ServicesDep,
    current: Annotated[Principal, Depends(require("profile:create"))],
) -> dict[str, Any]:
    owned_scope(services, value.scope_id, current)
    services.scope.validate(value.target, value.scope_id)
    if value.proxy_url:
        if value.proxy_scope_id is None:
            raise HTTPException(status_code=422, detail="proxy_scope_id is required")
        owned_scope(services, value.proxy_scope_id, current)
        services.scope.validate(str(value.proxy_url), value.proxy_scope_id)
    profile_id = str(uuid.uuid4())
    created_at = datetime.now(UTC).isoformat()
    services.db.execute(
        """INSERT INTO target_profiles(id,name,target,proxy_url,proxy_scope_id,intent,indicators_json,
           scope_id,created_by,created_at) VALUES(?,?,?,?,?,?,?,?,?,?)""",
        (
            profile_id,
            value.name,
            value.target,
            str(value.proxy_url) if value.proxy_url else None,
            value.proxy_scope_id,
            value.intent,
            json.dumps(value.indicators, ensure_ascii=False),
            value.scope_id,
            current.id,
            created_at,
        ),
    )
    services.audit.record(
        current.id,
        "target_profile.create",
        "target_profile",
        profile_id,
        details={
            "scope_id": value.scope_id,
            "proxy_scope_id": value.proxy_scope_id,
            "intent": value.intent,
        },
    )
    return serialize_profile(
        services.db.fetch_one("SELECT * FROM target_profiles WHERE id=?", (profile_id,))
    )


@router.get("/api/v1/target-profiles")
def list_profiles(
    services: ServicesDep,
    current: Annotated[Principal, Depends(require("profile:read"))],
) -> list[dict[str, Any]]:
    if current.role.value == "admin":
        rows = services.db.fetch_all("SELECT * FROM target_profiles ORDER BY created_at DESC")
    else:
        rows = services.db.fetch_all(
            "SELECT * FROM target_profiles WHERE created_by=? ORDER BY created_at DESC",
            (current.id,),
        )
    return [serialize_profile(row) for row in rows]
