from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, Depends

from ... import __version__
from ...security import Principal
from ..dependencies import ServicesDep, require

router = APIRouter(tags=["system"])


@router.get("/health")
def health(services: ServicesDep) -> dict[str, Any]:
    return {"status": "ok", "version": __version__, "mode": services.settings.execution_mode}


@router.get("/ready")
def ready(services: ServicesDep) -> dict[str, Any]:
    services.db.fetch_one("SELECT 1")
    return {"status": "ready", "database": "ok"}


@router.get("/api/v1/system/requirements")
def requirements(
    services: ServicesDep,
    _: Annotated[Principal, Depends(require("health:read"))],
) -> dict[str, Any]:
    return {
        "scope": "P0 enterprise engineering baseline with a disabled-by-default legacy reference runtime",
        "implemented": {
            "2.1": "legacy reference: model adapters and failover; enterprise gateway is P2",
            "2.2": "legacy reference: encrypted write-only keys; tenant credential domain is P2",
            "2.3": "legacy reference: limited local/open-compatible adapters; registry is P2",
            "2.4": "P0 baseline: versioned REST/OpenAPI contract and generated TypeScript types",
            "2.5": "legacy reference: single-process DAG; durable distributed state machine is P3",
            "2.6": "legacy reference only and disabled by default; controlled validation is P6",
            "2.7": "legacy reference only and disabled by default; enterprise asset service is P5",
            "2.8": "legacy reference: declarative skill registry; enterprise registry is P3",
            "2.9": "legacy reference: task context/checkpoint; tenant-aware service is P4",
            "2.10": "legacy reference only and disabled by default; sandbox service is P5",
            "2.11": "legacy reference: per-process isolation; distributed quotas are P3",
            "2.12": "P0 baseline: versioned domain protocol schema; orchestration is P3",
            "2.13": "legacy reference: ACL-prefiltered retrieval; knowledge service is P4",
            "2.14": "P0 design: policy/approval model; multi-level enforcement is P1/P5",
            "2.15": "legacy reference: local HMAC chain; tenant audit platform is P1",
            "2.16": "P0 baseline: Monorepo, Compose platform, gateway, observability and CI",
            "2.17": "P0 design: eight-role matrix; tenant/project RBAC is P1",
        },
        "p0_migration": {
            "status": "baseline_ready",
            "target": "tenant-aware API-first enterprise control plane",
            "compatibility": "existing endpoints remain available behind the reference runtime",
            "legacy_execution_enabled": services.settings.legacy_execution_enabled,
        },
        "excluded": [
            "public-internet scanning without deployment allowlisting",
            "weaponized exploit generation, persistence, credential access, evasion, or stealth optimization",
            "a claim that ordinary containers are an absolute anti-escape boundary",
        ],
    }
