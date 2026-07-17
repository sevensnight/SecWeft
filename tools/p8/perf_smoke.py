#!/usr/bin/env python3
"""Local ASGI performance smoke check for P8.

This deliberately avoids internet access and external services. It exercises the
in-process FastAPI app through httpx ASGITransport with bounded concurrency.
"""

from __future__ import annotations

import argparse
import asyncio
import base64
import hashlib
import json
import statistics
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

import httpx

ROOT = Path(__file__).resolve().parents[2]
SOURCE_ROOT = ROOT / "apps" / "control-plane" / "src"
if str(SOURCE_ROOT) not in sys.path:
    sys.path.insert(0, str(SOURCE_ROOT))

from vulnlab.app import create_app  # noqa: E402
from vulnlab.config import Settings  # noqa: E402


def _settings(temp_root: Path) -> Settings:
    master = base64.urlsafe_b64encode(hashlib.sha256(b"p8-perf-smoke").digest()).decode()
    return Settings(
        env="test",
        db_path=temp_root / "perf.db",
        workspace_root=temp_root / "workspaces",
        admin_key="p8-perf-admin-key-with-sufficient-entropy",
        master_key=master,
        execution_mode="dry_run",
        allowed_hosts=("localhost", "127.0.0.1", "::1"),
        allowed_ports=(80, 443, 8000, 8080, 65534),
        legacy_execution_enabled=False,
    )


async def _request(client: httpx.AsyncClient, semaphore: asyncio.Semaphore) -> float:
    async with semaphore:
        started = time.perf_counter()
        response = await client.get(
            "/api/v1/system/requirements",
            headers={"X-API-Key": "p8-perf-admin-key-with-sufficient-entropy"},
        )
        response.raise_for_status()
        return (time.perf_counter() - started) * 1000


async def _run_async(requests: int, concurrency: int) -> dict[str, Any]:
    with tempfile.TemporaryDirectory(prefix="vulnlab-p8-perf-") as temp:
        app = create_app(_settings(Path(temp)))
        transport = httpx.ASGITransport(app=app)
        semaphore = asyncio.Semaphore(concurrency)
        async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
            health = await client.get("/health")
            health.raise_for_status()
            timings = await asyncio.gather(*(_request(client, semaphore) for _ in range(requests)))
    sorted_timings = sorted(timings)
    p95_index = max(0, min(len(sorted_timings) - 1, round(len(sorted_timings) * 0.95) - 1))
    return {
        "requests": requests,
        "concurrency": concurrency,
        "min_ms": round(min(timings), 3),
        "mean_ms": round(statistics.fmean(timings), 3),
        "p95_ms": round(sorted_timings[p95_index], 3),
        "max_ms": round(max(timings), 3),
    }


def run(requests: int = 64, concurrency: int = 16, p95_budget_ms: float = 250.0) -> dict[str, Any]:
    if requests < 1:
        raise ValueError("requests must be positive")
    if concurrency < 1 or concurrency > requests:
        raise ValueError("concurrency must be between 1 and requests")
    metrics = asyncio.run(_run_async(requests, concurrency))
    return {
        "valid": metrics["p95_ms"] <= p95_budget_ms,
        "budget": {"p95_ms": p95_budget_ms},
        "metrics": metrics,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--requests", type=int, default=64)
    parser.add_argument("--concurrency", type=int, default=16)
    parser.add_argument("--p95-budget-ms", type=float, default=250.0)
    args = parser.parse_args()
    result = run(args.requests, args.concurrency, args.p95_budget_ms)
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if result["valid"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
