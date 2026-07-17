from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI

from . import __version__
from .api.routers import ALL_ROUTERS
from .api.runtime import install_runtime
from .api.services import build_services
from .config import Settings


def create_app(settings: Settings | None = None) -> FastAPI:
    """Create the P1 control plane with an explicit compatibility boundary."""
    services = build_services(settings or Settings.from_env())

    @asynccontextmanager
    async def lifespan(_: FastAPI) -> AsyncIterator[None]:
        try:
            yield
        finally:
            services.close()

    app = FastAPI(
        title="VulnLab Module 2 Control Plane",
        version=__version__,
        description=(
            "P1 enterprise identity, tenancy, RBAC, configuration, and audit API. "
            "The P0 API-key surface remains an explicitly disabled-by-default compatibility layer."
        ),
        lifespan=lifespan,
    )
    app.state.services = services
    install_runtime(app, services)
    for router in ALL_ROUTERS:
        app.include_router(router)
    return app
