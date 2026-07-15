from __future__ import annotations

from fastapi import FastAPI

from . import __version__
from .api.routers import ALL_ROUTERS
from .api.runtime import install_runtime
from .api.services import build_services
from .config import Settings


def create_app(settings: Settings | None = None) -> FastAPI:
    """Create the control-plane compatibility API through explicit composition."""
    services = build_services(settings or Settings.from_env())
    app = FastAPI(
        title="VulnLab Module 2 Control Plane",
        version=__version__,
        description=(
            "P0 compatibility API for the authorized-lab reference runtime. "
            "Enterprise service extraction is governed by the checked-in architecture contracts."
        ),
    )
    app.state.services = services
    install_runtime(app, services)
    for router in ALL_ROUTERS:
        app.include_router(router)
    return app
