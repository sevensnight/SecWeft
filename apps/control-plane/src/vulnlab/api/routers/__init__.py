from .audit import router as audit_router
from .authorization import router as authorization_router
from .execution import router as execution_router
from .knowledge import router as knowledge_router
from .models import router as models_router
from .system import router as system_router
from .tasks import router as tasks_router
from .users import router as users_router

ALL_ROUTERS = (
    system_router,
    users_router,
    models_router,
    authorization_router,
    tasks_router,
    knowledge_router,
    execution_router,
    audit_router,
)
