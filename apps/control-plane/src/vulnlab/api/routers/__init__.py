from .audit import router as audit_router
from .authorization import router as authorization_router
from .cases import router as cases_router
from .enterprise_iam import router as enterprise_iam_router
from .evaluations import router as evaluations_router
from .execution import router as execution_router
from .knowledge import router as knowledge_router
from .models import router as models_router
from .policies import router as policies_router
from .releases import router as releases_router
from .system import router as system_router
from .tasks import router as tasks_router
from .users import router as users_router
from .validation_executions import router as validation_executions_router
from .validation_plans import router as validation_plans_router

ALL_ROUTERS = (
    system_router,
    users_router,
    models_router,
    authorization_router,
    tasks_router,
    knowledge_router,
    policies_router,
    cases_router,
    evaluations_router,
    releases_router,
    validation_plans_router,
    validation_executions_router,
    execution_router,
    audit_router,
    enterprise_iam_router,
)
