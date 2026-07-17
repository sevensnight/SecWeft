from __future__ import annotations


class EnterpriseError(Exception):
    """Safe error carrying a stable API code and status."""

    status_code = 500
    code = "enterprise_error"

    def __init__(self, detail: str = "enterprise request failed") -> None:
        super().__init__(detail)
        self.detail = detail


class EnterpriseAuthenticationError(EnterpriseError):
    status_code = 401
    code = "authentication_failed"

    def __init__(self, detail: str = "bearer token is missing or invalid") -> None:
        super().__init__(detail)


class EnterpriseAuthorizationError(EnterpriseError):
    status_code = 403
    code = "permission_denied"


class EnterpriseNotFoundError(EnterpriseError):
    status_code = 404
    code = "resource_not_found"


class EnterpriseConflictError(EnterpriseError):
    status_code = 409
    code = "conflict"

    def __init__(
        self, detail: str = "resource conflicts with existing data", *, code: str | None = None
    ):
        super().__init__(detail)
        if code is not None:
            self.code = code


class EnterpriseValidationError(EnterpriseError):
    status_code = 422
    code = "invalid_request"


class EnterpriseUnavailableError(EnterpriseError):
    status_code = 503
    code = "enterprise_service_unavailable"


class RequestInProgressError(EnterpriseConflictError):
    code = "request_in_progress"

    def __init__(self) -> None:
        super().__init__("an identical request is already being processed", code=self.code)
