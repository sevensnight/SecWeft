from __future__ import annotations

from dataclasses import dataclass

from ..config import Settings
from .auth import OidcTokenVerifier
from .repository import EnterpriseRepository


@dataclass(slots=True)
class EnterpriseServices:
    verifier: OidcTokenVerifier
    repository: EnterpriseRepository

    def close(self) -> None:
        self.repository.close()


def build_enterprise_services(settings: Settings) -> EnterpriseServices:
    if settings.auth_mode != "oidc":
        raise RuntimeError("enterprise services require OIDC mode")
    if not all(
        (
            settings.database_url,
            settings.oidc_issuer,
            settings.oidc_audience,
            settings.oidc_jwks_url,
        )
    ):
        raise RuntimeError("OIDC settings are incomplete")
    assert settings.database_url is not None
    assert settings.oidc_issuer is not None
    assert settings.oidc_audience is not None
    assert settings.oidc_jwks_url is not None
    repository = EnterpriseRepository(
        settings.database_url,
        min_size=settings.database_pool_min_size,
        max_size=settings.database_pool_max_size,
        timeout_seconds=settings.database_pool_timeout_seconds,
    )
    verifier = OidcTokenVerifier(
        issuer=settings.oidc_issuer,
        audience=settings.oidc_audience,
        jwks_url=settings.oidc_jwks_url,
        tenant_claim=settings.oidc_tenant_claim,
        required_acr=settings.oidc_required_acr,
        leeway_seconds=settings.oidc_leeway_seconds,
        timeout_seconds=settings.request_timeout_seconds,
    )
    return EnterpriseServices(verifier=verifier, repository=repository)
