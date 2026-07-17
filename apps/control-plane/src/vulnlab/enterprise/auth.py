from __future__ import annotations

from collections.abc import Callable
from typing import Any
from uuid import UUID

import jwt

from .errors import EnterpriseAuthenticationError
from .models import OidcIdentity

SigningKeyResolver = Callable[[str], Any]


class OidcTokenVerifier:
    """Verify OIDC access tokens without trusting token-selected algorithms or scope claims."""

    _ALGORITHMS = ("RS256",)
    _MAX_TOKEN_LENGTH = 16_384

    def __init__(
        self,
        *,
        issuer: str,
        audience: str,
        jwks_url: str,
        tenant_claim: str = "tenant_id",
        required_acr: str | None = None,
        leeway_seconds: int = 30,
        timeout_seconds: float = 8.0,
        signing_key_resolver: SigningKeyResolver | None = None,
    ) -> None:
        self.issuer = issuer
        self.audience = audience
        self.tenant_claim = tenant_claim
        self.required_acr = required_acr
        self.leeway_seconds = leeway_seconds
        self._jwks_client: jwt.PyJWKClient | None = None
        self._resolve_signing_key: SigningKeyResolver
        if signing_key_resolver is None:
            self._jwks_client = jwt.PyJWKClient(
                jwks_url,
                cache_keys=True,
                max_cached_keys=32,
                cache_jwk_set=True,
                lifespan=300,
                timeout=timeout_seconds,
            )
            self._resolve_signing_key = self._resolve_from_jwks
        else:
            self._resolve_signing_key = signing_key_resolver

    def _resolve_from_jwks(self, token: str) -> Any:
        if self._jwks_client is None:  # pragma: no cover - constructor invariant
            raise EnterpriseAuthenticationError()
        return self._jwks_client.get_signing_key_from_jwt(token).key

    def verify(self, token: str) -> OidcIdentity:
        if (
            not token
            or len(token) > self._MAX_TOKEN_LENGTH
            or any(char.isspace() for char in token)
        ):
            raise EnterpriseAuthenticationError()
        try:
            header = jwt.get_unverified_header(token)
            if header.get("alg") not in self._ALGORITHMS:
                raise EnterpriseAuthenticationError()
            if not isinstance(header.get("kid"), str) or not header["kid"]:
                raise EnterpriseAuthenticationError()
            signing_key = self._resolve_signing_key(token)
            claims = jwt.decode(
                token,
                signing_key,
                algorithms=list(self._ALGORITHMS),
                audience=self.audience,
                issuer=self.issuer,
                leeway=self.leeway_seconds,
                options={
                    "require": ["exp", "iat", "iss", "sub", "aud"],
                    "verify_signature": True,
                    "verify_exp": True,
                    "verify_iat": True,
                    "verify_nbf": True,
                    "verify_aud": True,
                    "verify_iss": True,
                },
            )
            subject = claims.get("sub")
            if not isinstance(subject, str) or not 1 <= len(subject) <= 255:
                raise EnterpriseAuthenticationError()
            tenant_value = claims.get(self.tenant_claim)
            if not isinstance(tenant_value, str):
                raise EnterpriseAuthenticationError()
            tenant_id = UUID(tenant_value)
            username_value = claims.get("preferred_username", subject)
            if not isinstance(username_value, str) or not 1 <= len(username_value) <= 128:
                raise EnterpriseAuthenticationError()
            email_value = claims.get("email")
            if email_value is not None and (
                not isinstance(email_value, str) or len(email_value) > 320
            ):
                raise EnterpriseAuthenticationError()
            if self.required_acr is not None and claims.get("acr") != self.required_acr:
                raise EnterpriseAuthenticationError()
        except EnterpriseAuthenticationError:
            raise
        except (jwt.PyJWTError, TypeError, ValueError, KeyError) as exc:
            raise EnterpriseAuthenticationError() from exc
        except Exception as exc:
            # JWKS network, parsing, and key-selection errors are deliberately indistinguishable.
            raise EnterpriseAuthenticationError() from exc
        return OidcIdentity(
            issuer=self.issuer,
            subject=subject,
            tenant_id=tenant_id,
            username=username_value,
            email=email_value,
        )
