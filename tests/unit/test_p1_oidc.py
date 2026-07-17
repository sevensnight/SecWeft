from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import uuid4

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from vulnlab.enterprise.auth import OidcTokenVerifier
from vulnlab.enterprise.errors import EnterpriseAuthenticationError

ISSUER = "https://identity.example.test/realms/vulnlab"
AUDIENCE = "vulnlab-control-plane"


@pytest.fixture(scope="module")
def signing_keys():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return private_key, private_key.public_key()


def _claims(**overrides):
    now = datetime.now(UTC)
    claims = {
        "iss": ISSUER,
        "sub": "oidc-subject-001",
        "aud": AUDIENCE,
        "iat": now,
        "exp": now + timedelta(minutes=5),
        "tenant_id": str(uuid4()),
        "preferred_username": "p1-user",
        "email": "p1-user@example.test",
    }
    claims.update(overrides)
    return claims


def _verifier(public_key, *, required_acr: str | None = None) -> OidcTokenVerifier:
    return OidcTokenVerifier(
        issuer=ISSUER,
        audience=AUDIENCE,
        jwks_url="https://identity.example.test/jwks",
        required_acr=required_acr,
        signing_key_resolver=lambda _: public_key,
    )


def _token(private_key, claims=None, *, algorithm="RS256") -> str:
    key = private_key if algorithm == "RS256" else "not-a-production-secret-with-32-bytes"
    return jwt.encode(
        claims or _claims(), key, algorithm=algorithm, headers={"kid": "test-signing-key"}
    )


def test_valid_oidc_token_resolves_server_side_identity(signing_keys) -> None:
    private_key, public_key = signing_keys
    tenant_id = uuid4()
    identity = _verifier(public_key).verify(_token(private_key, _claims(tenant_id=str(tenant_id))))

    assert identity.issuer == ISSUER
    assert identity.subject == "oidc-subject-001"
    assert identity.tenant_id == tenant_id
    assert identity.username == "p1-user"


@pytest.mark.parametrize(
    "overrides",
    [
        {"iss": "https://attacker.example.test"},
        {"aud": "wrong-audience"},
        {"exp": datetime.now(UTC) - timedelta(minutes=1)},
        {"iat": datetime.now(UTC) + timedelta(minutes=10)},
        {"tenant_id": "not-a-uuid"},
    ],
)
def test_invalid_claims_fail_with_one_generic_error(signing_keys, overrides) -> None:
    private_key, public_key = signing_keys
    with pytest.raises(EnterpriseAuthenticationError) as captured:
        _verifier(public_key).verify(_token(private_key, _claims(**overrides)))

    assert captured.value.detail == "bearer token is missing or invalid"


def test_missing_required_claim_is_rejected(signing_keys) -> None:
    private_key, public_key = signing_keys
    claims = _claims()
    del claims["aud"]

    with pytest.raises(EnterpriseAuthenticationError):
        _verifier(public_key).verify(_token(private_key, claims))


def test_configured_authentication_context_is_enforced(signing_keys) -> None:
    private_key, public_key = signing_keys
    required_acr = "urn:example:loa:mfa"
    verifier = _verifier(public_key, required_acr=required_acr)

    verifier.verify(_token(private_key, _claims(acr=required_acr)))
    with pytest.raises(EnterpriseAuthenticationError):
        verifier.verify(_token(private_key, _claims()))
    with pytest.raises(EnterpriseAuthenticationError):
        verifier.verify(_token(private_key, _claims(acr="urn:example:loa:password")))


def test_token_selected_algorithm_is_rejected_before_key_resolution(signing_keys) -> None:
    private_key, public_key = signing_keys
    called = False

    def resolver(_: str):
        nonlocal called
        called = True
        return public_key

    verifier = OidcTokenVerifier(
        issuer=ISSUER,
        audience=AUDIENCE,
        jwks_url="https://identity.example.test/jwks",
        signing_key_resolver=resolver,
    )
    with pytest.raises(EnterpriseAuthenticationError):
        verifier.verify(_token(private_key, algorithm="HS256"))

    assert not called


def test_missing_key_id_and_oversized_tokens_are_rejected(signing_keys) -> None:
    private_key, public_key = signing_keys
    verifier = _verifier(public_key)
    token_without_kid = jwt.encode(_claims(), private_key, algorithm="RS256")

    with pytest.raises(EnterpriseAuthenticationError):
        verifier.verify(token_without_kid)
    with pytest.raises(EnterpriseAuthenticationError):
        verifier.verify("a" * 16_385)
