from __future__ import annotations

import pytest
from cryptography.fernet import Fernet
from vulnlab.config import Settings


def _clear_p1_environment(monkeypatch) -> None:
    for name in (
        "DATABASE_URL",
        "VULNLAB_AUTH_MODE",
        "VULNLAB_ENV",
        "VULNLAB_MASTER_KEY",
        "VULNLAB_OIDC_ISSUER",
        "VULNLAB_OIDC_AUDIENCE",
        "VULNLAB_OIDC_JWKS_URL",
        "VULNLAB_OIDC_REQUIRED_ACR",
    ):
        monkeypatch.delenv(name, raising=False)


def test_production_fails_closed_without_oidc(monkeypatch) -> None:
    _clear_p1_environment(monkeypatch)
    monkeypatch.setenv("VULNLAB_ENV", "production")
    monkeypatch.setenv("VULNLAB_MASTER_KEY", Fernet.generate_key().decode())

    with pytest.raises(RuntimeError, match="requires VULNLAB_AUTH_MODE=oidc"):
        Settings.from_env()


def test_oidc_mode_requires_database_and_explicit_trust_anchors(monkeypatch) -> None:
    _clear_p1_environment(monkeypatch)
    monkeypatch.setenv("VULNLAB_AUTH_MODE", "oidc")

    with pytest.raises(RuntimeError, match="DATABASE_URL"):
        Settings.from_env()


def test_production_rejects_insecure_oidc_urls(monkeypatch) -> None:
    _clear_p1_environment(monkeypatch)
    monkeypatch.setenv("VULNLAB_ENV", "production")
    monkeypatch.setenv("VULNLAB_AUTH_MODE", "oidc")
    monkeypatch.setenv("VULNLAB_MASTER_KEY", Fernet.generate_key().decode())
    monkeypatch.setenv("DATABASE_URL", "postgresql://app:secret@database/vulnlab")
    monkeypatch.setenv("VULNLAB_OIDC_ISSUER", "http://identity.example.test/realm")
    monkeypatch.setenv("VULNLAB_OIDC_AUDIENCE", "vulnlab-control-plane")
    monkeypatch.setenv("VULNLAB_OIDC_JWKS_URL", "https://identity.example.test/jwks")

    with pytest.raises(RuntimeError, match="absolute https URL"):
        Settings.from_env()


def test_development_oidc_configuration_is_parsed_without_discovery(monkeypatch) -> None:
    _clear_p1_environment(monkeypatch)
    monkeypatch.setenv("VULNLAB_AUTH_MODE", "oidc")
    monkeypatch.setenv("DATABASE_URL", "postgresql://app:secret@database/vulnlab")
    monkeypatch.setenv("VULNLAB_OIDC_ISSUER", "http://127.0.0.1:8081/realms/vulnlab")
    monkeypatch.setenv("VULNLAB_OIDC_AUDIENCE", "vulnlab-control-plane")
    monkeypatch.setenv("VULNLAB_OIDC_REQUIRED_ACR", "urn:example:loa:mfa")
    monkeypatch.setenv(
        "VULNLAB_OIDC_JWKS_URL",
        "http://identity:8080/realms/vulnlab/protocol/openid-connect/certs",
    )

    settings = Settings.from_env()

    assert settings.auth_mode == "oidc"
    assert settings.oidc_audience == "vulnlab-control-plane"
    assert settings.oidc_required_acr == "urn:example:loa:mfa"
    assert settings.database_pool_min_size <= settings.database_pool_max_size
