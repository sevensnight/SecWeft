from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def test_gateway_csp_allows_only_the_configured_browser_oidc_origin() -> None:
    caddyfile = (ROOT / "apps/api-gateway/Caddyfile").read_text(encoding="utf-8")

    assert "connect-src 'self' {$VULNLAB_OIDC_BROWSER_ORIGIN:" in caddyfile
    assert "connect-src *" not in caddyfile


def test_compose_passes_browser_oidc_origin_to_gateway() -> None:
    compose = (ROOT / "infrastructure/docker-compose/platform.yml").read_text(encoding="utf-8")
    root_env = (ROOT / ".env.example").read_text(encoding="utf-8")
    compose_env = (ROOT / "infrastructure/docker-compose/.env.platform.example").read_text(
        encoding="utf-8"
    )

    expected = "VULNLAB_OIDC_BROWSER_ORIGIN: ${VULNLAB_OIDC_BROWSER_ORIGIN:-http://127.0.0.1:8081}"
    assert expected in compose
    assert "VULNLAB_OIDC_BROWSER_ORIGIN=http://127.0.0.1:8081" in root_env
    assert "VULNLAB_OIDC_BROWSER_ORIGIN=http://127.0.0.1:8081" in compose_env


def test_start_scripts_reject_oidc_origin_drift_and_non_oidc_identity_mode() -> None:
    scripts = [
        (ROOT / "infrastructure/scripts/common.ps1").read_text(encoding="utf-8"),
        (ROOT / "infrastructure/scripts/common.sh").read_text(encoding="utf-8"),
    ]

    for script in scripts:
        assert "The identity profile requires VULNLAB_AUTH_MODE=oidc" in script
        assert "VULNLAB_OIDC_BROWSER_ORIGIN must match the issuer origin" in script
        assert "VULNLAB_OIDC_BROWSER_ORIGIN must contain only scheme, host" in script


def test_ci_runs_real_p1_postgres_and_keycloak_integrations() -> None:
    workflow = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")

    assert "python tools/p1/validate_enterprise_postgres.py" in workflow
    assert "tests/integration/test_p1_enterprise_api.py" in workflow
    assert "node tools/p1/validate_keycloak_oidc.mjs" in workflow
    assert "quay.io/keycloak/keycloak:26.1.4" in workflow
