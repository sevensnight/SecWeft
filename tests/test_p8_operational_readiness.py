from __future__ import annotations

from tools.p8 import operational_readiness, perf_smoke


def test_p8_operational_readiness_static_checks_pass() -> None:
    result = operational_readiness.run()
    assert result["valid"], result
    assert result["checks"]["compose"]["invariants"]["app_services_are_read_only"] is True
    assert result["checks"]["helm"]["invariants"]["network_policy_enabled_by_default"] is True
    assert result["checks"]["secrets"]["invariants"]["local_env_is_not_git_tracked"] is True


def test_p8_perf_smoke_exercises_asgi_without_external_network() -> None:
    result = perf_smoke.run(requests=8, concurrency=4, p95_budget_ms=1000)
    assert result["valid"], result
    assert result["metrics"]["requests"] == 8
    assert result["metrics"]["concurrency"] == 4
