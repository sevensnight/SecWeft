from __future__ import annotations

import json
from concurrent.futures import ThreadPoolExecutor

import pytest
from vulnlab.context import scrub_secrets
from vulnlab.model_gateway import ModelGateway
from vulnlab.scope import ScopeViolation, parse_target
from vulnlab.security import redact


def test_provider_secret_is_encrypted_and_write_only(client, app, admin_headers):
    secret = "sk-" + "this-is-a-canary-secret-123456"
    response = client.post(
        "/api/v1/providers",
        headers=admin_headers,
        json={
            "name": "private-model",
            "kind": "openai_compatible",
            "base_url": "https://model.example/v1",
            "model": "model-a",
            "api_key": secret,
            "priority": 1,
        },
    )
    assert response.status_code == 201, response.text
    assert secret not in response.text
    row = app.state.services.db.fetch_one(
        "SELECT encrypted_api_key FROM providers WHERE name='private-model'"
    )
    assert row is not None
    assert secret not in row["encrypted_api_key"]
    assert (
        app.state.services.settings.fernet.decrypt(row["encrypted_api_key"].encode()).decode()
        == secret
    )
    assert secret not in json.dumps(client.get("/api/v1/audit", headers=admin_headers).json())


def test_provider_endpoint_blocks_metadata_and_plaintext_public_http(client, admin_headers):
    metadata = client.post(
        "/api/v1/providers",
        headers=admin_headers,
        json={
            "name": "metadata",
            "kind": "openai_compatible",
            "base_url": "http://169.254.169.254/latest",
            "model": "x",
            "config": {"allow_insecure_http": True, "allow_private_endpoint": True},
        },
    )
    assert metadata.status_code == 422
    plaintext = client.post(
        "/api/v1/providers",
        headers=admin_headers,
        json={
            "name": "plaintext",
            "kind": "openai_compatible",
            "base_url": "http://example.com/v1",
            "model": "x",
        },
    )
    assert plaintext.status_code == 422


@pytest.mark.parametrize(
    "value",
    [
        "Authorization: Bearer top-secret-token-value",
        "api_key=canary-value",
        "https://example.invalid/?token=canary-value",
        "sk-" + "canarycanarycanary12345",
    ],
)
def test_recursive_redaction_catches_secrets_in_values(value):
    cleaned = json.dumps(redact({"message": value, "nested": [value]}))
    assert "canary-value" not in cleaned
    assert "top-secret-token-value" not in cleaned
    assert "sk-canary" not in cleaned
    assert "REDACTED" in cleaned


def test_context_secret_scrubber():
    value = "api_key=abc123 Authorization: Bearer xyz987 sk-abcdefghijklmnop"
    cleaned = scrub_secrets(value)
    assert "abc123" not in cleaned
    assert "xyz987" not in cleaned
    assert "sk-abc" not in cleaned


def test_model_gateway_scrubs_direct_prompt_secrets_before_provider(
    app, admin_headers, monkeypatch
):
    captured = {}

    async def fake_invoke(row, messages, max_tokens):
        captured["messages"] = messages
        return "safe response"

    gateway: ModelGateway = app.state.services.gateway
    monkeypatch.setattr(gateway, "_invoke", fake_invoke)
    principal = app.state.services.security.authenticate(admin_headers["X-API-Key"])

    import asyncio

    result = asyncio.run(
        gateway.complete(
            principal,
            [{"role": "user", "content": "Authorization: Bearer prompt-canary-token"}],
            "summarization",
            64,
        )
    )
    assert result["content"] == "safe response"
    assert "prompt-canary-token" not in json.dumps(captured["messages"])
    assert "[REDACTED]" in json.dumps(captured["messages"])


def test_audit_hash_chain_detects_tampering(client, app, admin_headers):
    client.get("/api/v1/providers", headers=admin_headers)
    valid = client.get("/api/v1/audit/verify", headers=admin_headers).json()
    assert valid["valid"] is True
    row = app.state.services.db.fetch_one("SELECT id FROM audit_logs ORDER BY id LIMIT 1")
    assert row is not None
    app.state.services.db.execute(
        "UPDATE audit_logs SET action='tampered' WHERE id=?", (row["id"],)
    )
    invalid = client.get("/api/v1/audit/verify", headers=admin_headers).json()
    assert invalid["valid"] is False
    assert invalid["first_invalid_id"] == row["id"]
    blocked = client.post(
        "/api/v1/users",
        headers=admin_headers,
        json={"username": "must-not-write", "role": "viewer"},
    )
    assert blocked.status_code == 503
    assert blocked.json()["code"] == "audit_integrity_failed"


def test_audit_head_detects_tail_deletion(client, app, admin_headers):
    client.post(
        "/api/v1/users", headers=admin_headers, json={"username": "audit-tail", "role": "viewer"}
    )
    last = app.state.services.db.fetch_one("SELECT id FROM audit_logs ORDER BY id DESC LIMIT 1")
    assert last is not None
    app.state.services.db.execute("DELETE FROM audit_logs WHERE id=?", (last["id"],))
    result = client.get("/api/v1/audit/verify", headers=admin_headers).json()
    assert result["valid"] is False
    with pytest.raises(RuntimeError, match="audit tail"):
        app.state.services.audit.record("system", "must.fail", "audit", "tail")


def test_concurrent_audit_appends_preserve_chain(app):
    audit = app.state.services.audit

    def append(index: int) -> int:
        return audit.record(
            "system", "concurrency.test", "item", str(index), details={"index": index}
        )

    with ThreadPoolExecutor(max_workers=8) as pool:
        ids = list(pool.map(append, range(40)))
    assert len(ids) == len(set(ids)) == 40
    verified = audit.verify()
    assert verified["valid"] is True
    assert verified["entries"] == 41  # one initialization event plus 40 test events


@pytest.mark.parametrize(
    "target",
    [
        "file:///etc/passwd",
        "http://user:pass@localhost",
        "ftp://localhost/a",
        "http://[fe80::1%25eth0]/",
    ],
)
def test_ambiguous_or_unsafe_targets_are_rejected(target):
    with pytest.raises(ScopeViolation):
        parse_target(target)


def test_task_context_checkpoint_preserves_security_envelope(
    client, admin_headers, analyst, pending_task
):
    _, analyst_headers = analyst
    added = client.post(
        f"/api/v1/tasks/{pending_task['id']}/context",
        headers=analyst_headers,
        json={
            "role": "user",
            "content": "token=very-secret-value remember scope",
            "visibility": "task",
        },
    )
    assert added.status_code == 201
    assert "very-secret-value" not in added.text
    checkpoint = client.post(
        f"/api/v1/tasks/{pending_task['id']}/checkpoints", headers=analyst_headers
    )
    assert checkpoint.status_code == 201
    body = checkpoint.json()
    assert body["state"]["security_envelope"]["scope_id"] == pending_task["scope_id"]
    assert body["state"]["security_envelope"]["approval_status"] == "pending"
    assert "revalidated" in body["state"]["security_envelope"]["policy"]


def test_context_restore_rechecks_current_scope_and_cannot_restore_revoked_authority(
    client, admin_headers, analyst, approved_scope, pending_task
):
    _, analyst_headers = analyst
    checkpoint = client.post(
        f"/api/v1/tasks/{pending_task['id']}/checkpoints", headers=analyst_headers
    )
    assert checkpoint.status_code == 201
    revoke = client.post(
        f"/api/v1/scopes/{approved_scope['id']}/approve",
        headers=admin_headers,
        json={"approved": False, "reason": "authorization withdrawn"},
    )
    assert revoke.status_code == 200
    restored = client.post(
        f"/api/v1/tasks/{pending_task['id']}/context/restore", headers=analyst_headers
    )
    assert restored.status_code == 200
    envelope = restored.json()["current_security_envelope"]
    assert envelope["scope_valid"] is False
    assert envelope["execution_authorized"] is False
    assert "never restores authority" in envelope["policy"]


def test_sandbox_is_not_a_generic_shell(client, admin_headers):
    denied = client.post(
        "/api/v1/sandbox/runs",
        headers=admin_headers,
        json={"argv": ["sh", "-c", "id"]},
    )
    assert denied.status_code == 422
    denied_meta = client.post(
        "/api/v1/sandbox/runs",
        headers=admin_headers,
        json={"argv": ["python", "-c", "print('x')"]},
    )
    assert denied_meta.status_code == 422
    allowed = client.post(
        "/api/v1/sandbox/runs",
        headers=admin_headers,
        json={"argv": ["python", "--version"]},
    )
    assert allowed.status_code == 201
    assert allowed.json()["status"] == "dry_run"
