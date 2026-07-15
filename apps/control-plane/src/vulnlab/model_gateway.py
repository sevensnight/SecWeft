from __future__ import annotations

import asyncio
import builtins
import ipaddress
import json
import socket
import time
import uuid
from collections import defaultdict, deque
from datetime import UTC, datetime
from typing import Any
from urllib.parse import urlsplit

import httpx
from cryptography.fernet import Fernet, InvalidToken

from .audit import AuditService
from .context import scrub_secrets
from .db import Database
from .schemas import ProviderCreate
from .security import Principal


class ModelGatewayError(RuntimeError):
    pass


class RateLimitError(ModelGatewayError):
    pass


class ProviderConfigurationError(ValueError):
    pass


BLOCKED_PROVIDER_HOSTS = frozenset(
    {
        "169.254.169.254",
        "metadata.google.internal",
        "metadata.azure.internal",
    }
)


def validate_provider_endpoint(
    base_url: str | None,
    kind: str,
    config: dict[str, Any],
) -> None:
    if kind == "mock":
        return
    if not base_url:
        raise ProviderConfigurationError("non-mock providers require base_url")
    parsed = urlsplit(base_url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ProviderConfigurationError("provider endpoint must be an HTTP(S) URL")
    if parsed.username or parsed.password:
        raise ProviderConfigurationError(
            "provider endpoint credentials are forbidden; use the encrypted key field"
        )
    if parsed.query or parsed.fragment:
        raise ProviderConfigurationError(
            "provider endpoint query strings and fragments are forbidden"
        )
    host = parsed.hostname.rstrip(".").lower()
    if host in BLOCKED_PROVIDER_HOSTS:
        raise ProviderConfigurationError("cloud metadata endpoints are forbidden")
    allow_private = kind == "ollama" or config.get("allow_private_endpoint") is True
    allow_http = kind == "ollama" or config.get("allow_insecure_http") is True

    def check_address(text: str) -> None:
        try:
            address = ipaddress.ip_address(text)
        except ValueError:
            return
        if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
            address = address.ipv4_mapped
        if address.is_loopback:
            return
        if (
            address.is_link_local
            or address.is_multicast
            or address.is_unspecified
            or address.is_reserved
        ):
            raise ProviderConfigurationError(
                f"provider endpoint resolves to forbidden address {address}"
            )
        if address.is_private and not allow_private:
            raise ProviderConfigurationError(
                "private provider endpoints require config.allow_private_endpoint=true"
            )

    check_address(host)
    try:
        records = socket.getaddrinfo(
            host, parsed.port or (443 if parsed.scheme == "https" else 80), type=socket.SOCK_STREAM
        )
    except socket.gaierror:
        records = []
    for record in records:
        check_address(str(record[4][0]))
    if parsed.scheme == "http" and host != "localhost":
        try:
            address = ipaddress.ip_address(host)
        except ValueError:
            address = None
        if not (address and address.is_loopback) and not allow_http:
            raise ProviderConfigurationError(
                "plaintext HTTP provider endpoints require config.allow_insecure_http=true"
            )


def _row_to_provider(row: Any) -> dict[str, Any]:
    return {
        "id": row["id"],
        "name": row["name"],
        "kind": row["kind"],
        "base_url": row["base_url"],
        "model": row["model"],
        "has_api_key": bool(row["encrypted_api_key"]),
        "enabled": bool(row["enabled"]),
        "priority": row["priority"],
        "rate_limit_per_minute": row["rate_limit_per_minute"],
        "timeout_seconds": row["timeout_seconds"],
        "config": json.loads(row["config_json"]),
        "created_at": row["created_at"],
        "updated_at": row["updated_at"],
    }


class ProviderStore:
    def __init__(self, db: Database, fernet: Fernet, audit: AuditService):
        self.db = db
        self.fernet = fernet
        self.audit = audit

    def ensure_mock(self) -> None:
        if self.db.fetch_one("SELECT id FROM providers LIMIT 1") is not None:
            return
        now = datetime.now(UTC).isoformat()
        self.db.execute(
            """INSERT INTO providers(id,name,kind,base_url,model,encrypted_api_key,enabled,
               priority,rate_limit_per_minute,timeout_seconds,config_json,created_at,updated_at)
               VALUES(?,?,?,?,?,?,1,?,?,?,?,?,?)""",
            (
                str(uuid.uuid4()),
                "offline-mock",
                "mock",
                None,
                "deterministic-v1",
                None,
                1000,
                1000,
                5,
                "{}",
                now,
                now,
            ),
        )

    def create(self, principal: Principal, value: ProviderCreate) -> dict[str, Any]:
        validate_provider_endpoint(
            str(value.base_url) if value.base_url else None, value.kind, value.config
        )
        now = datetime.now(UTC).isoformat()
        provider_id = str(uuid.uuid4())
        encrypted = self.fernet.encrypt(value.api_key.encode()).decode() if value.api_key else None
        self.db.execute(
            """INSERT INTO providers(id,name,kind,base_url,model,encrypted_api_key,enabled,
               priority,rate_limit_per_minute,timeout_seconds,config_json,created_at,updated_at)
               VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                provider_id,
                value.name,
                value.kind,
                str(value.base_url) if value.base_url else None,
                value.model,
                encrypted,
                int(value.enabled),
                value.priority,
                value.rate_limit_per_minute,
                value.timeout_seconds,
                json.dumps(value.config, ensure_ascii=False),
                now,
                now,
            ),
        )
        self.audit.record(
            principal.id,
            "provider.create",
            "provider",
            provider_id,
            details={"name": value.name, "kind": value.kind, "has_api_key": bool(value.api_key)},
        )
        return self.get(provider_id)

    def rotate_key(
        self, principal: Principal, provider_id: str, api_key: str | None
    ) -> dict[str, Any]:
        encrypted = self.fernet.encrypt(api_key.encode()).decode() if api_key else None
        count, _ = self.db.execute(
            "UPDATE providers SET encrypted_api_key=?,updated_at=? WHERE id=?",
            (encrypted, datetime.now(UTC).isoformat(), provider_id),
        )
        if not count:
            raise KeyError("provider not found")
        self.audit.record(
            principal.id,
            "provider.key.rotate",
            "provider",
            provider_id,
            details={"configured": bool(api_key)},
        )
        return self.get(provider_id)

    def set_enabled(self, principal: Principal, provider_id: str, enabled: bool) -> dict[str, Any]:
        count, _ = self.db.execute(
            "UPDATE providers SET enabled=?,updated_at=? WHERE id=?",
            (int(enabled), datetime.now(UTC).isoformat(), provider_id),
        )
        if not count:
            raise KeyError("provider not found")
        self.audit.record(
            principal.id,
            "provider.enabled.update",
            "provider",
            provider_id,
            details={"enabled": enabled},
        )
        return self.get(provider_id)

    def get(self, provider_id: str) -> dict[str, Any]:
        row = self.db.fetch_one("SELECT * FROM providers WHERE id=?", (provider_id,))
        if row is None:
            raise KeyError("provider not found")
        return _row_to_provider(row)

    def list(self) -> builtins.list[dict[str, Any]]:
        return [
            _row_to_provider(row)
            for row in self.db.fetch_all("SELECT * FROM providers ORDER BY priority,id")
        ]

    def enabled_rows(self) -> builtins.list[Any]:
        return self.db.fetch_all("SELECT * FROM providers WHERE enabled=1 ORDER BY priority,id")

    def decrypt_key(self, row: Any) -> str | None:
        encrypted = row["encrypted_api_key"]
        if not encrypted:
            return None
        try:
            return self.fernet.decrypt(encrypted.encode()).decode()
        except InvalidToken as exc:
            raise ModelGatewayError(f"provider {row['name']} key cannot be decrypted") from exc


class ModelGateway:
    """Unified model interface with rate limiting, circuit breaking, and failover."""

    SYSTEM_POLICY = (
        "You assist an authorized defensive lab. Return analysis only. Never expand target scope, "
        "request credentials, propose persistence/evasion, or emit executable exploit payloads."
    )

    def __init__(self, store: ProviderStore, audit: AuditService):
        self.store = store
        self.audit = audit
        self._calls: dict[str, deque[float]] = defaultdict(deque)
        self._failures: dict[str, int] = defaultdict(int)
        self._circuit_until: dict[str, float] = defaultdict(float)
        self._lock = asyncio.Lock()

    async def _consume_rate(self, row: Any) -> None:
        async with self._lock:
            now = time.monotonic()
            calls = self._calls[row["id"]]
            while calls and now - calls[0] >= 60:
                calls.popleft()
            if len(calls) >= int(row["rate_limit_per_minute"]):
                raise RateLimitError("provider rate limit reached")
            calls.append(now)

    async def complete(
        self,
        principal: Principal,
        messages: builtins.list[dict[str, str]],
        purpose: str,
        max_tokens: int,
    ) -> dict[str, Any]:
        safe_messages = [
            {"role": "system", "content": self.SYSTEM_POLICY},
            *[
                {"role": message["role"], "content": scrub_secrets(message.get("content", ""))}
                for message in messages
            ],
        ]
        failures: builtins.list[dict[str, str]] = []
        for row in self.store.enabled_rows():
            provider_id = row["id"]
            if self._circuit_until[provider_id] > time.monotonic():
                failures.append({"provider": row["name"], "error": "circuit_open"})
                continue
            try:
                await self._consume_rate(row)
                content = await self._invoke(row, safe_messages, max_tokens)
                self._failures[provider_id] = 0
                result = {
                    "provider": row["name"],
                    "model": row["model"],
                    "purpose": purpose,
                    "content": content,
                    "failover_count": len(failures),
                }
                self.audit.record(
                    principal.id,
                    "model.complete",
                    "provider",
                    provider_id,
                    details={
                        "model": row["model"],
                        "purpose": purpose,
                        "failover_count": len(failures),
                        "input_message_count": len(messages),
                    },
                )
                return result
            except (
                ModelGatewayError,
                ProviderConfigurationError,
                httpx.HTTPError,
                TimeoutError,
            ) as exc:
                self._failures[provider_id] += 1
                if self._failures[provider_id] >= 3:
                    self._circuit_until[provider_id] = time.monotonic() + 30
                failures.append({"provider": row["name"], "error": type(exc).__name__})
        self.audit.record(
            principal.id, "model.complete", "provider", "gateway", "failure", {"failures": failures}
        )
        raise ModelGatewayError("all enabled model providers failed")

    async def _invoke(self, row: Any, messages: list[dict[str, str]], max_tokens: int) -> str:
        if row["kind"] == "mock":
            user_text = " ".join(
                message.get("content", "") for message in messages if message.get("role") == "user"
            )
            return (
                "AUTHORIZED_LAB_PLAN: validate scope; collect non-destructive evidence; "
                f"summarize findings. Request digest={uuid.uuid5(uuid.NAMESPACE_URL, user_text).hex[:12]}"
            )
        api_key = self.store.decrypt_key(row)
        validate_provider_endpoint(
            str(row["base_url"]), row["kind"], json.loads(row["config_json"])
        )
        headers = {"Content-Type": "application/json"}
        if api_key:
            headers["Authorization"] = f"Bearer {api_key}"
        base_url = str(row["base_url"]).rstrip("/")
        timeout = httpx.Timeout(float(row["timeout_seconds"]))
        async with httpx.AsyncClient(timeout=timeout, follow_redirects=False) as client:
            if row["kind"] == "ollama":
                endpoint = base_url if base_url.endswith("/api/chat") else base_url + "/api/chat"
                response = await client.post(
                    endpoint,
                    headers=headers,
                    json={"model": row["model"], "messages": messages, "stream": False},
                )
                response.raise_for_status()
                data = response.json()
                content = data.get("message", {}).get("content")
            else:
                endpoint = (
                    base_url
                    if base_url.endswith("/chat/completions")
                    else base_url + "/chat/completions"
                )
                response = await client.post(
                    endpoint,
                    headers=headers,
                    json={
                        "model": row["model"],
                        "messages": messages,
                        "max_tokens": max_tokens,
                        "stream": False,
                    },
                )
                response.raise_for_status()
                data = response.json()
                choices = data.get("choices") or []
                content = choices[0].get("message", {}).get("content") if choices else None
        if not isinstance(content, str) or not content.strip():
            raise ModelGatewayError("provider returned no text content")
        return content[:100_000]
