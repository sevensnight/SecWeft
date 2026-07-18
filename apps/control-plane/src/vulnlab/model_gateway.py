from __future__ import annotations

import asyncio
import builtins
import hashlib
import ipaddress
import json
import socket
import time
import uuid
from collections import defaultdict, deque
from datetime import UTC, datetime, timedelta
from typing import Any
from urllib.parse import urlsplit

import httpx
from cryptography.fernet import Fernet, InvalidToken

from .audit import AuditService
from .context import scrub_secrets
from .repository import ControlPlaneRepository
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
    has_api_key = bool(row["encrypted_api_key"])
    return {
        "id": row["id"],
        "name": row["name"],
        "kind": row["kind"],
        "base_url": row["base_url"],
        "model": row["model"],
        "has_api_key": has_api_key,
        "credential_ref": f"credential://provider/{row['id']}/api-key" if has_api_key else None,
        "enabled": bool(row["enabled"]),
        "priority": row["priority"],
        "rate_limit_per_minute": row["rate_limit_per_minute"],
        "token_quota_per_minute": row["token_quota_per_minute"],
        "timeout_seconds": row["timeout_seconds"],
        "input_cost_per_1k": row["input_cost_per_1k"],
        "output_cost_per_1k": row["output_cost_per_1k"],
        "capabilities": json.loads(row["capabilities_json"]),
        "config": json.loads(row["config_json"]),
        "created_at": row["created_at"],
        "updated_at": row["updated_at"],
    }


class ProviderStore:
    def __init__(self, db: ControlPlaneRepository, fernet: Fernet, audit: AuditService):
        self.db = db
        self.fernet = fernet
        self.audit = audit

    def ensure_mock(self) -> None:
        if self.db.fetch_one("SELECT id FROM providers LIMIT 1") is not None:
            return
        now = datetime.now(UTC).isoformat()
        self.db.execute(
            """INSERT INTO providers(id,name,kind,base_url,model,encrypted_api_key,enabled,
               priority,rate_limit_per_minute,token_quota_per_minute,timeout_seconds,
               input_cost_per_1k,output_cost_per_1k,capabilities_json,config_json,created_at,updated_at)
               VALUES(?,?,?,?,?,?,1,?,?,?,?,?,?,?,?,?,?)""",
            (
                str(uuid.uuid4()),
                "offline-mock",
                "mock",
                None,
                "deterministic-v1",
                None,
                1000,
                1000,
                1_000_000,
                5,
                0.0,
                0.0,
                json.dumps(["text", "json_object", "tool_protocol"]),
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
               priority,rate_limit_per_minute,token_quota_per_minute,timeout_seconds,
               input_cost_per_1k,output_cost_per_1k,capabilities_json,config_json,created_at,updated_at)
               VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
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
                value.token_quota_per_minute,
                value.timeout_seconds,
                value.input_cost_per_1k,
                value.output_cost_per_1k,
                json.dumps(value.capabilities, ensure_ascii=False),
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

    def catalog(self) -> builtins.list[dict[str, Any]]:
        return [
            {
                "provider_id": provider["id"],
                "provider": provider["name"],
                "kind": provider["kind"],
                "model": provider["model"],
                "enabled": provider["enabled"],
                "priority": provider["priority"],
                "capabilities": provider["capabilities"],
                "input_cost_per_1k": provider["input_cost_per_1k"],
                "output_cost_per_1k": provider["output_cost_per_1k"],
            }
            for provider in self.store.list()
        ]

    def health(self) -> builtins.list[dict[str, Any]]:
        now = time.monotonic()
        result: builtins.list[dict[str, Any]] = []
        for provider in self.store.list():
            provider_id = provider["id"]
            circuit_until = self._circuit_until[provider_id]
            result.append(
                {
                    "provider_id": provider_id,
                    "provider": provider["name"],
                    "model": provider["model"],
                    "enabled": provider["enabled"],
                    "status": "circuit_open"
                    if circuit_until > now
                    else "disabled"
                    if not provider["enabled"]
                    else "ready",
                    "failure_count": self._failures[provider_id],
                    "circuit_open": circuit_until > now,
                    "circuit_retry_after_ms": max(0, int((circuit_until - now) * 1000)),
                    "recent_request_count": len(self._calls[provider_id]),
                }
            )
        return result

    def invocations(self, principal: Principal, limit: int = 100) -> builtins.list[dict[str, Any]]:
        limit = max(1, min(limit, 500))
        rows = self.store.db.fetch_all(
            """SELECT id,provider_name,model,purpose,status,prompt_tokens,completion_tokens,
               total_tokens,cost_usd,failover_count,structured_output,tool_count,latency_ms,
               error,created_at
               FROM model_invocations
               WHERE actor_id=?
               ORDER BY created_at DESC,id DESC
               LIMIT ?""",
            (principal.id, limit),
        )
        return [
            {
                "id": row["id"],
                "provider": row["provider_name"],
                "model": row["model"],
                "purpose": row["purpose"],
                "status": row["status"],
                "usage": {
                    "prompt_tokens": row["prompt_tokens"],
                    "completion_tokens": row["completion_tokens"],
                    "total_tokens": row["total_tokens"],
                },
                "cost_usd": row["cost_usd"],
                "failover_count": row["failover_count"],
                "structured_output": bool(row["structured_output"]),
                "tool_count": row["tool_count"],
                "latency_ms": row["latency_ms"],
                "error": row["error"],
                "created_at": row["created_at"],
            }
            for row in rows
        ]

    @staticmethod
    def _estimate_tokens(messages: builtins.list[dict[str, str]], max_tokens: int = 0) -> int:
        text = "\n".join(message.get("content", "") for message in messages)
        return max(1, len(text) // 4) + max_tokens

    @staticmethod
    def _request_hash(messages: builtins.list[dict[str, str]], purpose: str) -> str:
        payload = json.dumps(
            {"messages": messages, "purpose": purpose},
            sort_keys=True,
            separators=(",", ":"),
        )
        return hashlib.sha256(payload.encode()).hexdigest()

    @staticmethod
    def _provider_config(row: Any) -> dict[str, Any]:
        value = json.loads(row["config_json"])
        return value if isinstance(value, dict) else {}

    @staticmethod
    def _provider_retry_budget(row: Any) -> int:
        configured = ModelGateway._provider_config(row).get("max_retries", 1)
        return max(0, min(int(configured), 3)) if isinstance(configured, int) else 1

    @staticmethod
    def _cost(row: Any, prompt_tokens: int, completion_tokens: int) -> float:
        input_cost = (prompt_tokens / 1000) * float(row["input_cost_per_1k"])
        output_cost = (completion_tokens / 1000) * float(row["output_cost_per_1k"])
        return round(input_cost + output_cost, 8)

    def _record_invocation(
        self,
        *,
        principal: Principal,
        row: Any | None,
        provider_name: str,
        model: str,
        purpose: str,
        request_hash: str,
        status: str,
        prompt_tokens: int,
        completion_tokens: int,
        cost_usd: float,
        failover_count: int,
        structured_output: bool,
        tool_count: int,
        latency_ms: int,
        error: str | None = None,
    ) -> str:
        invocation_id = str(uuid.uuid4())
        self.store.db.execute(
            """INSERT INTO model_invocations(
               id,actor_id,provider_id,provider_name,model,purpose,request_hash,status,
               prompt_tokens,completion_tokens,total_tokens,cost_usd,failover_count,
               structured_output,tool_count,latency_ms,error,created_at)
               VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                invocation_id,
                principal.id,
                row["id"] if row is not None else None,
                provider_name,
                model,
                purpose,
                request_hash,
                status,
                prompt_tokens,
                completion_tokens,
                prompt_tokens + completion_tokens,
                cost_usd,
                failover_count,
                int(structured_output),
                tool_count,
                latency_ms,
                error,
                datetime.now(UTC).isoformat(),
            ),
        )
        return invocation_id

    async def _consume_rate(self, row: Any) -> None:
        async with self._lock:
            now = time.monotonic()
            calls = self._calls[row["id"]]
            while calls and now - calls[0] >= 60:
                calls.popleft()
            if len(calls) >= int(row["rate_limit_per_minute"]):
                raise RateLimitError("provider rate limit reached")
            calls.append(now)

    async def _consume_token_quota(
        self, principal: Principal, row: Any, estimated_total_tokens: int
    ) -> None:
        quota = int(row["token_quota_per_minute"])
        since = (datetime.now(UTC) - timedelta(seconds=60)).isoformat()
        used = self.store.db.fetch_one(
            """SELECT COALESCE(SUM(total_tokens),0) AS total
               FROM model_invocations
               WHERE actor_id=? AND provider_id=? AND status='succeeded' AND created_at>=?""",
            (principal.id, row["id"], since),
        )
        used_tokens = int(used["total"] if used is not None else 0)
        if used_tokens + estimated_total_tokens > quota:
            raise RateLimitError("provider token quota reached")

    async def complete(
        self,
        principal: Principal,
        messages: builtins.list[dict[str, str]],
        purpose: str,
        max_tokens: int,
        response_format: str = "text",
        tools: builtins.list[dict[str, Any]] | None = None,
    ) -> dict[str, Any]:
        tools = tools or []
        safe_messages = [
            {"role": "system", "content": self.SYSTEM_POLICY},
            *[
                {"role": message["role"], "content": scrub_secrets(message.get("content", ""))}
                for message in messages
            ],
        ]
        prompt_tokens = self._estimate_tokens(safe_messages)
        estimated_total_tokens = prompt_tokens + max_tokens
        request_hash = self._request_hash(safe_messages, purpose)
        structured_output = response_format == "json_object"
        tool_names = [tool["name"] for tool in tools]
        failures: builtins.list[dict[str, str]] = []
        for row in self.store.enabled_rows():
            provider_id = row["id"]
            if self._circuit_until[provider_id] > time.monotonic():
                failures.append({"provider": row["name"], "error": "circuit_open"})
                continue
            provider_started = time.perf_counter()
            provider_errors: builtins.list[str] = []
            try:
                await self._consume_token_quota(principal, row, estimated_total_tokens)
            except RateLimitError as exc:
                provider_errors.append(type(exc).__name__)
            else:
                for _ in range(self._provider_retry_budget(row) + 1):
                    try:
                        await self._consume_rate(row)
                        content = await self._invoke(
                            row, safe_messages, max_tokens, response_format, tools
                        )
                        if structured_output:
                            try:
                                parsed = json.loads(content)
                            except json.JSONDecodeError as exc:
                                raise ModelGatewayError(
                                    "provider returned invalid JSON for structured output"
                                ) from exc
                            if not isinstance(parsed, dict):
                                raise ModelGatewayError(
                                    "provider returned non-object JSON for structured output"
                                )
                        completion_tokens = self._estimate_tokens(
                            [{"role": "assistant", "content": content}]
                        )
                        cost_usd = self._cost(row, prompt_tokens, completion_tokens)
                        latency_ms = int((time.perf_counter() - provider_started) * 1000)
                        invocation_id = self._record_invocation(
                            principal=principal,
                            row=row,
                            provider_name=row["name"],
                            model=row["model"],
                            purpose=purpose,
                            request_hash=request_hash,
                            status="succeeded",
                            prompt_tokens=prompt_tokens,
                            completion_tokens=completion_tokens,
                            cost_usd=cost_usd,
                            failover_count=len(failures),
                            structured_output=structured_output,
                            tool_count=len(tools),
                            latency_ms=latency_ms,
                        )
                        self._failures[provider_id] = 0
                        result = {
                            "id": invocation_id,
                            "provider": row["name"],
                            "model": row["model"],
                            "purpose": purpose,
                            "content": content,
                            "response_format": response_format,
                            "tool_protocol": {
                                "allowed_tools": tool_names,
                                "tool_calls": [],
                            },
                            "usage": {
                                "prompt_tokens": prompt_tokens,
                                "completion_tokens": completion_tokens,
                                "total_tokens": prompt_tokens + completion_tokens,
                            },
                            "cost_usd": cost_usd,
                            "failover_count": len(failures),
                            "latency_ms": latency_ms,
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
                                "usage": result["usage"],
                                "cost_usd": cost_usd,
                                "tool_count": len(tools),
                                "structured_output": structured_output,
                            },
                        )
                        return result
                    except (
                        ModelGatewayError,
                        ProviderConfigurationError,
                        httpx.HTTPError,
                        TimeoutError,
                    ) as exc:
                        provider_errors.append(type(exc).__name__)
                        continue
            self._failures[provider_id] += 1
            if self._failures[provider_id] >= 3:
                self._circuit_until[provider_id] = time.monotonic() + 30
            last_error = provider_errors[-1] if provider_errors else "provider_failed"
            failures.append({"provider": row["name"], "error": last_error})
            self._record_invocation(
                principal=principal,
                row=row,
                provider_name=row["name"],
                model=row["model"],
                purpose=purpose,
                request_hash=request_hash,
                status="failed",
                prompt_tokens=prompt_tokens,
                completion_tokens=0,
                cost_usd=0.0,
                failover_count=len(failures) - 1,
                structured_output=structured_output,
                tool_count=len(tools),
                latency_ms=int((time.perf_counter() - provider_started) * 1000),
                error=last_error,
            )
        self.audit.record(
            principal.id, "model.complete", "provider", "gateway", "failure", {"failures": failures}
        )
        if failures and all(item["error"] == "RateLimitError" for item in failures):
            raise RateLimitError("all enabled model providers are rate limited")
        raise ModelGatewayError("all enabled model providers failed")

    async def _invoke(
        self,
        row: Any,
        messages: list[dict[str, str]],
        max_tokens: int,
        response_format: str,
        tools: builtins.list[dict[str, Any]],
    ) -> str:
        if row["kind"] == "mock":
            user_text = " ".join(
                message.get("content", "") for message in messages if message.get("role") == "user"
            )
            digest = uuid.uuid5(uuid.NAMESPACE_URL, user_text).hex[:12]
            if response_format == "json_object":
                return json.dumps(
                    {
                        "summary": "authorized lab request accepted",
                        "request_digest": digest,
                        "allowed_tools": [tool["name"] for tool in tools],
                    },
                    sort_keys=True,
                )
            return (
                "AUTHORIZED_LAB_PLAN: validate scope; collect non-destructive evidence; "
                f"summarize findings. Request digest={digest}"
            )
        api_key = self.store.decrypt_key(row)
        validate_provider_endpoint(str(row["base_url"]), row["kind"], self._provider_config(row))
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
                    json={
                        "model": row["model"],
                        "messages": messages,
                        "stream": False,
                        **({"format": "json"} if response_format == "json_object" else {}),
                    },
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
                        **(
                            {"response_format": {"type": "json_object"}}
                            if response_format == "json_object"
                            else {}
                        ),
                        **(
                            {
                                "tools": [
                                    {
                                        "type": "function",
                                        "function": {
                                            "name": tool["name"],
                                            "description": tool["description"],
                                            "parameters": tool["input_schema"],
                                        },
                                    }
                                    for tool in tools
                                ]
                            }
                            if tools
                            else {}
                        ),
                    },
                )
                response.raise_for_status()
                data = response.json()
                choices = data.get("choices") or []
                content = choices[0].get("message", {}).get("content") if choices else None
        if not isinstance(content, str) or not content.strip():
            raise ModelGatewayError("provider returned no text content")
        return content[:100_000]
