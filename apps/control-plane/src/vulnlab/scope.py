from __future__ import annotations

import asyncio
import hashlib
import http.client
import ipaddress
import json
import socket
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any
from urllib.parse import urlsplit

from .config import Settings
from .repository import ControlPlaneRepository


class ScopeViolation(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class Target:
    raw: str
    host: str
    port: int | None
    scheme: str | None


def scope_hash(
    target_pattern: str,
    protocols: Sequence[str],
    ports: Sequence[int],
    expires_at: str | None,
    resolved_ips: Sequence[str] | None = None,
) -> str:
    canonical = json.dumps(
        {
            "target_pattern": target_pattern.strip().rstrip(".").lower(),
            "protocols": sorted(set(protocols)),
            "ports": sorted(set(ports)),
            "expires_at": expires_at,
            "resolved_ips": sorted(set(resolved_ips or [])),
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(canonical.encode()).hexdigest()


def row_scope_hash(row: Any) -> str:
    return scope_hash(
        row["target_pattern"],
        json.loads(row["protocols_json"]),
        json.loads(row["ports_json"]),
        row["expires_at"],
        json.loads(row["resolved_ips_json"]),
    )


def parse_target(raw: str) -> Target:
    value = raw.strip()
    if not value:
        raise ScopeViolation("target is empty")
    parsed = urlsplit(value if "://" in value else "//" + value)
    if parsed.username or parsed.password:
        raise ScopeViolation("embedded target credentials are forbidden")
    if parsed.scheme and parsed.scheme.lower() not in {"http", "https", "tcp"}:
        raise ScopeViolation("only http, https, and tcp targets are supported")
    host = parsed.hostname
    if not host:
        raise ScopeViolation("target has no valid hostname")
    try:
        port = parsed.port
    except ValueError as exc:
        raise ScopeViolation("target has an invalid port") from exc
    if port is None and parsed.scheme:
        port = {"http": 80, "https": 443}.get(parsed.scheme.lower())
    host = host.rstrip(".").lower()
    if "%" in host:
        raise ScopeViolation("IPv6 zone identifiers are forbidden")
    return Target(raw=value, host=host, port=port, scheme=(parsed.scheme.lower() or None))


def _as_ip(value: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    try:
        result = ipaddress.ip_address(value)
        if isinstance(result, ipaddress.IPv6Address) and result.ipv4_mapped:
            return result.ipv4_mapped
        return result
    except ValueError:
        return None


def _matches_pattern(host: str, pattern: str) -> bool:
    normalized = pattern.strip().rstrip(".").lower()
    try:
        network = ipaddress.ip_network(normalized, strict=False)
    except ValueError:
        return host == normalized
    address = _as_ip(host)
    return bool(address and address in network)


class ScopeService:
    def __init__(self, db: ControlPlaneRepository, settings: Settings):
        self.db = db
        self.settings = settings

    def _global_host_allowed(self, host: str) -> bool:
        if any(_matches_pattern(host, pattern) for pattern in self.settings.allowed_hosts):
            return True
        address = _as_ip(host)
        return bool(
            address
            and self.settings.allow_private_networks
            and (address.is_private or address.is_loopback)
        )

    @staticmethod
    def _address_safe(address_text: str) -> bool:
        address = _as_ip(address_text)
        if address and address.is_loopback:
            return True
        return bool(
            address
            and not address.is_multicast
            and not address.is_unspecified
            and not address.is_reserved
            and not address.is_link_local
        )

    def approval_snapshot(self, target_pattern: str) -> list[str]:
        try:
            ipaddress.ip_network(target_pattern, strict=False)
            if "/" in target_pattern:
                return []
        except ValueError:
            pass
        if not self._global_host_allowed(target_pattern):
            raise ScopeViolation("scope target is outside the deployment allowlist")
        address = _as_ip(target_pattern)
        if address is not None:
            addresses = [str(address)]
        else:
            try:
                records = socket.getaddrinfo(target_pattern, None, type=socket.SOCK_STREAM)
            except socket.gaierror as exc:
                raise ScopeViolation(f"scope target DNS resolution failed: {exc}") from exc
            normalized = (_as_ip(str(record[4][0])) for record in records)
            addresses = sorted(
                {address.compressed for address in normalized if address is not None}
            )
        if not addresses or any(not self._address_safe(item) for item in addresses):
            raise ScopeViolation("scope resolves to an unsafe or empty address set")
        return addresses

    def validate(
        self,
        target_raw: str,
        scope_id: str,
        ports: list[int] | None = None,
        *,
        require_approved: bool = True,
    ) -> Target:
        target = parse_target(target_raw)
        row = self.db.fetch_one("SELECT * FROM scopes WHERE id=?", (scope_id,))
        if row is None:
            raise ScopeViolation("scope does not exist")
        if require_approved and not bool(row["approved"]):
            raise ScopeViolation("scope is not approved")
        if row["scope_hash"] != row_scope_hash(row):
            raise ScopeViolation("scope content changed after signing; reapproval is required")
        if row["expires_at"]:
            expiry = datetime.fromisoformat(row["expires_at"])
            if expiry.tzinfo is None:
                expiry = expiry.replace(tzinfo=UTC)
            if expiry <= datetime.now(UTC):
                raise ScopeViolation("scope has expired")
        if not _matches_pattern(target.host, row["target_pattern"]):
            raise ScopeViolation("target is outside the selected scope")
        if not self._global_host_allowed(target.host):
            raise ScopeViolation("target is outside the deployment allowlist")
        allowed_ports = set(json.loads(row["ports_json"])) & set(self.settings.allowed_ports)
        requested = set(ports or ([target.port] if target.port else []))
        if requested and not requested <= allowed_ports:
            raise ScopeViolation("one or more ports are outside the scope/deployment intersection")
        if target.scheme:
            protocols = set(json.loads(row["protocols_json"]))
            if target.scheme not in protocols:
                raise ScopeViolation("target protocol is outside the scope")
        return target

    async def resolve_and_revalidate(
        self, target_raw: str, scope_id: str, port: int
    ) -> tuple[Target, list[str]]:
        target = self.validate(target_raw, scope_id, [port])
        loop = asyncio.get_running_loop()
        try:
            records = await loop.run_in_executor(
                None, lambda: socket.getaddrinfo(target.host, port, type=socket.SOCK_STREAM)
            )
        except socket.gaierror as exc:
            raise ScopeViolation(f"target DNS resolution failed: {exc}") from exc
        addresses = sorted({str(record[4][0]) for record in records})
        if not addresses:
            raise ScopeViolation("target resolved to no addresses")
        for address_text in addresses:
            if not self._address_safe(address_text):
                raise ScopeViolation(f"resolved address {address_text} is not safe")
            if target.host not in self.settings.allowed_hosts and not self._global_host_allowed(
                address_text
            ):
                raise ScopeViolation(
                    f"resolved address {address_text} is outside the deployment allowlist"
                )
        row = self.db.fetch_one("SELECT resolved_ips_json FROM scopes WHERE id=?", (scope_id,))
        approved_addresses = set(json.loads(row["resolved_ips_json"])) if row else set()
        normalized_addresses = {str(_as_ip(item)) for item in addresses}
        if approved_addresses and not normalized_addresses <= approved_addresses:
            raise ScopeViolation(
                "target DNS resolution changed after scope approval; reapproval is required"
            )
        return target, addresses

    async def probe(
        self, target_raw: str, scope_id: str, ports: list[int], timeout: float
    ) -> dict[str, Any]:
        results: list[dict[str, object]] = []
        for port in ports:
            target, addresses = await self.resolve_and_revalidate(target_raw, scope_id, port)
            started = asyncio.get_running_loop().time()
            try:
                status = "closed_or_filtered"
                error: str | None = "ConnectionFailed"
                # Connect only to an address that was just resolved and validated. This avoids a
                # second hostname lookup and closes the common DNS-rebinding TOCTOU gap.
                for address in addresses:
                    try:
                        reader, writer = await asyncio.wait_for(
                            asyncio.open_connection(address, port), timeout=timeout
                        )
                        del reader
                        writer.close()
                        await writer.wait_closed()
                        status = "open"
                        error = None
                        break
                    except (TimeoutError, OSError) as exc:
                        error = type(exc).__name__
            except (TimeoutError, OSError) as exc:
                status = "closed_or_filtered"
                error = type(exc).__name__
            results.append(
                {
                    "port": port,
                    "status": status,
                    "resolved_addresses": addresses,
                    "latency_ms": round((asyncio.get_running_loop().time() - started) * 1000, 2),
                    "error": error,
                }
            )
        return {
            "target": parse_target(target_raw).host,
            "results": results,
            "non_destructive": True,
        }

    async def http_probe(
        self,
        target_raw: str,
        scope_id: str,
        port: int,
        method: str,
        path: str,
        timeout: float,
    ) -> dict[str, object]:
        target, addresses = await self.resolve_and_revalidate(target_raw, scope_id, port)
        if target.scheme != "http":
            raise ScopeViolation(
                "structured HTTP probing supports plain HTTP lab targets only; HTTPS uses TCP evidence"
            )

        def request(address: str) -> dict[str, object]:
            connection = http.client.HTTPConnection(address, port, timeout=timeout)
            try:
                connection.request(
                    method,
                    path,
                    headers={
                        "Host": target.host,
                        "User-Agent": "VulnLab-Authorized-Probe/1.0",
                        "Connection": "close",
                    },
                )
                response = connection.getresponse()
                body = response.read(65_536 if method == "GET" else 0)
                return {
                    "status": response.status,
                    "reason": response.reason,
                    "headers": {
                        key.lower(): value[:512]
                        for key, value in response.getheaders()
                        if key.lower() in {"server", "content-type", "content-length", "location"}
                    },
                    "body": body.decode("utf-8", errors="replace"),
                }
            finally:
                connection.close()

        errors: list[str] = []
        for address in addresses:
            try:
                result = await asyncio.wait_for(
                    asyncio.to_thread(request, address), timeout=timeout + 0.5
                )
                return {
                    "target": target.host,
                    "connected_address": address,
                    "port": port,
                    "method": method,
                    "path": path,
                    **result,
                    "non_destructive": True,
                }
            except (TimeoutError, OSError, http.client.HTTPException) as exc:
                errors.append(type(exc).__name__)
        return {
            "target": target.host,
            "port": port,
            "method": method,
            "path": path,
            "error": errors[-1] if errors else "ConnectionFailed",
            "non_destructive": True,
        }
