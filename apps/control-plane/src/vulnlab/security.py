from __future__ import annotations

import hashlib
import hmac
import re
import secrets
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime

from .db import Database
from .schemas import Role

ROLE_PERMISSIONS: dict[Role, frozenset[str]] = {
    Role.VIEWER: frozenset(
        {
            "health:read",
            "task:read",
            "skill:read",
            "scope:read",
            "rag:read",
            "context:read",
            "profile:read",
        }
    ),
    Role.ANALYST: frozenset(
        {
            "health:read",
            "task:read",
            "task:create",
            "task:cancel",
            "skill:read",
            "provider:read",
            "scope:read",
            "rag:read",
            "rag:write",
            "context:read",
            "context:write",
            "profile:read",
            "profile:create",
            "scope:create",
        }
    ),
    Role.OPERATOR: frozenset(
        {
            "health:read",
            "task:read",
            "task:create",
            "task:cancel",
            "task:execute",
            "skill:read",
            "provider:read",
            "scope:read",
            "rag:read",
            "rag:write",
            "context:read",
            "context:write",
            "sandbox:execute",
            "asset:probe",
            "profile:read",
            "profile:create",
            "scope:create",
        }
    ),
    Role.ADMIN: frozenset({"*"}),
}


@dataclass(frozen=True, slots=True)
class Principal:
    id: str
    username: str
    role: Role

    def can(self, permission: str) -> bool:
        permissions = ROLE_PERMISSIONS[self.role]
        return "*" in permissions or permission in permissions


class AuthenticationError(ValueError):
    pass


class PermissionDenied(PermissionError):
    pass


class SecurityService:
    def __init__(self, db: Database, secret: bytes):
        self.db = db
        self.secret = secret

    def hash_key(self, api_key: str) -> str:
        return hmac.new(self.secret, api_key.encode(), hashlib.sha256).hexdigest()

    def bootstrap_admin(self, api_key: str) -> None:
        now = datetime.now(UTC).isoformat()
        key_hash = self.hash_key(api_key)
        with self.db.transaction() as connection:
            row = connection.execute("SELECT id FROM users WHERE username='admin'").fetchone()
            if row is None:
                connection.execute(
                    "INSERT INTO users(id,username,key_hash,role,active,created_at) VALUES(?,?,?,?,1,?)",
                    (str(uuid.uuid4()), "admin", key_hash, Role.ADMIN.value, now),
                )
            else:
                connection.execute(
                    "UPDATE users SET key_hash=?,role=?,active=1 WHERE id=?",
                    (key_hash, Role.ADMIN.value, row["id"]),
                )

    def authenticate(self, api_key: str | None) -> Principal:
        if not api_key:
            raise AuthenticationError("missing API key")
        row = self.db.fetch_one(
            "SELECT id,username,role,active FROM users WHERE key_hash=?",
            (self.hash_key(api_key),),
        )
        if row is None or not bool(row["active"]):
            raise AuthenticationError("invalid or inactive API key")
        return Principal(id=row["id"], username=row["username"], role=Role(row["role"]))

    @staticmethod
    def require(principal: Principal, permission: str) -> None:
        if not principal.can(permission):
            raise PermissionDenied(f"role {principal.role.value} lacks permission {permission}")

    def create_user(self, username: str, role: Role) -> tuple[dict[str, object], str]:
        api_key = "vl_" + secrets.token_urlsafe(32)
        user_id = str(uuid.uuid4())
        created_at = datetime.now(UTC).isoformat()
        self.db.execute(
            "INSERT INTO users(id,username,key_hash,role,active,created_at) VALUES(?,?,?,?,1,?)",
            (user_id, username, self.hash_key(api_key), role.value, created_at),
        )
        return {
            "id": user_id,
            "username": username,
            "role": role.value,
            "active": True,
            "created_at": created_at,
        }, api_key

    def update_user(
        self, user_id: str, role: Role | None, active: bool | None
    ) -> dict[str, object]:
        row = self.db.fetch_one("SELECT * FROM users WHERE id=?", (user_id,))
        if row is None:
            raise KeyError("user not found")
        new_role = role.value if role is not None else row["role"]
        new_active = int(active) if active is not None else int(row["active"])
        self.db.execute(
            "UPDATE users SET role=?,active=? WHERE id=?", (new_role, new_active, user_id)
        )
        return {
            "id": row["id"],
            "username": row["username"],
            "role": new_role,
            "active": bool(new_active),
            "created_at": row["created_at"],
        }


def redact(value: object) -> object:
    """Recursively remove secrets before data enters logs or API responses."""
    if isinstance(value, dict):
        redacted: dict[str, object] = {}
        for key, item in value.items():
            lowered = str(key).lower()
            if any(
                marker in lowered
                for marker in ("api_key", "authorization", "password", "secret", "token", "cookie")
            ):
                redacted[str(key)] = "[REDACTED]"
            else:
                redacted[str(key)] = redact(item)
        return redacted
    if isinstance(value, (list, tuple)):
        return [redact(item) for item in value]
    if isinstance(value, str):
        redacted_text = value
        patterns = (
            (
                re.compile(r"(?i)(authorization\s*:\s*bearer\s+)[A-Za-z0-9._~+/=-]+"),
                r"\1[REDACTED]",
            ),
            (
                re.compile(r"(?i)((?:api[_-]?key|password|secret|token)\s*[=:]\s*)[^\s,;&]+"),
                r"\1[REDACTED]",
            ),
            (re.compile(r"\bsk-[A-Za-z0-9_-]{12,}\b"), "[REDACTED]"),
            (
                re.compile(r"(?i)([?&](?:api[_-]?key|token|secret|password)=)[^&#\s]+"),
                r"\1[REDACTED]",
            ),
        )
        for pattern, replacement in patterns:
            redacted_text = pattern.sub(replacement, redacted_text)
        if len(redacted_text) > 4096:
            digest = hashlib.sha256(redacted_text.encode()).hexdigest()[:16]
            return redacted_text[:512] + f"...[truncated sha256:{digest}]"
        return redacted_text
    return value
