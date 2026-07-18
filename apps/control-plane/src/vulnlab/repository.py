from __future__ import annotations

import re
import threading
from collections.abc import Iterator, Sequence
from contextlib import AbstractContextManager, closing, contextmanager
from dataclasses import dataclass
from typing import Any, Protocol

import psycopg
from psycopg.rows import dict_row

from .config import Settings
from .db import SCHEMA, Database


class RepositoryCursor(Protocol):
    rowcount: int
    lastrowid: int | None

    def fetchone(self) -> Any: ...

    def fetchall(self) -> list[Any]: ...


class RepositoryConnection(Protocol):
    def execute(self, sql: str, params: Sequence[Any] | None = None) -> RepositoryCursor: ...

    def commit(self) -> None: ...

    def rollback(self) -> None: ...

    def close(self) -> None: ...


class ControlPlaneRepository(Protocol):
    """Repository contract used by compatibility control-plane services.

    The contract intentionally captures the existing modular-monolith data-access
    surface. Domain services depend on this protocol; deployment selects either a
    SQLite deterministic adapter or a PostgreSQL production adapter.
    """

    def initialize(self) -> None: ...

    def connect(self) -> Any: ...

    def transaction(self) -> AbstractContextManager[Any]: ...

    def fetch_one(self, sql: str, params: Sequence[Any] = ()) -> Any | None: ...

    def fetch_all(self, sql: str, params: Sequence[Any] = ()) -> list[Any]: ...

    def execute(self, sql: str, params: Sequence[Any] = ()) -> tuple[int, int]: ...


class SQLiteControlPlaneRepository(Database):
    """SQLite adapter retained for deterministic local development and baseline tests."""


def _split_sql_script(script: str) -> list[str]:
    statements: list[str] = []
    current: list[str] = []
    in_single = False
    in_double = False
    index = 0
    while index < len(script):
        char = script[index]
        current.append(char)
        if char == "'" and not in_double:
            if index + 1 < len(script) and script[index + 1] == "'":
                current.append(script[index + 1])
                index += 2
                continue
            in_single = not in_single
        elif char == '"' and not in_single:
            in_double = not in_double
        elif char == ";" and not in_single and not in_double:
            statement = "".join(current).strip().rstrip(";").strip()
            if statement:
                statements.append(statement)
            current = []
        index += 1
    trailing = "".join(current).strip()
    if trailing:
        statements.append(trailing)
    return statements


def _replace_placeholders(sql: str) -> str:
    converted: list[str] = []
    in_single = False
    in_double = False
    index = 0
    while index < len(sql):
        char = sql[index]
        if char == "'" and not in_double:
            converted.append(char)
            if index + 1 < len(sql) and sql[index + 1] == "'":
                converted.append(sql[index + 1])
                index += 2
                continue
            in_single = not in_single
        elif char == '"' and not in_single:
            converted.append(char)
            in_double = not in_double
        elif char == "?" and not in_single and not in_double:
            converted.append("%s")
        else:
            converted.append(char)
        index += 1
    return "".join(converted)


def _translate_sql(sql: str) -> str:
    stripped = sql.strip()
    upper = stripped.upper()
    if upper.startswith("PRAGMA "):
        return "SELECT 1"
    if upper == "BEGIN IMMEDIATE":
        return "BEGIN"

    translated = re.sub(
        r"\bINSERT\s+OR\s+IGNORE\s+INTO\b",
        "INSERT INTO",
        stripped,
        flags=re.IGNORECASE,
    )
    insert_or_ignore = translated != stripped
    translated = _replace_placeholders(translated)
    if insert_or_ignore and " ON CONFLICT " not in translated.upper():
        translated = f"{translated} ON CONFLICT DO NOTHING"
    return translated


def _postgres_schema_sql() -> str:
    schema = SCHEMA
    schema = re.sub(
        r"\bid\s+INTEGER\s+PRIMARY\s+KEY\s+AUTOINCREMENT\b",
        "id BIGSERIAL PRIMARY KEY",
        schema,
        flags=re.IGNORECASE,
    )
    return schema


_SEQUENCE_INSERT = re.compile(
    r"^\s*INSERT\s+INTO\s+(task_events|validation_execution_events|audit_logs)\b",
    re.IGNORECASE,
)


@dataclass(slots=True)
class _PostgresCursor:
    cursor: Any
    lastrowid: int | None = None

    @property
    def rowcount(self) -> int:
        return int(self.cursor.rowcount)

    def fetchone(self) -> Any | None:
        return self.cursor.fetchone()

    def fetchall(self) -> list[Any]:
        return list(self.cursor.fetchall())


class _PostgresConnection:
    def __init__(self, dsn: str, *, schema: str) -> None:
        self._schema = schema
        self._connection = psycopg.connect(
            dsn,
            row_factory=dict_row,
            autocommit=False,
            connect_timeout=10,
        )
        self._connection.execute("SET TIME ZONE 'UTC'")
        self._connection.execute(f"SET search_path TO {schema}, public")

    def execute(self, sql: str, params: Sequence[Any] | None = None) -> _PostgresCursor:
        translated = _translate_sql(sql)
        cursor = self._connection.execute(translated, tuple(params or ()))
        lastrowid: int | None = None
        if _SEQUENCE_INSERT.match(translated):
            last = self._connection.execute("SELECT lastval() AS id").fetchone()
            if last is not None:
                lastrowid = int(last["id"])
        return _PostgresCursor(cursor=cursor, lastrowid=lastrowid)

    def commit(self) -> None:
        self._connection.commit()

    def rollback(self) -> None:
        self._connection.rollback()

    def close(self) -> None:
        self._connection.close()


class PostgresControlPlaneRepository:
    """PostgreSQL adapter for the compatibility control-plane repository contract."""

    def __init__(self, database_url: str, *, schema: str = "compat") -> None:
        self.database_url = database_url
        self.schema = schema
        self._write_lock = threading.RLock()

    def connect(self) -> _PostgresConnection:
        return _PostgresConnection(self.database_url, schema=self.schema)

    def initialize(self) -> None:
        with closing(
            psycopg.connect(
                self.database_url,
                row_factory=dict_row,
                autocommit=True,
                connect_timeout=10,
            )
        ) as connection:
            connection.execute("SET TIME ZONE 'UTC'")
            connection.execute(f"CREATE SCHEMA IF NOT EXISTS {self.schema}")
            connection.execute(f"SET search_path TO {self.schema}, public")
            for statement in _split_sql_script(_postgres_schema_sql()):
                translated = _translate_sql(statement)
                connection.execute(translated)
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS repository_adapter_metadata (
                    tenant_id uuid NOT NULL DEFAULT '00000000-0000-0000-0000-000000000000',
                    id integer NOT NULL CHECK (id = 1),
                    adapter_name text NOT NULL,
                    adapter_version text NOT NULL,
                    schema_name text NOT NULL,
                    installed_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    updated_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    version integer NOT NULL DEFAULT 1,
                    PRIMARY KEY (tenant_id, id),
                    CONSTRAINT ck_repository_adapter_metadata_version CHECK (version > 0)
                )
                """
            )
            connection.execute(
                """
                INSERT INTO repository_adapter_metadata(
                    id, adapter_name, adapter_version, schema_name
                ) VALUES(1, 'PostgresControlPlaneRepository', '2.9.1-p9h', %s)
                ON CONFLICT(tenant_id, id) DO UPDATE
                SET adapter_name = excluded.adapter_name,
                    adapter_version = excluded.adapter_version,
                    schema_name = excluded.schema_name,
                    installed_at = CURRENT_TIMESTAMP,
                    updated_at = CURRENT_TIMESTAMP,
                    version = repository_adapter_metadata.version + 1
                """,
                (self.schema,),
            )

    @contextmanager
    def transaction(self) -> Iterator[_PostgresConnection]:
        with self._write_lock, closing(self.connect()) as connection:
            connection.execute("BEGIN")
            try:
                yield connection
            except Exception:
                connection.rollback()
                raise
            else:
                connection.commit()

    def fetch_one(self, sql: str, params: Sequence[Any] = ()) -> Any | None:
        with closing(self.connect()) as connection:
            cursor = connection.execute(sql, params)
            row = cursor.fetchone()
            connection.commit()
            return row

    def fetch_all(self, sql: str, params: Sequence[Any] = ()) -> list[Any]:
        with closing(self.connect()) as connection:
            cursor = connection.execute(sql, params)
            rows = cursor.fetchall()
            connection.commit()
            return rows

    def execute(self, sql: str, params: Sequence[Any] = ()) -> tuple[int, int]:
        with self.transaction() as connection:
            cursor = connection.execute(sql, params)
            return cursor.rowcount, int(cursor.lastrowid or 0)


def build_control_plane_repository(settings: Settings) -> ControlPlaneRepository:
    backend = settings.repository_backend
    if backend == "sqlite":
        if settings.env in {"production", "prod"}:
            raise RuntimeError("SQLite control-plane repository is forbidden in production")
        return SQLiteControlPlaneRepository(settings.db_path)
    if backend == "postgres":
        if not settings.database_url:
            raise RuntimeError("PostgreSQL control-plane repository requires DATABASE_URL")
        return PostgresControlPlaneRepository(
            settings.database_url,
            schema=settings.repository_schema,
        )
    raise RuntimeError(f"unknown control-plane repository backend: {backend}")
