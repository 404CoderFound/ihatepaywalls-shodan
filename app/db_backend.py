"""Database connection backends for the control plane.

SQLite remains the zero-configuration backend. PostgreSQL uses psycopg 3 and a
small compatibility layer for the application's existing qmark SQL and row
access patterns; PostgreSQL-specific schema changes live in versioned SQL
migrations.
"""
from __future__ import annotations

import re
import sqlite3
from collections.abc import Iterator, Mapping, Sequence
from pathlib import Path
from typing import Any, Protocol


class ConnectionProtocol(Protocol):
    def execute(self, sql: str, parameters: Any = ...) -> Any: ...
    def executemany(self, sql: str, parameters: Any) -> Any: ...
    def executescript(self, sql: str) -> Any: ...
    def commit(self) -> None: ...
    def rollback(self) -> None: ...
    def close(self) -> None: ...


class DatabaseBackend(Protocol):
    name: str

    def connect(self, path: Path) -> ConnectionProtocol: ...
    def configure(self, connection: ConnectionProtocol) -> None: ...


class SQLiteBackend:
    name = "sqlite"

    def connect(self, path: Path) -> sqlite3.Connection:
        return sqlite3.connect(path, timeout=20)

    def configure(self, connection: ConnectionProtocol) -> None:
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys=ON")


_GENERATED_ID_TABLES = {
    "observations", "services", "authorizations", "scan_profiles", "audit_logs",
    "passive_providers", "passive_records", "hostnames", "routing_prefixes",
    "indexing_schedules", "api_keys", "dns_observations", "host_vulnerability_matches",
    "host_screenshots", "monitor_targets", "monitor_events", "monitor_destinations",
    "monitor_notifications", "saved_searches",
}


class PostgreSQLRow(Mapping[str, Any]):
    """A row supporting both sqlite3.Row-style integer and mapping access."""

    def __init__(self, names: Sequence[str], values: Sequence[Any]):
        self._names = tuple(names)
        self._values = tuple(values)
        self._indexes = {}
        for index, name in enumerate(self._names):
            self._indexes.setdefault(name, index)

    def __getitem__(self, key: str | int) -> Any:
        if isinstance(key, int):
            return self._values[key]
        return self._values[self._indexes[key]]

    def __iter__(self) -> Iterator[str]:
        return iter(self._names)

    def __len__(self) -> int:
        return len(self._names)


class PostgreSQLCursor:
    def __init__(self, cursor: Any, generated_id: bool = False):
        self._cursor = cursor
        self._generated_id = generated_id
        self._first_row: PostgreSQLRow | None = None
        self._first_row_loaded = False
        self._columns = tuple(column.name for column in (cursor.description or ()))

    @property
    def rowcount(self) -> int:
        return self._cursor.rowcount

    @property
    def lastrowid(self) -> int | None:
        if not self._generated_id:
            return None
        if not self._first_row_loaded:
            raw = self._cursor.fetchone()
            self._first_row = self._row(raw) if raw is not None else None
            self._first_row_loaded = True
        return self._first_row[0] if self._first_row is not None else None

    def _row(self, value: Any) -> PostgreSQLRow | None:
        return PostgreSQLRow(self._columns, value) if value is not None else None

    def fetchone(self) -> PostgreSQLRow | None:
        if self._first_row_loaded:
            self._first_row_loaded = False
            row, self._first_row = self._first_row, None
            return row
        return self._row(self._cursor.fetchone())

    def fetchall(self) -> list[PostgreSQLRow]:
        rows = []
        if self._first_row_loaded:
            self._first_row_loaded = False
            if self._first_row is not None:
                rows.append(self._first_row)
            self._first_row = None
        rows.extend(PostgreSQLRow(self._columns, row) for row in self._cursor.fetchall())
        return rows

    def fetchmany(self, size: int = 1) -> list[PostgreSQLRow]:
        rows = []
        if self._first_row_loaded and size:
            self._first_row_loaded = False
            if self._first_row is not None:
                rows.append(self._first_row)
            self._first_row = None
        if len(rows) < size:
            rows.extend(PostgreSQLRow(self._columns, row) for row in self._cursor.fetchmany(size - len(rows)))
        return rows

    def __iter__(self) -> Iterator[PostgreSQLRow]:
        while (row := self.fetchone()) is not None:
            yield row


def _qmark_to_format(sql: str) -> str:
    """Convert unquoted SQLite placeholders without touching literal text."""
    output: list[str] = []
    quote: str | None = None
    index = 0
    while index < len(sql):
        char = sql[index]
        if quote:
            output.append(char)
            if char == quote:
                if index + 1 < len(sql) and sql[index + 1] == quote:
                    output.append(sql[index + 1])
                    index += 1
                else:
                    quote = None
        elif char in "'\"":
            quote = char
            output.append(char)
        elif char == "?":
            output.append("%s")
        else:
            output.append(char)
        index += 1
    return "".join(output)


def _postgres_sql(sql: str) -> str:
    statement = sql.strip().rstrip(";")
    if statement.upper().startswith("PRAGMA JOURNAL_MODE=") or statement.upper().startswith("PRAGMA FOREIGN_KEYS="):
        return "SELECT 1 WHERE FALSE"
    info = re.fullmatch(r"PRAGMA\s+table_info\((\w+)\)", statement, re.IGNORECASE)
    if info:
        return 'SELECT ordinal_position-1 AS cid,column_name AS name,data_type AS type,(is_nullable=\'NO\') AS "notnull",NULL AS dflt_value,0 AS pk FROM information_schema.columns WHERE table_schema=current_schema() AND table_name=%s ORDER BY ordinal_position'
    ignore_conflict = bool(re.match(r"\s*INSERT\s+OR\s+IGNORE\s+INTO\b", statement, re.IGNORECASE))
    statement = re.sub(r"\bINSERT\s+OR\s+IGNORE\s+INTO\b", "INSERT INTO", statement, flags=re.IGNORECASE)
    statement = re.sub(r"\bMIN\(([^(),]+),\s*([^(),]+)\)", r"LEAST(\1,\2)", statement, flags=re.IGNORECASE)
    statement = re.sub(r"\bMAX\(([^(),]+),\s*([^(),]+)\)", r"GREATEST(\1,\2)", statement, flags=re.IGNORECASE)
    statement = re.sub(r"\bINSTR\(([^(),]+),\s*([^(),]+)\)", r"POSITION(\2 IN \1)", statement, flags=re.IGNORECASE)
    def json_path(match: re.Match[str]) -> str:
        path = match.group(2).removeprefix("$").strip(".")
        keys = ",".join(key.replace("'", "''") for key in path.split(".") if key)
        return f"({match.group(1)}::jsonb #>> '{{{keys}}}')"
    statement = re.sub(r"\bjson_extract\(\s*([^,]+?)\s*,\s*'([^']+)'\s*\)", json_path, statement, flags=re.IGNORECASE)
    if re.search(r"\bINSERT\s+INTO\b", statement, re.IGNORECASE):
        has_conflict_clause = re.search(r"\bON\s+CONFLICT\b", statement, re.IGNORECASE) is not None
        if ignore_conflict and not has_conflict_clause:
            statement += " ON CONFLICT DO NOTHING"
        if not ignore_conflict and not has_conflict_clause and re.search(r"\bRETURNING\b", statement, re.IGNORECASE) is None:
            match = re.search(r"\bINSERT\s+INTO\s+([a-z_][a-z0-9_]*)", statement, re.IGNORECASE)
            if match and match.group(1).lower() in _GENERATED_ID_TABLES and not re.search(r"\bSELECT\b", statement, re.IGNORECASE):
                statement += " RETURNING id"
    statement = re.sub(r"\bINTEGER\s+PRIMARY\s+KEY\s+AUTOINCREMENT\b", "BIGSERIAL PRIMARY KEY", statement, flags=re.IGNORECASE)
    statement = re.sub(r"\bBLOB\b", "BYTEA", statement, flags=re.IGNORECASE)
    return _qmark_to_format(statement)


class PostgreSQLConnection:
    def __init__(self, raw: Any):
        self._raw = raw

    def execute(self, sql: str, parameters: Any = ()) -> PostgreSQLCursor:
        compiled = _postgres_sql(sql)
        generated_id = bool(re.search(r"\bINSERT\s+INTO\b.*\bRETURNING\s+id\s*$", compiled, re.IGNORECASE))
        match = re.fullmatch(r"\s*PRAGMA\s+table_info\((\w+)\)\s*;?\s*", sql, re.IGNORECASE)
        params = (match.group(1).lower(),) if match else parameters
        return PostgreSQLCursor(self._raw.execute(compiled, params), generated_id=generated_id)

    def executemany(self, sql: str, parameters: Any) -> PostgreSQLCursor:
        compiled = _postgres_sql(sql)
        cursor = self._raw.cursor()
        cursor.executemany(compiled, parameters)
        return PostgreSQLCursor(cursor)

    def executescript(self, sql: str) -> None:
        for statement in sql.split(";"):
            if statement.strip():
                self.execute(statement)

    def commit(self) -> None:
        self._raw.commit()

    def rollback(self) -> None:
        self._raw.rollback()

    def close(self) -> None:
        self._raw.close()


class PostgreSQLBackend:
    name = "postgresql"

    def connect(self, path: Path) -> PostgreSQLConnection:
        del path  # PostgreSQL is configured with DATABASE_URL, not a filesystem path.
        try:
            import psycopg
            from psycopg.rows import tuple_row
        except ImportError as exc:
            raise RuntimeError("PostgreSQL support requires psycopg 3; install requirements.txt") from exc
        import os

        dsn = os.getenv("DATABASE_URL") or os.getenv("POSTGRES_DSN")
        if not dsn:
            raise RuntimeError("DATABASE_URL is required when DATABASE_BACKEND=postgresql")
        schema = os.getenv("DATABASE_SCHEMA", "public")
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,62}", schema):
            raise RuntimeError("DATABASE_SCHEMA must be a valid PostgreSQL identifier")
        raw = psycopg.connect(dsn, row_factory=tuple_row)
        raw.execute(f'CREATE SCHEMA IF NOT EXISTS "{schema}"')
        raw.execute(f'SET search_path TO "{schema}"')
        return PostgreSQLConnection(raw)

    def configure(self, connection: ConnectionProtocol) -> None:
        return None


def configured_backend(name: str | None = None) -> DatabaseBackend:
    selected = (name or "sqlite").strip().lower()
    if selected == "sqlite":
        return SQLiteBackend()
    if selected in {"postgres", "postgresql"}:
        return PostgreSQLBackend()
    raise RuntimeError(f"Database backend {selected!r} is not implemented")
