"""Small database backend seam; SQLite remains the sole supported backend.

The v1 application uses SQLite SQL features in its query/migration layer. This
module centralizes connection construction and transaction setup so a future
PostgreSQL backend can be added deliberately without changing callers that use
``database.connection()``. It does not claim PostgreSQL compatibility yet.
"""
from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Any, Protocol


class ConnectionProtocol(Protocol):
    row_factory: Any

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


def configured_backend(name: str | None = None) -> DatabaseBackend:
    selected = (name or "sqlite").strip().lower()
    if selected == "sqlite":
        return SQLiteBackend()
    raise RuntimeError(
        f"Database backend {selected!r} is not implemented; SQLite remains the supported backend"
    )
