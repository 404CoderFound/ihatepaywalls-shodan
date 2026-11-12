"""Unit tests for fail-closed production importer; no PostgreSQL/network required."""
import hashlib
import os
import sqlite3
import sys
import types
from pathlib import Path

import pytest
from scripts import import_production_sqlite_snapshot as prod


@pytest.fixture
def backup(tmp_path):
    path = tmp_path / "approved-frozen.db"
    db = sqlite3.connect(path)
    for name in sorted(prod.REQUIRED_TABLES):
        db.execute(f"CREATE TABLE {name}(id INTEGER PRIMARY KEY, text TEXT)")
    db.commit()
    db.close()
    return path, hashlib.sha256(path.read_bytes()).hexdigest()


def test_frozen_source_verified_without_writes(backup):
    path, digest = backup
    content = path.read_bytes()
    assert prod.inspect_frozen_source(path, digest)[2] == len(prod.REQUIRED_TABLES)
    assert path.read_bytes() == content
    assert not Path(str(path) + "-shm").exists()


def test_wrong_checksum_refused(backup):
    path, _ = backup
    with pytest.raises(ValueError, match="SHA-256 differs"):
        prod.inspect_frozen_source(path, "0" * 64)


def test_live_file_name_refused(backup):
    path, digest = backup
    new = path.parent / "scanlattice.db"
    path.rename(new)
    with pytest.raises(ValueError, match="live scanlattice.db"):
        prod.inspect_frozen_source(new, digest)


def test_wal_sidecar_refused(backup):
    path, digest = backup
    Path(str(path) + "-wal").touch()
    with pytest.raises(ValueError, match="journal/WAL"):
        prod.inspect_frozen_source(path, digest)


def test_symlink_and_hardlink_refused(backup, tmp_path):
    path, digest = backup
    linked = tmp_path / "backup-link.db"
    linked.symlink_to(path)
    with pytest.raises(ValueError, match="symlink"):
        prod.inspect_frozen_source(linked, digest)
    hard = tmp_path / "backup-hard.db"
    os.link(path, hard)
    with pytest.raises(ValueError, match="hard-linked"):
        prod.inspect_frozen_source(path, digest)


def test_unrelated_sqlite_refused(tmp_path):
    path = tmp_path / "unrelated.db"
    db = sqlite3.connect(path)
    db.execute("CREATE TABLE unrelated (id INTEGER PRIMARY KEY)")
    db.commit()
    db.close()
    with pytest.raises(ValueError, match="missing required"):
        prod.inspect_frozen_source(path, hashlib.sha256(path.read_bytes()).hexdigest())


class Result:
    def __init__(self, rows): self.rows = rows
    def fetchone(self): return self.rows[0] if self.rows else None
    def fetchall(self): return self.rows


class DB:
    def __init__(self, tables=(), ledger=(), clients=0):
        self.tables, self.ledger, self.clients = tables, ledger, clients
        self.statements = []
    def execute(self, sql, params=()):
        self.statements.append(sql)
        if "pg_stat_activity" in sql: return Result([(self.clients,)])
        if "current_database()" in sql: return Result([("scanlattice",)])
        if "pg_catalog.pg_tables" in sql: return Result([(v,) for v in self.tables])
        if "sqlite_migration_runs" in sql: return Result(self.ledger)
        raise AssertionError(sql)


@pytest.fixture
def pg_dsn(monkeypatch):
    conninfo = types.ModuleType("psycopg.conninfo")
    conninfo.conninfo_to_dict = lambda dsn: {"host": "postgres", "dbname": "scanlattice"}
    monkeypatch.setitem(sys.modules, "psycopg.conninfo", conninfo)
    monkeypatch.setenv("DATABASE_URL", "postgresql://scanlattice@postgres:5432/scanlattice")


def identity(db):
    return prod.identity_and_state(db, "public", "postgres", "scanlattice", "fp", "id")


def test_empty_target_is_safe(pg_dsn):
    db = DB()
    assert identity(db) == "empty"
    assert not any(sql.lower().startswith(("insert", "update", "delete", "create")) for sql in db.statements)


def test_nonempty_unrelated_target_refused(pg_dsn):
    with pytest.raises(ValueError, match="already contains"):
        identity(DB(tables=("hosts",)))


@pytest.mark.parametrize("ledger", [
    ("id", "fp", "running"), ("other", "fp", "completed"), ("id", "wrong", "completed")
])
def test_interrupted_or_unrelated_import_refused(pg_dsn, ledger):
    with pytest.raises(ValueError, match="manual recovery"):
        identity(DB(tables=("hosts", "sqlite_migration_runs"), ledger=[ledger]))


def test_idempotent_complete_source_accepted(pg_dsn):
    assert identity(DB(tables=("sqlite_migration_runs",), ledger=[("id", "fp", "completed")])) == "completed"


def test_concurrent_clients_refused(pg_dsn):
    with pytest.raises(ValueError, match="Another PostgreSQL client"):
        identity(DB(clients=1))


def test_wrong_target_identity_refused(pg_dsn):
    with pytest.raises(ValueError, match="does not match"):
        prod.identity_and_state(DB(), "public", "another-host", "scanlattice", "fp", "id")


def test_preflight_does_not_call_importer(backup, monkeypatch):
    path, digest = backup
    monkeypatch.setattr(prod, "check_target", lambda *args: "empty")
    monkeypatch.setattr(prod, "migrate", lambda *args: pytest.fail("dry-run touched importer"))
    assert prod.main([str(path), "--source-sha256", digest, "--expected-host", "postgres",
                      "--expected-database", "scanlattice"]) == 0


def test_execute_requires_writer_acknowledgment(backup):
    path, digest = backup
    with pytest.raises(SystemExit) as exc:
        prod.main([str(path), "--source-sha256", digest, "--expected-host", "postgres",
                   "--expected-database", "scanlattice", "--execute"])
    assert exc.value.code == 2
