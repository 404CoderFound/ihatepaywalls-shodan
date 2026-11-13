"""Unit tests for fail-closed production importer; no PostgreSQL/network required."""
import hashlib
import os
import shutil
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
    path.chmod(0o600)
    return path, hashlib.sha256(path.read_bytes()).hexdigest()


@pytest.fixture
def verified_backup(backup, tmp_path):
    source, digest = backup
    rollback = tmp_path / "verified-rollback-copy.db"
    shutil.copyfile(source, rollback)
    rollback.chmod(0o600)
    return source, digest, rollback


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


def test_verified_snapshot_requires_separate_byte_identical_backup(verified_backup, tmp_path):
    source, digest, rollback = verified_backup
    assert prod.verify_snapshot_and_backup(source, digest, rollback, digest)[2] == len(prod.REQUIRED_TABLES)
    with pytest.raises(ValueError, match="separate files"):
        prod.verify_snapshot_and_backup(source, digest, source, digest)
    changed = tmp_path / "different-rollback.db"
    shutil.copyfile(rollback, changed)
    changed.chmod(0o600)
    changed.write_bytes(changed.read_bytes() + b"tampered")
    with pytest.raises(ValueError, match="integrity_check failed|differs"):
        prod.verify_snapshot_and_backup(source, digest, changed, hashlib.sha256(changed.read_bytes()).hexdigest())


def test_frozen_source_rejects_group_or_world_access(backup):
    path, digest = backup
    path.chmod(0o644)
    with pytest.raises(ValueError, match="group/world accessible"):
        prod.inspect_frozen_source(path, digest)


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
    db.execute("CREATE TABLE padding (value TEXT)")
    db.execute("INSERT INTO padding VALUES(?)", ("x" * 8192,))
    db.commit()
    db.close()
    path.chmod(0o600)
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
        if "pg_catalog.pg_depend" in sql: return Result([])
        if "pg_catalog.pg_class" in sql:
            return Result([(name, "r") for name in self.tables])
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
    with pytest.raises(ValueError, match="unrelated objects"):
        identity(DB(tables=("hosts",)))


def test_target_schema_with_non_table_relations_is_refused(pg_dsn):
    class ViewDB(DB):
        def execute(self, sql, params=()):
            if "pg_catalog.pg_class" in sql:
                return Result([("unexpected_view", "v")])
            return super().execute(sql, params)
    with pytest.raises(ValueError, match="unsupported objects"):
        identity(ViewDB())


def test_orphan_sequence_is_refused(pg_dsn):
    class SequenceDB(DB):
        def execute(self, sql, params=()):
            if "pg_catalog.pg_class" in sql:
                return Result([("unrelated_seq", "S")])
            if "pg_catalog.pg_depend" in sql:
                return Result([])
            return super().execute(sql, params)
    with pytest.raises(ValueError, match="unrelated objects"):
        identity(SequenceDB())


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


def test_preflight_does_not_call_importer(verified_backup, monkeypatch):
    path, digest, rollback = verified_backup
    monkeypatch.setattr(prod, "check_target", lambda *args: "empty")
    monkeypatch.setattr(prod, "migrate", lambda *args: pytest.fail("dry-run touched importer"))
    assert prod.main([str(path), "--source-sha256", digest, "--expected-host", "postgres",
                      "--expected-database", "scanlattice", "--rollback-backup", str(rollback),
                      "--rollback-backup-sha256", digest]) == 0


def test_execute_requires_writer_acknowledgment(verified_backup):
    path, digest, rollback = verified_backup
    with pytest.raises(SystemExit) as exc:
        prod.main([str(path), "--source-sha256", digest, "--expected-host", "postgres",
                   "--expected-database", "scanlattice", "--rollback-backup", str(rollback),
                   "--rollback-backup-sha256", digest, "--execute"])
    assert exc.value.code == 2


def test_execute_requires_written_go_approval_reference(verified_backup):
    path, digest, rollback = verified_backup
    with pytest.raises(SystemExit) as exc:
        prod.main([str(path), "--source-sha256", digest, "--expected-host", "postgres",
                   "--expected-database", "scanlattice", "--rollback-backup", str(rollback),
                   "--rollback-backup-sha256", digest, "--execute",
                   "--acknowledge-writers-frozen"])
    assert exc.value.code == 2


def test_migration_id_reconciliation_is_bounded_and_deterministic(tmp_path):
    path = tmp_path / "ids.sqlite"
    db = sqlite3.connect(path)
    db.execute("CREATE TABLE sample(id INTEGER PRIMARY KEY)")
    db.executemany("INSERT INTO sample(id) VALUES(?)", [(1,), (3,), (9,)])
    digest, maximum, count = prod._sqlite_id_digest(db, "sample")
    assert len(digest) == 64
    assert (maximum, count) == (9, 3)
    db.execute("DELETE FROM sample")
    db.executemany("INSERT INTO sample(id) VALUES(?)", [(9,), (1,), (3,)])
    assert prod._sqlite_id_digest(db, "sample")[0] == digest
    db.close()


def test_production_runbook_has_explicit_go_gates_and_rollback_rules():
    root = Path(__file__).parents[1]
    runbook = (root / "deploy" / "PRODUCTION_IMPORT.md").read_text()
    rehearsal = (root / "scripts" / "rehearse_postgresql_from_backup.sh").read_text()
    assert "GO / NO-GO gates" in runbook
    assert "--rollback-backup-sha256" in runbook
    assert "pointing v1 back to the old" in runbook
    assert "--acknowledge-writers-frozen" in rehearsal
    assert "--rollback-backup" in rehearsal
