#!/usr/bin/env python3
"""Stream a consistent SQLite snapshot into an empty PostgreSQL staging schema.

The source is opened read-only and copied through SQLite's online backup API.
Each target batch and its source rowid cursor commit together, making retries
safe after interruption. The command refuses to run without an explicit
disposable-staging acknowledgement.
"""
from __future__ import annotations

import argparse
import hashlib
import os
import re
import sqlite3
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from app import database
from app.db_backend import PostgreSQLBackend


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def fingerprint(path: Path) -> tuple[str, str]:
    stat = path.stat()
    identity = f"{path.resolve()}:{stat.st_size}:{stat.st_mtime_ns}"
    digest = hashlib.sha256(identity.encode()).hexdigest()
    return f"sqlite-{digest[:32]}", identity


def quote_identifier(name: str) -> str:
    return '"' + name.replace('"', '""') + '"'


def source_tables(source: sqlite3.Connection) -> list[str]:
    tables = [row[0] for row in source.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name"
    )]
    dependencies: dict[str, set[str]] = {table: set() for table in tables}
    for table in tables:
        for foreign_key in source.execute(f"PRAGMA foreign_key_list({quote_identifier(table)})"):
            parent = foreign_key[2]
            if parent in dependencies and parent != table:
                dependencies[table].add(parent)
    ordered: list[str] = []
    pending = set(tables)
    while pending:
        ready = sorted(table for table in pending if not (dependencies[table] & pending))
        if not ready:
            raise RuntimeError(f"Foreign-key cycle in SQLite source tables: {sorted(pending)}")
        ordered.extend(ready)
        pending.difference_update(ready)
    return ordered


def target_columns(db, table: str) -> set[str]:
    return {row[0] for row in db.execute(
        "SELECT column_name FROM information_schema.columns WHERE table_schema=current_schema() AND table_name=?",
        (table,),
    )}


def target_has_table(db, table: str) -> bool:
    """Check table existence from its column metadata, not its table name."""
    return bool(target_columns(db, table))

def copy_snapshot(source: sqlite3.Connection, snapshot_path: Path) -> None:
    snapshot = sqlite3.connect(snapshot_path)
    try:
        source.backup(snapshot, pages=1000, sleep=0.05)
        snapshot.commit()
    finally:
        snapshot.close()


def migrate(snapshot_path: Path, batch_size: int, schema: str,
            import_id: str, source_fingerprint: str) -> None:
    if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,62}", schema):
        raise ValueError("Invalid PostgreSQL schema name")
    os.environ["DATABASE_BACKEND"] = "postgresql"
    os.environ["DATABASE_SCHEMA"] = schema
    os.environ["SEED_DEMO"] = "false"
    database.DB_PATH = Path(tempfile.gettempdir()) / "scanlattice-postgresql-unused.db"

    # Bootstrap only the target schema and seed defaults; they are removed on
    # a fresh import so source primary keys and service ids remain unchanged.
    database.init_db(seed_demo=False)
    backend = PostgreSQLBackend()
    target = backend.connect(database.DB_PATH)
    backend.configure(target)
    source = sqlite3.connect(f"file:{snapshot_path}?mode=ro", uri=True)
    source.row_factory = sqlite3.Row
    try:
        run = target.execute("SELECT status,source_fingerprint FROM sqlite_migration_runs WHERE import_id=?", (import_id,)).fetchone()
        if run and run["source_fingerprint"] != source_fingerprint:
            raise RuntimeError("Import id is already associated with a different SQLite source")
        if run and run["status"] == "completed":
            print(f"Import {import_id} is already complete; no rows changed.")
            return
        if not run:
            occupied = []
            for table in source_tables(source):
                # target_columns() returns COLUMN names, not table names.
                # A non-empty result means the source table exists in the
                # currently selected, disposable PostgreSQL schema.
                if not target_has_table(target, table):
                    raise RuntimeError(f"Target migration is missing source table {table!r}")
                if table not in {"scan_profiles", "passive_providers"}:
                    count = target.execute(f'SELECT COUNT(*) FROM "{table}"').fetchone()[0]
                    if count:
                        occupied.append(table)
            if occupied:
                raise RuntimeError(f"Target PostgreSQL schema contains application data: {occupied}. Use a fresh staging schema.")
            target.execute("DELETE FROM scan_profiles")
            target.execute("DELETE FROM passive_providers")
            now = utc_now()
            target.execute(
                "INSERT INTO sqlite_migration_runs(import_id,source_fingerprint,status,started_at,updated_at) VALUES(?,?,'running',?,?)",
                (import_id, source_fingerprint, now, now),
            )
            target.commit()

        for table in source_tables(source):
            source_columns = [row[1] for row in source.execute(f"PRAGMA table_info({quote_identifier(table)})")]
            common_columns = [column for column in source_columns if column in target_columns(target, table)]
            if not common_columns:
                continue
            checkpoint = target.execute(
                "SELECT last_source_rowid,rows_imported FROM sqlite_migration_cursors WHERE import_id=? AND table_name=?",
                (import_id, table),
            ).fetchone()
            last_rowid = int(checkpoint["last_source_rowid"]) if checkpoint else 0
            total = int(checkpoint["rows_imported"]) if checkpoint else 0
            names_sql = ",".join(quote_identifier(name) for name in common_columns)
            placeholders = ",".join("?" for _ in common_columns)
            quoted_table = quote_identifier(table)
            insert_sql = f'INSERT INTO {quoted_table}({names_sql}) VALUES({placeholders}) ON CONFLICT DO NOTHING'
            while True:
                rows = source.execute(
                    f'SELECT rowid,{names_sql} FROM {quoted_table} WHERE rowid>? ORDER BY rowid LIMIT ?',
                    (last_rowid, batch_size),
                ).fetchall()
                if not rows:
                    break
                cursor = target.executemany(insert_sql, [tuple(row[column] for column in common_columns) for row in rows])
                if cursor.rowcount != len(rows):
                    raise RuntimeError(f"Unexpected duplicate/conflicting rows while importing {table}: {len(rows)-cursor.rowcount} skipped")
                last_rowid = int(rows[-1][0])
                total += len(rows)
                now = utc_now()
                target.execute(
                    """INSERT INTO sqlite_migration_cursors(import_id,table_name,last_source_rowid,rows_imported,updated_at)
                       VALUES(?,?,?,?,?) ON CONFLICT(import_id,table_name) DO UPDATE SET
                       last_source_rowid=excluded.last_source_rowid,rows_imported=excluded.rows_imported,updated_at=excluded.updated_at""",
                    (import_id, table, last_rowid, total, now),
                )
                target.execute("UPDATE sqlite_migration_runs SET updated_at=? WHERE import_id=?", (now, import_id))
                target.commit()
                print(f"{table}: {total} rows copied through source rowid {last_rowid}", flush=True)
        target.execute("UPDATE sqlite_migration_runs SET status='copied',updated_at=? WHERE import_id=?", (utc_now(), import_id))
        target.commit()
    finally:
        source.close()
        target.close()

    # Reconcile derived host/service rows and normalized values after the source
    # tables have been copied, then align BIGSERIAL sequences to imported ids.
    database.init_db(seed_demo=False)
    target = backend.connect(database.DB_PATH)
    try:
        source_for_sequences = sqlite3.connect(f"file:{snapshot_path}?mode=ro", uri=True)
        try:
            tables = source_tables(source_for_sequences)
        finally:
            source_for_sequences.close()
        for table in tables:
            if "id" not in target_columns(target, table):
                continue
            sequence = target.execute("SELECT pg_get_serial_sequence(?, 'id')", (table,)).fetchone()[0]
            if sequence:
                target.execute(
                    f"SELECT setval(?::regclass, GREATEST(COALESCE(MAX(id),1),1), COUNT(*)>0) FROM {quote_identifier(table)}",
                    (sequence,),
                )
        target.execute("UPDATE sqlite_migration_runs SET status='completed',updated_at=?,completed_at=? WHERE import_id=?", (utc_now(), utc_now(), import_id))
        target.commit()
    finally:
        target.close()
    print(f"SQLite snapshot import complete: {import_id}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("sqlite_database", type=Path)
    parser.add_argument("--batch-size", type=int, default=1000)
    parser.add_argument("--schema", default=os.getenv("DATABASE_SCHEMA", "public"))
    parser.add_argument("--target-is-disposable-staging", action="store_true",
                        help="confirm that DATABASE_URL points only to disposable, isolated staging")
    args = parser.parse_args()
    if not args.target_is_disposable_staging:
        parser.error("--target-is-disposable-staging is required; this command never migrates production")
    if not args.sqlite_database.is_file():
        parser.error(f"SQLite database does not exist: {args.sqlite_database}")
    if not 1 <= args.batch_size <= 10000:
        parser.error("--batch-size must be between 1 and 10000")
    if not (os.getenv("DATABASE_URL") or os.getenv("POSTGRES_DSN")):
        parser.error("DATABASE_URL is required for the PostgreSQL staging target")

    import_id, source_fingerprint = fingerprint(args.sqlite_database)
    with tempfile.TemporaryDirectory(prefix="scanlattice-sqlite-snapshot-") as temp_dir:
        snapshot_path = Path(temp_dir) / "source.sqlite"
        original = sqlite3.connect(f"file:{args.sqlite_database.resolve()}?mode=ro", uri=True)
        try:
            copy_snapshot(original, snapshot_path)
        finally:
            original.close()
        migrate(snapshot_path, args.batch_size, args.schema, import_id, source_fingerprint)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"SQLite to PostgreSQL migration failed: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc
