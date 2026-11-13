#!/usr/bin/env python3
"""Guarded SQLite snapshot -> new PostgreSQL candidate import.

Dry-run by default. This does NOT stop writers, deploy, or switch traffic.
Interrupted imports are rejected for manual recovery (SQLite upgrades may
produce different generated fields on subsequent runs).
"""
from __future__ import annotations

import argparse
import hashlib
import os
import re
import shutil
import sqlite3
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from scripts.migrate_sqlite_to_postgresql import migrate, quote_identifier, source_tables

REQUIRED_TABLES = frozenset({
    "hosts", "observations", "services", "workers", "scan_jobs",
    "authorizations", "passive_records", "scan_profiles",
})
FORBIDDEN_SOURCE_PATHS = (
    Path("/var/lib/docker/volumes/web_scanlattice_data"),
    Path("/opt/scanlattice/web"),
)
SCHEMA_PATTERN = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,62}\Z")
SHA_PATTERN = re.compile(r"[a-fA-F0-9]{64}\Z")
GO_REFERENCE_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._/-]{2,127}\Z")


def digest_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def inspect_frozen_source(path: Path, expected_sha: str) -> tuple[Path, tuple[int, int], int]:
    if not SHA_PATTERN.fullmatch(expected_sha):
        raise ValueError("--source-sha256 must be 64 hex digits")
    if path.is_symlink():
        raise ValueError("Refusing a symlinked SQLite source")
    source = path.resolve(strict=True)
    if ROOT in source.parents:
        raise ValueError("Refusing a SQLite source inside the code repository")
    if not source.is_file() or source.name == "scanlattice.db":
        raise ValueError("Refusing missing/non-file or live scanlattice.db source")
    if any(source == parent or parent in source.parents for parent in FORBIDDEN_SOURCE_PATHS):
        raise ValueError("Refusing source in known live application/volume path")
    st = source.stat()
    if st.st_mode & 0o077:
        raise ValueError("SQLite snapshot must not be group/world accessible")
    if st.st_nlink != 1:
        raise ValueError("Refusing a hard-linked SQLite source")
    if st.st_size < 4096:
        raise ValueError("SQLite snapshot unexpectedly small")
    if any(Path(str(source) + ext).exists() for ext in ("-wal", "-shm", "-journal")):
        raise ValueError("SQLite journal/WAL sidecars exist; use checkpointed backup")
    sig = st.st_size, st.st_mtime_ns
    if digest_file(source) != expected_sha.lower():
        raise ValueError("SQLite backup SHA-256 differs from approved checksum")
    db = sqlite3.connect(source.as_uri() + "?mode=ro&immutable=1", uri=True)
    try:
        if db.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
            raise ValueError("SQLite integrity_check failed")
        tables = {r[0] for r in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        if not REQUIRED_TABLES <= tables:
            raise ValueError("SQLite missing required ScanLattice tables")
        count = len(tables)
    finally:
        db.close()
    if (source.stat().st_size, source.stat().st_mtime_ns) != sig or digest_file(source) != expected_sha.lower():
        raise ValueError("SQLite source changed during preflight")
    return source, sig, count


def verify_snapshot_and_backup(snapshot_path: Path, snapshot_sha: str,
                               backup_path: Path, backup_sha: str) -> tuple[Path, tuple[int, int], int]:
    """Require a second, independently stored, integrity-checked rollback copy."""
    snapshot, sig, count = inspect_frozen_source(snapshot_path, snapshot_sha)
    backup, _, backup_count = inspect_frozen_source(backup_path, backup_sha)
    if snapshot == backup or os.path.samefile(snapshot, backup):
        raise ValueError("Migration snapshot and rollback backup must be separate files")
    if snapshot_sha.lower() != backup_sha.lower() or digest_file(snapshot) != digest_file(backup):
        raise ValueError("Verified rollback backup differs from the frozen snapshot SHA-256")
    if backup_count != count:
        raise ValueError("Snapshot and rollback backup table inventories differ")
    return snapshot, sig, count


def identity_and_state(conn, schema: str, expected_host: str, expected_database: str,
                       fingerprint: str, import_id: str) -> str:
    from psycopg.conninfo import conninfo_to_dict
    dsn = os.getenv("DATABASE_URL") or os.getenv("POSTGRES_DSN") or ""
    params = conninfo_to_dict(dsn)
    if not expected_host or not expected_database or not params.get("host") or not params.get("dbname"):
        raise ValueError("Explicit DSN host/dbname and expected host/database are required")
    if params["host"] != expected_host or params["dbname"] != expected_database:
        raise ValueError("PostgreSQL DSN does not match expected host/database")
    if conn.execute("SELECT current_database()").fetchone()[0] != expected_database:
        raise ValueError("Connected to unexpected PostgreSQL database")
    other_clients = conn.execute(
        "SELECT COUNT(*) FROM pg_stat_activity "
        "WHERE datname=current_database() AND backend_type='client backend' AND pid<>pg_backend_pid()"
    ).fetchone()[0]
    if other_clients:
        raise ValueError("Another PostgreSQL client is connected; refuse concurrent import")
    objects = conn.execute(
        "SELECT c.relname,c.relkind FROM pg_catalog.pg_class c "
        "JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace "
        "WHERE n.nspname=%s AND c.relkind IN ('r','p','v','m','S','f') ORDER BY c.relname",
        (schema,),
    ).fetchall()
    if not objects:
        return "empty"
    tables = {name for name, kind in objects if kind in ("r", "p")}
    if any(kind not in ("r", "p", "S") for _, kind in objects):
        raise ValueError("Target schema contains unsupported objects; refusing overwrite")
    sequences = {name for name, kind in objects if kind == "S"}
    owned_sequences = {row[0] for row in conn.execute(
        "SELECT seq.relname FROM pg_catalog.pg_class seq "
        "JOIN pg_catalog.pg_namespace ns ON ns.oid=seq.relnamespace "
        "JOIN pg_catalog.pg_depend dep ON dep.objid=seq.oid AND dep.deptype IN ('a','i') "
        "JOIN pg_catalog.pg_class tbl ON tbl.oid=dep.refobjid "
        "WHERE ns.nspname=%s AND seq.relkind='S' AND tbl.relnamespace=ns.oid",
        (schema,),
    ).fetchall()}
    if sequences != owned_sequences or not tables or "sqlite_migration_runs" not in tables:
        raise ValueError("Target schema already contains unrelated objects; refusing overwrite")
    rows = conn.execute(
        f'SELECT import_id,source_fingerprint,status FROM "{schema}".sqlite_migration_runs'
    ).fetchall()
    if len(rows) != 1 or tuple(rows[0]) != (import_id, fingerprint, "completed"):
        raise ValueError("Target contains interrupted/unrelated import; manual recovery required")
    return "completed"


def check_target(schema: str, host: str, dbname: str, fingerprint: str, import_id: str) -> str:
    from psycopg import connect
    dsn = os.getenv("DATABASE_URL") or os.getenv("POSTGRES_DSN")
    if not dsn:
        raise ValueError("DATABASE_URL or POSTGRES_DSN required")
    with connect(dsn) as conn:
        return identity_and_state(conn, schema, host, dbname, fingerprint, import_id)


def prepare_derived_copy(source: Path, scratch: Path, approved_sha: str) -> None:
    from app import database
    shutil.copyfile(source, scratch)
    if digest_file(source) != approved_sha:
        raise ValueError("Source changed during private copy")
    previous_backend = os.environ.get("DATABASE_BACKEND")
    previous_path = database.DB_PATH
    try:
        os.environ["DATABASE_BACKEND"] = "sqlite"
        database.DB_PATH = scratch
        database.init_db(seed_demo=False)
    finally:
        database.DB_PATH = previous_path
        if previous_backend is None:
            os.environ.pop("DATABASE_BACKEND", None)
        else:
            os.environ["DATABASE_BACKEND"] = previous_backend
    with sqlite3.connect(f"file:{scratch}?mode=ro", uri=True) as db:
        if db.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
            raise ValueError("Scratch upgrade failed SQLite integrity check")


def reconcile(scratch: Path, schema: str, import_id: str, fingerprint: str) -> int:
    from psycopg import connect
    dsn = os.getenv("DATABASE_URL") or os.getenv("POSTGRES_DSN")
    source = sqlite3.connect(f"file:{scratch}?mode=ro", uri=True)
    try:
        with connect(dsn) as conn:
            conn.execute(f'SET search_path TO "{schema}"')
            ledger = conn.execute(
                "SELECT status,source_fingerprint FROM sqlite_migration_runs WHERE import_id=%s",
                (import_id,),
            ).fetchone()
            if tuple(ledger or ()) != ("completed", fingerprint):
                raise RuntimeError("Approved import ledger is not completed")
            tables = source_tables(source)
            for name in tables:
                quoted = quote_identifier(name)
                source_cols = {r[1] for r in source.execute(f"PRAGMA table_info({quoted})")}
                target_cols = {r[0] for r in conn.execute(
                    "SELECT column_name FROM information_schema.columns "
                    "WHERE table_schema=%s AND table_name=%s", (schema, name)
                )}
                if not source_cols <= target_cols:
                    raise RuntimeError(f"Missing target columns: {name}")
                sqlite_count = source.execute(f"SELECT COUNT(*) FROM {quoted}").fetchone()[0]
                pg_count = conn.execute(f"SELECT COUNT(*) FROM {quoted}").fetchone()[0]
                if sqlite_count != pg_count:
                    raise RuntimeError(f"Row count mismatch in {name}: {sqlite_count} vs {pg_count}")
                if "id" in source_cols:
                    source_digest, source_max, source_ids = _sqlite_id_digest(source, name)
                    target_digest, target_max, target_ids = _postgres_id_digest(conn, schema, name)
                    if (source_digest, source_max, source_ids) != (target_digest, target_max, target_ids):
                        raise RuntimeError(f"Primary-key id reconciliation failed in {name}")
                    sequence_name = conn.execute(
                        "SELECT pg_get_serial_sequence(%s, 'id')",
                        (f'{quote_identifier(schema)}.{quote_identifier(name)}',),
                    ).fetchone()[0]
                    if sequence_name:
                        sequence_value = conn.execute(
                            "SELECT pg_sequence_last_value(%s::regclass)", (sequence_name,)
                        ).fetchone()[0]
                        if source_max is None:
                            if sequence_value is not None:
                                raise RuntimeError(f"Unexpected used identity sequence in empty table {name}")
                        elif sequence_value != source_max:
                            raise RuntimeError(f"Identity sequence is not aligned with imported ids in {name}")
            for ip, asn, org in source.execute("SELECT ip,asn,org FROM hosts ORDER BY ip LIMIT 5"):
                migrated = conn.execute("SELECT ip,asn,org FROM hosts WHERE ip=%s", (ip,)).fetchone()
                if tuple(migrated or ()) != (ip, asn, org):
                    raise RuntimeError("Host identity mismatch (values withheld)")
            return len(tables)
    finally:
        source.close()


def _sqlite_id_digest(source: sqlite3.Connection, table: str) -> tuple[str, int | None, int]:
    accumulator = 0
    cursor = source.execute(f"SELECT id FROM {quote_identifier(table)} ORDER BY id")
    count = 0
    maximum = None
    while rows := cursor.fetchmany(10000):
        for (value,) in rows:
            accumulator = (accumulator + int.from_bytes(
                hashlib.sha256(str(value).encode("utf-8")).digest(), "big"
            )) % (1 << 256)
            maximum = value
            count += 1
    return f"{accumulator:064x}", maximum, count


def _postgres_id_digest(conn, schema: str, table: str) -> tuple[str, int | None, int]:
    accumulator = 0
    count = 0
    maximum = None
    cursor_name = "scanlattice_ids_" + hashlib.sha1(f"{schema}.{table}".encode()).hexdigest()[:16]
    with conn.cursor(name=cursor_name) as cursor:
        cursor.execute(
            f"SELECT id FROM {quote_identifier(schema)}.{quote_identifier(table)} ORDER BY id"
        )
        while rows := cursor.fetchmany(10000):
            for (value,) in rows:
                accumulator = (accumulator + int.from_bytes(
                    hashlib.sha256(str(value).encode("utf-8")).digest(), "big"
                )) % (1 << 256)
                maximum = value
                count += 1
    return f"{accumulator:064x}", maximum, count


def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("sqlite_snapshot", type=Path)
    p.add_argument("--source-sha256", required=True)
    p.add_argument("--rollback-backup", type=Path, required=True,
                   help="separate, verified immutable SQLite rollback copy")
    p.add_argument("--rollback-backup-sha256", required=True)
    p.add_argument("--expected-host", required=True)
    p.add_argument("--expected-database", required=True)
    p.add_argument("--schema", default="public")
    p.add_argument("--batch-size", type=int, default=500)
    p.add_argument("--execute", action="store_true")
    p.add_argument("--acknowledge-writers-frozen", action="store_true")
    p.add_argument("--go-approval-reference",
                   help="change/ticket reference for the explicit migration GO approval")
    return p


def main(argv: list[str] | None = None) -> int:
    p = parser()
    args = p.parse_args(argv)
    if not SCHEMA_PATTERN.fullmatch(args.schema):
        p.error("Invalid PostgreSQL schema name")
    if not 1 <= args.batch_size <= 10000:
        p.error("--batch-size must be between 1 and 10000")
    if args.execute and not args.acknowledge_writers_frozen:
        p.error("--execute requires --acknowledge-writers-frozen")
    if args.execute and not GO_REFERENCE_PATTERN.fullmatch(args.go_approval_reference or ""):
        p.error("--execute requires a valid --go-approval-reference from the written GO approval")
    if args.go_approval_reference and not GO_REFERENCE_PATTERN.fullmatch(args.go_approval_reference):
        p.error("--go-approval-reference has an invalid format")
    source, sig, count = verify_snapshot_and_backup(
        args.sqlite_snapshot, args.source_sha256,
        args.rollback_backup, args.rollback_backup_sha256,
    )
    sha = args.source_sha256.lower()
    fingerprint = "sha256:" + sha
    import_id = "sqlite-prod-" + sha[:32]
    state = check_target(args.schema, args.expected_host, args.expected_database, fingerprint, import_id)
    print(f"Preflight PASS: detached SQLite backup, {count} source tables, SHA-256 verified")
    print(f"Target: host={args.expected_host}, db={args.expected_database}, schema={args.schema}, state={state}")
    if not args.execute:
        print("DRY RUN: no PostgreSQL application data created or changed")
        return 0
    with tempfile.TemporaryDirectory(prefix="scanlattice-prod-import-") as tmpdir:
        scratch = Path(tmpdir) / "upgraded.sqlite"
        prepare_derived_copy(source, scratch, sha)
        if (source.stat().st_size, source.stat().st_mtime_ns) != sig:
            raise ValueError("Frozen SQLite source changed after copy")
        state_again = check_target(args.schema, args.expected_host, args.expected_database, fingerprint, import_id)
        if state_again != state:
            raise RuntimeError("Target changed after preflight")
        if state == "empty":
            migrate(scratch, args.batch_size, args.schema, import_id, fingerprint)
        tables = reconcile(scratch, args.schema, import_id, fingerprint)
        if digest_file(source) != sha or digest_file(args.rollback_backup.resolve()) != args.rollback_backup_sha256.lower():
            raise RuntimeError("Frozen snapshot or rollback backup changed during import")
        print(f"PASS: guarded candidate import reconciled {tables} tables")
        print("Web traffic NOT switched; worker NOT started; preserve original SQLite backup")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"Production import PREVENTED/FAILED: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc
