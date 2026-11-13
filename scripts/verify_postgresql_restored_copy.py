#!/usr/bin/env python3
"""Compare isolated pg_dump/pg_restore schema data inside the disposable Mac rehearsal.

NO writes. The backup and restored database are both in the same disposable
PostgreSQL Docker project, never in production.
"""
from __future__ import annotations

import os
from psycopg import connect, sql
from psycopg.conninfo import conninfo_to_dict, make_conninfo

dsn = os.environ.get("DATABASE_URL", "")
params = conninfo_to_dict(dsn)
assert params.get("host") == "postgres", "Only the disposable Compose PostgreSQL hostname is allowed"
assert params.get("dbname") == "scanlattice", "Unexpected source PostgreSQL database"
assert os.environ.get("DATABASE_BACKEND") == "postgresql"
assert os.environ.get("DATABASE_SCHEMA") == "rehearsal"
assert os.environ.get("SEED_DEMO") == "false"
schema = "production_rehearsal"
restored_dbname = "scanlattice_restore"


def tables(connection) -> tuple[str, ...]:
    return tuple(row[0] for row in connection.execute(
        "SELECT tablename FROM pg_catalog.pg_tables "
        "WHERE schemaname=%s ORDER BY tablename", (schema,)
    ))


def fingerprints(connection, names: tuple[str, ...]) -> dict[str, tuple[int, str]]:
    result = {}
    for table in names:
        query = sql.SQL("""
            SELECT COUNT(*),
                   MD5(COALESCE(
                     STRING_AGG(MD5(TO_JSONB(t)::text), ''
                       ORDER BY MD5(TO_JSONB(t)::text)), ''))
            FROM {} AS t
        """).format(sql.Identifier(schema, table))
        count, digest = connection.execute(query).fetchone()
        result[table] = (int(count), digest)
    return result


def sequences(connection) -> tuple[tuple[str, int | None], ...]:
    return tuple(connection.execute(
        "SELECT sequencename,last_value FROM pg_catalog.pg_sequences "
        "WHERE schemaname=%s ORDER BY sequencename", (schema,)
    ).fetchall())


with (
    connect(dsn) as original,
    connect(make_conninfo(dsn, dbname=restored_dbname)) as restored,
):
    assert original.info.dbname == "scanlattice"
    assert restored.info.dbname == restored_dbname
    assert original.info.dbname != restored.info.dbname

    original_tables = tables(original)
    restored_tables = tables(restored)
    assert len(original_tables) >= 40, "Unexpectedly few source PostgreSQL tables"
    assert original_tables == restored_tables, "Restored table inventory differs"

    before = fingerprints(original, original_tables)
    after = fingerprints(restored, restored_tables)
    for name in original_tables:
        assert before[name] == after[name], (
            f"Restored PostgreSQL row count/hash differs for {name}"
        )

    original_sequences = sequences(original)
    restored_sequences = sequences(restored)
    assert original_sequences == restored_sequences, (
        "PostgreSQL sequence names / last values differ after restore"
    )

    ledger = restored.execute(sql.SQL(
        "SELECT COUNT(*) FROM {} WHERE status='completed'"
    ).format(sql.Identifier(schema, "sqlite_migration_runs"))).fetchone()[0]
    assert ledger >= 1, "Restored migration ledger is incomplete"

    print(
        "PASS: pg_dump archive restored into isolated second PostgreSQL database; "
        f"{len(original_tables)} tables with identical counts and content hashes, "
        f"{len(original_sequences)} sequences reconciled, import ledger intact"
    )
