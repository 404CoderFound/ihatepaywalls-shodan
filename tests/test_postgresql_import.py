import sqlite3

from scripts.migrate_sqlite_to_postgresql import copy_snapshot, quote_identifier, source_tables


def test_source_table_order_follows_foreign_keys_and_quotes_names(tmp_path):
    source_path = tmp_path / "source.sqlite"
    source = sqlite3.connect(source_path)
    source.executescript('''
        CREATE TABLE "parent table" (id INTEGER PRIMARY KEY);
        CREATE TABLE child (id INTEGER PRIMARY KEY, parent_id INTEGER REFERENCES "parent table"(id));
    ''')
    assert source_tables(source) == ["parent table", "child"]
    assert quote_identifier('a"b') == '"a""b"'
    source.close()


def test_sqlite_backup_snapshot_is_readable_and_independent(tmp_path):
    source_path = tmp_path / "source.sqlite"
    snapshot_path = tmp_path / "snapshot.sqlite"
    source = sqlite3.connect(source_path)
    source.execute("CREATE TABLE observations(id INTEGER PRIMARY KEY, banner TEXT)")
    source.execute("INSERT INTO observations VALUES(1,'fixture')")
    source.commit()

    copy_snapshot(source, snapshot_path)
    source.execute("UPDATE observations SET banner='changed'")
    source.commit()
    copied = sqlite3.connect(snapshot_path)
    assert copied.execute("SELECT banner FROM observations").fetchone()[0] == "fixture"
    copied.close()
    source.close()


def test_target_has_table_checks_columns_not_table_name():
    """A normal PostgreSQL table exposes column names, never its own table name."""
    from scripts.migrate_sqlite_to_postgresql import target_has_table

    class FakeConnection:
        def execute(self, sql, params):
            assert "information_schema.columns" in sql
            assert "table_schema=current_schema()" in sql
            assert len(params) == 1
            return [("token_hash",), ("created_at",)] if params[0] == "admin_sessions" else []

    db = FakeConnection()
    assert target_has_table(db, "admin_sessions")
    assert not target_has_table(db, "nonexistent_table")
