from app.db_backend import PostgreSQLRow, _postgres_sql, _qmark_to_format


def test_postgresql_sql_translates_legacy_sql_features():
    assert _postgres_sql("INSERT OR IGNORE INTO passive_records(subject) VALUES(?)") == (
        "INSERT INTO passive_records(subject) VALUES(%s) ON CONFLICT DO NOTHING"
    )
    assert _postgres_sql("SELECT MIN(a,b), MAX(c,d) FROM t") == (
        "SELECT LEAST(a,b), GREATEST(c,d) FROM t"
    )
    assert _postgres_sql("SELECT INSTR(prefix,':') FROM t") == "SELECT POSITION(':' IN prefix) FROM t"
    assert _postgres_sql("SELECT json_extract(s.http_json,'$.title') FROM services s") == (
        "SELECT (s.http_json::jsonb #>> '{title}') FROM services s"
    )
    assert _postgres_sql("CREATE TABLE t(id INTEGER PRIMARY KEY AUTOINCREMENT, image BLOB)") == (
        "CREATE TABLE t(id BIGSERIAL PRIMARY KEY, image BYTEA)"
    )


def test_qmark_conversion_skips_quoted_question_marks():
    assert _qmark_to_format("SELECT '?', \"?\", value FROM t WHERE a=? AND b='it''s ?'") == (
        "SELECT '?', \"?\", value FROM t WHERE a=%s AND b='it''s ?'"
    )


def test_postgresql_row_keeps_sqlite_row_access_patterns():
    row = PostgreSQLRow(("id", "name"), (7, "fixture"))
    assert row[0] == 7 and row["name"] == "fixture"
    assert dict(row) == {"id": 7, "name": "fixture"}


def test_postgresql_executemany_keeps_cursor_when_psycopg_returns_none():
    """psycopg3 Cursor.executemany() returns None; the cursor itself is usable."""
    from app.db_backend import PostgreSQLConnection

    class FakePsycopgCursor:
        description = None
        rowcount = 0

        def executemany(self, statement, params):
            self.statement = statement
            self.params = list(params)
            self.rowcount = len(self.params)
            return None  # Matches the psycopg 3 API.

    class FakePsycopgConnection:
        def __init__(self):
            self.last_cursor = FakePsycopgCursor()

        def cursor(self):
            return self.last_cursor

    raw = FakePsycopgConnection()
    db = PostgreSQLConnection(raw)
    result = db.executemany(
        "INSERT INTO scan_profiles(name,ports) VALUES(?,?)",
        [("Web services", "80,443"), ("Conservative", "22,80,443")],
    )
    assert result.rowcount == 2
    assert raw.last_cursor.statement == "INSERT INTO scan_profiles(name,ports) VALUES(%s,%s)"
    assert raw.last_cursor.params == [
        ("Web services", "80,443"),
        ("Conservative", "22,80,443"),
    ]
