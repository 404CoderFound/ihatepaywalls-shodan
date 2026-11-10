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
