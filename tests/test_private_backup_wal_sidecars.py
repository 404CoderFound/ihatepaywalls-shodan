"""Regression: WAL-mode SQLite online backups must not acquire sidecars.

A regular 'mode=ro' opener may create -wal/-shm even when no statements write.
The rehearsal must read the immutable, private backup copy with immutable=1.
"""
from pathlib import Path
import sqlite3


def test_rehearsal_original_backup_read_never_creates_wal_sidecars(tmp_path):
    source = tmp_path / "live_source.db"
    snapshot = tmp_path / "backup_original.sqlite"
    with sqlite3.connect(source) as live:
        assert live.execute("PRAGMA journal_mode=WAL").fetchone()[0] == "wal"
        live.execute("CREATE TABLE data(id INTEGER PRIMARY KEY, label TEXT)")
        live.execute("INSERT INTO data VALUES(1,'fixture')")
        live.commit()  # Finish WAL transaction before taking online backup.
        with sqlite3.connect(snapshot) as backup:
            live.backup(backup)
    assert snapshot.read_bytes()[18:20] == bytes([2, 2])  # SQLite WAL header
    sidecars = [Path(str(snapshot) + ext) for ext in ("-wal", "-shm", "-journal")]
    assert not any(path.exists() for path in sidecars)

    with sqlite3.connect(f"file:{snapshot}?mode=ro&immutable=1", uri=True) as conn:
        assert conn.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
        assert conn.execute("SELECT label FROM data").fetchone()[0] == "fixture"
    assert not any(path.exists() for path in sidecars)


def test_rehearsal_guards_the_actual_original_snapshot(tmp_path):
    script = (Path(__file__).resolve().parents[1] / "scripts" /
              "rehearse_postgresql_from_backup.sh").read_text()
    assert 'sqlite3.connect(f"file:{original}?mode=ro&immutable=1", uri=True)' in script
    assert 'Frozen original backup unexpectedly acquired SQLite WAL/journal sidecars' in script
