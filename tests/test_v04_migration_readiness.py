import sqlite3
from pathlib import Path


def _table_counts(db):
    names=[row[0] for row in db.execute("SELECT name FROM sqlite_master WHERE type='table' AND name!='sqlite_sequence'")]
    return {name:db.execute(f'SELECT COUNT(*) FROM "{name}"').fetchone()[0] for name in names}


def test_frozen_v04_database_migration_preserves_existing_records(tmp_path,monkeypatch):
    import app.database as database
    target=tmp_path/"v04-before.db"
    legacy=sqlite3.connect(target)
    fixture=(Path(__file__).parent/"fixtures_v04_snapshot.sql").read_text()
    legacy.executescript(fixture);before=_table_counts(legacy)
    legacy_host=legacy.execute("SELECT ip,hostname,asn,org,country,first_seen,last_seen,last_scan_at FROM hosts WHERE ip='198.51.100.10'").fetchone()
    legacy_observation=legacy.execute("SELECT ip,port,proto,asn,source,banner,seen_at FROM observations WHERE ip='198.51.100.10'").fetchone()
    legacy_job=legacy.execute("SELECT id,target,status,progress_done,progress_total,completed_at FROM scan_jobs WHERE id='v04-job-01'").fetchone()
    legacy.close()

    monkeypatch.setattr(database,"DB_PATH",target)
    database.init_db(False)
    with database.connection() as migrated:
        after=_table_counts(migrated)
        # v1.0 seeds one additional, disabled passive-provider adapter.
        assert after["passive_providers"]==before["passive_providers"]+1
        for table,count in before.items():
            if table=="passive_providers":continue
            assert after[table]==count, f"row count changed for pre-existing v0.4 table {table}"
        assert tuple(migrated.execute("SELECT ip,hostname,asn,org,country,first_seen,last_seen,last_scan_at FROM hosts WHERE ip='198.51.100.10'").fetchone())==legacy_host
        assert tuple(migrated.execute("SELECT ip,port,proto,asn,source,banner,seen_at FROM observations WHERE ip='198.51.100.10'").fetchone())==legacy_observation
        assert tuple(migrated.execute("SELECT id,target,status,progress_done,progress_total,completed_at FROM scan_jobs WHERE id='v04-job-01'").fetchone())==legacy_job
        assert tuple(migrated.execute("SELECT service,product,source,banner FROM services WHERE host_ip='198.51.100.10' AND port=443").fetchone())==("https","nginx","v04-release-fixture","fixture banner from v0.4")
        assert migrated.execute("SELECT COUNT(*) FROM result_uploads WHERE idempotency_key='v04-result-key'").fetchone()[0]==1
        assert migrated.execute("SELECT COUNT(*) FROM campaign_jobs WHERE campaign_id='v04-campaign-01'").fetchone()[0]==1
        assert migrated.execute("SELECT COUNT(*) FROM passive_records WHERE source='v04-rdap-fixture'").fetchone()[0]==1
        assert migrated.execute("PRAGMA integrity_check").fetchone()[0]=="ok"
