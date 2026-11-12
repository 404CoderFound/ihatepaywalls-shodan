"""Static safety regression checks for the disposable PostgreSQL restore rehearsal."""
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_restore_drill_never_invokes_production_compose():
    script = (ROOT / "scripts" / "rehearse_postgresql_from_backup.sh").read_text()
    segment = script.split("Backing up the guarded-import schema")[1].split(
        'echo "Testing REST API against a separate disposable SQLite rollback COPY"'
    )[0]
    assert 'compose exec -T postgres pg_dump' in segment
    assert 'compose exec -T postgres pg_restore' in segment
    assert 'compose exec -T postgres createdb' in segment
    assert '--no-owner --no-acl' in segment
    assert '--exit-on-error' in segment
    assert '--schema=production_rehearsal' in segment
    assert 'runner python /repo/scripts/verify_postgresql_restored_copy.py' in segment
    assert 'docker compose -p web' not in segment
    assert 'web_scanlattice_data' not in segment
    assert 'worker_worker_state' not in segment


def test_restore_validator_requires_separate_databases():
    script = (ROOT / "scripts" / "verify_postgresql_restored_copy.py").read_text()
    assert 'restored_dbname = "scanlattice_restore"' in script
    assert 'original.info.dbname != restored.info.dbname' in script
    assert 'params.get("host") == "postgres"' in script
    assert 'TO_JSONB(t)::text' in script
    assert 'pg_catalog.pg_sequences' in script
