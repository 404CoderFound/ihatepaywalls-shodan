#!/bin/sh
# Local, disposable SQLite -> PostgreSQL migration and rollback rehearsal.
# Uses the checked-in v0.4 fixture only. Never reads .env or production volumes.
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$ROOT"
for command in docker openssl; do
  command -v "$command" >/dev/null 2>&1 || { echo "Missing $command" >&2; exit 2; }
done
docker compose version >/dev/null 2>&1 || { echo "Compose v2 is required" >&2; exit 2; }

PROJECT="scanlattice-pg-rehearsal-$(date +%s)-$$"
STAGING_PROJECT="$PROJECT"
STAGING_PORT=18083
STAGING_ADMIN_TOKEN="$(openssl rand -hex 32)"
STAGING_ENROLLMENT_TOKEN="$(openssl rand -hex 32)"
STAGING_POSTGRES_PASSWORD="$(openssl rand -hex 32)"
export STAGING_PROJECT STAGING_PORT STAGING_ADMIN_TOKEN STAGING_ENROLLMENT_TOKEN STAGING_POSTGRES_PASSWORD

WORK_DIR=$(mktemp -d /tmp/scanlattice-rehearsal.XXXXXX)
compose() {
  docker compose --env-file /dev/null -p "$PROJECT" -f compose.postgresql-staging.yaml "$@"
}
cleanup() {
  status=$?
  if [ "$status" -ne 0 ]; then
    echo "Rehearsal failed; staging container logs:" >&2
    compose logs --no-color --tail=80 >&2 || true
  fi
  compose down --volumes >/dev/null 2>&1 || true
  rm -rf "$WORK_DIR"
}
if [ -n "$(compose ps -q 2>/dev/null || true)" ] || docker volume inspect "$PROJECT"_postgres_staging_data >/dev/null 2>&1; then
  echo "Unexpected pre-existing staging resources; refusing to modify them" >&2
  exit 2
fi
trap cleanup EXIT
echo "Starting disposable, loopback-only PostgreSQL environment"
compose up -d --build
WEB_IMAGE=$(compose images -q web-staging)
[ -n "$WEB_IMAGE" ] || { echo "Web image missing" >&2; exit 1; }

runner() {
  docker run --rm -i --user "$(id -u):$(id -g)" \
    --network "$PROJECT"_default \
    --volume "$ROOT:/repo:ro" --volume "$WORK_DIR:/work" \
    --workdir /repo --env PYTHONPATH=/repo \
    --env DATABASE_BACKEND=postgresql --env DATABASE_SCHEMA=rehearsal \
    --env "DATABASE_URL=postgresql://scanlattice:$STAGING_POSTGRES_PASSWORD@postgres:5432/scanlattice" \
    --env PASSIVE_ENRICHMENT_ENABLED=false \
    --env MONITORING_AUTO_CHECKS=false --env VULNERABILITY_AUTO_REFRESH=false \
    --env SEED_DEMO=false "$WEB_IMAGE" "$@"
}

echo "Preparing an upgraded SQLite copy of the frozen v0.4 test fixture"
runner python - <<'PY'
import hashlib
import os
import shutil
import sqlite3
from pathlib import Path
from app import database

legacy = Path("/work/legacy.sqlite")
db = sqlite3.connect(legacy)
try:
    db.executescript(Path("/repo/tests/fixtures_v04_snapshot.sql").read_text())
finally:
    db.close()
os.environ["DATABASE_BACKEND"] = "sqlite"
database.DB_PATH = legacy
database.init_db(False)
with database.connection() as db:
    assert db.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
source = sqlite3.connect(legacy)
snapshot = sqlite3.connect("/work/source.sqlite")
try:
    source.backup(snapshot)
finally:
    snapshot.close()
    source.close()
shutil.copyfile("/work/source.sqlite", "/work/rollback.sqlite")
Path("/work/source.sha256").write_text(hashlib.sha256(Path("/work/source.sqlite").read_bytes()).hexdigest())
print("PASS: SQLite fixture upgrade and verified snapshot")
PY

echo "Running actual resumable SQLite-to-PostgreSQL importer"
runner python /repo/scripts/migrate_sqlite_to_postgresql.py \
  /work/source.sqlite --schema rehearsal --batch-size 2 --target-is-disposable-staging
echo "Verifying idempotent importer rerun"
runner python /repo/scripts/migrate_sqlite_to_postgresql.py \
  /work/source.sqlite --schema rehearsal --batch-size 2 --target-is-disposable-staging

echo "Checking all table counts and a representative host"
runner python - <<'PY'
import hashlib
import sqlite3
from pathlib import Path
from app.db_backend import PostgreSQLBackend
from scripts.migrate_sqlite_to_postgresql import quote_identifier, source_tables

src = Path("/work/source.sqlite")
assert hashlib.sha256(src.read_bytes()).hexdigest() == Path("/work/source.sha256").read_text(), "SQLite source changed"
source = sqlite3.connect(f"file:{src}?mode=ro", uri=True)
pg = PostgreSQLBackend().connect(Path("/tmp/unused.sqlite"))
try:
    tables = source_tables(source)
    mismatch = []
    for name in tables:
        ident = quote_identifier(name)
        a = source.execute(f"SELECT COUNT(*) FROM {ident}").fetchone()[0]
        b = pg.execute(f"SELECT COUNT(*) FROM {ident}").fetchone()[0]
        if a != b:
            mismatch.append((name, a, b))
    assert not mismatch, f"Table count differences (SQLite, PostgreSQL): {mismatch}"
    fixture_ip = "198.51.100.10"
    a = source.execute("SELECT ip,asn,org FROM hosts WHERE ip=?", (fixture_ip,)).fetchone()
    b = pg.execute("SELECT ip,asn,org FROM hosts WHERE ip=?", (fixture_ip,)).fetchone()
    assert a is not None and b is not None, "Fixture host missing after import"
    # SQLite row iteration yields values; PostgreSQLRow is a Mapping and
    # iteration yields column names. Compare the selected field values.
    columns = ("ip", "asn", "org")
    source_values = tuple(a[column] for column in columns)
    target_values = tuple(b[column] for column in columns)
    assert source_values == target_values, (
        f"Fixture host identity mismatch: SQLite={source_values!r}, PostgreSQL={target_values!r}"
    )
    run = pg.execute("SELECT status FROM sqlite_migration_runs").fetchone()
    assert run and run[0] == "completed"
    print(f"PASS: {len(tables)} migrated tables reconciled, fixture host and import ledger verified")
finally:
    pg.close()
    source.close()
PY

echo "Rehearsing SQLite rollback from a separate, untouched backup"
runner python - <<'PY'
import hashlib
import os
import sqlite3
from pathlib import Path
src = Path("/work/source.sqlite")
assert hashlib.sha256(src.read_bytes()).hexdigest() == Path("/work/source.sha256").read_text()
rollback = Path("/work/rollback.sqlite")
db = sqlite3.connect(rollback)
try:
    assert db.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
    assert db.execute("SELECT COUNT(*) FROM hosts WHERE ip='198.51.100.10'").fetchone()[0] == 1
finally:
    db.close()
os.environ["DATABASE_BACKEND"] = "sqlite"
os.environ["DATABASE_PATH"] = str(rollback)
os.environ["ADMIN_TOKEN"] = "fixture-only-admin-token"
os.environ["ENROLLMENT_TOKEN"] = "fixture-only-enrollment-token"
from app import database
database.DB_PATH = rollback
from app.main import app
from fastapi.testclient import TestClient
with TestClient(app) as client:
    assert client.get("/api/health").status_code == 200
    assert client.get("/api/hosts/198.51.100.10").status_code == 200
print("PASS: SQLite rollback copy integrity and app API smoke checks")
PY
echo "PASS: disposable import, repeat import, row reconciliation, and SQLite rollback rehearsal"
echo "No production server, credentials, or volumes accessed"
