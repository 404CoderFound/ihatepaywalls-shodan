#!/bin/sh
# Offline rehearsal from a PRIVATE SQLite backup already transferred to this Mac.
# NEVER run against a live production DB, server, Docker project or volume.
# This script never uses SSH, reads .env, or alters its input backup.
set -eu
umask 077
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$ROOT"

if [ "$#" -ne 1 ]; then
  echo "Usage: bash scripts/rehearse_postgresql_from_backup.sh /absolute/path/to/sqlite-backup.db" >&2
  exit 2
fi
for dependency in docker openssl python3; do
  command -v "$dependency" >/dev/null 2>&1 || {
    echo "Missing $dependency" >&2
    exit 2
  }
done
docker compose version >/dev/null 2>&1 || { echo "Docker Compose v2 required" >&2; exit 2; }

# Reject missing and repository-resident backups; Docker build sends repo
# contents as a context even when the Dockerfile does not COPY them.
BACKUP=$(python3 - "$1" <<'PY'
from pathlib import Path
import sys
path = Path(sys.argv[1]).expanduser().resolve()
if not path.is_file():
    sys.exit("Backup is missing or is not a regular file")
print(path)
PY
)
case "$BACKUP" in
  "$ROOT"|"$ROOT"/*)
    echo "Refusing a backup stored inside the Git checkout. Move it to a private directory outside the repo." >&2
    exit 2 ;;
esac

PROJECT="scanlattice-private-rehearsal-$(date +%s)-$$"
STAGING_PROJECT="$PROJECT"
STAGING_PORT=18083
STAGING_ADMIN_TOKEN="$(openssl rand -hex 32)"
STAGING_ENROLLMENT_TOKEN="$(openssl rand -hex 32)"
STAGING_POSTGRES_PASSWORD="$(openssl rand -hex 32)"
export STAGING_PROJECT STAGING_PORT STAGING_ADMIN_TOKEN STAGING_ENROLLMENT_TOKEN STAGING_POSTGRES_PASSWORD
WORK_DIR=$(mktemp -d /tmp/scanlattice-private-rehearsal.XXXXXX)

compose() {
  docker compose --env-file /dev/null -p "$PROJECT" -f compose.postgresql-staging.yaml "$@"
}
cleanup() {
  status=$?
  if [ "$status" -ne 0 ]; then
    echo "Migration rehearsal failed. Temporary container logs:" >&2
    compose logs --no-color --tail=50 >&2 || true
  fi
  compose down --volumes >/dev/null 2>&1 || true
  rm -rf "$WORK_DIR"
}
if [ -n "$(compose ps -q 2>/dev/null || true)" ] ||
   docker volume inspect "$PROJECT"_postgres_staging_data >/dev/null 2>&1; then
  echo "Staging project/volume already exists; refusing to reuse it." >&2
  exit 2
fi
trap cleanup EXIT

# Only copy from the read-only, outside-repo source into a disposable temp directory.
cp "$BACKUP" "$WORK_DIR/backup_original.sqlite"
chmod 600 "$WORK_DIR/backup_original.sqlite"

echo "Starting isolated local PostgreSQL (only port 127.0.0.1:$STAGING_PORT)"
# Check that Compose cannot attach arbitrary host paths / production volumes.
compose config --format json | python3 -c '
import json,sys
c=json.load(sys.stdin)
assert set(c["services"]) == {"postgres", "web-staging"}
assert not c["services"]["postgres"].get("ports")
assert all(p.get("host_ip")=="127.0.0.1" for p in c["services"]["web-staging"]["ports"])
assert all(not v.get("external",False) for v in c.get("volumes",{}).values())
assert all(v.get("source") not in {"web_scanlattice_data","worker_worker_state"} for s in c["services"].values() for v in s.get("volumes",[]))
print("PASS: loopback-only Compose, no external or production volumes")
'
compose up -d --build
WEB_IMAGE=$(compose images -q web-staging)
[ -n "$WEB_IMAGE" ] || { echo "Staging web image missing" >&2; exit 1; }

runner() {
  docker run --rm -i --user "$(id -u):$(id -g)" \
    --network "$PROJECT"_default \
    --volume "$ROOT:/repo:ro" \
    --volume "$WORK_DIR:/work" \
    --workdir /repo --env PYTHONPATH=/repo \
    --env DATABASE_BACKEND=postgresql --env DATABASE_SCHEMA=rehearsal \
    --env "DATABASE_URL=postgresql://scanlattice:$STAGING_POSTGRES_PASSWORD@postgres:5432/scanlattice" \
    --env PASSIVE_ENRICHMENT_ENABLED=false \
    --env MONITORING_AUTO_CHECKS=false \
    --env VULNERABILITY_AUTO_REFRESH=false \
    --env "ADMIN_TOKEN=$STAGING_ADMIN_TOKEN" \
    --env "ENROLLMENT_TOKEN=$STAGING_ENROLLMENT_TOKEN" \
    --env SEED_DEMO=false \
    "$WEB_IMAGE" "$@"
}

echo "Verifying and upgrading ONLY a disposable copy of the SQLite backup"
runner python - <<'PY'
import hashlib
import os
import shutil
import sqlite3
from pathlib import Path
from app import database

original = Path("/work/backup_original.sqlite")
# The offline SQLite snapshot may retain a WAL-mode database header.
# Even mode=ro can create -wal/-shm sidecars on close, causing the guarded
# production importer to reject this otherwise valid private backup.
# immutable=1 is safe here because this is a private, static backup COPY.
db = sqlite3.connect(f"file:{original}?mode=ro&immutable=1", uri=True)
try:
    assert db.execute("PRAGMA integrity_check").fetchone()[0] == "ok", "Backup failed SQLite integrity_check"
    tables = db.execute("SELECT COUNT(*) FROM sqlite_master WHERE type='table'").fetchone()[0]
    assert tables > 0, "Backup contains no tables"
finally:
    db.close()
# A staging-only read must not create WAL/journal sidecars on the approved
# original snapshot. Refuse to proceed if it does.
assert not any(Path(str(original) + ext).exists() for ext in ("-wal", "-shm", "-journal")), (
    "Frozen original backup unexpectedly acquired SQLite WAL/journal sidecars"
)
shutil.copyfile(original, "/work/rollback.sqlite")
shutil.copyfile(original, "/work/source.sqlite")
Path("/work/original.sha256").write_text(hashlib.sha256(original.read_bytes()).hexdigest())

os.environ["DATABASE_BACKEND"] = "sqlite"
database.DB_PATH = Path("/work/source.sqlite")
database.init_db(False)
with database.connection() as db:
    assert db.execute("PRAGMA integrity_check").fetchone()[0] == "ok"

src = Path("/work/source.sqlite")
Path("/work/source.sha256").write_text(hashlib.sha256(src.read_bytes()).hexdigest())
print("PASS: original SQLite backup intact; private copy migrated to current SQLite schema")
PY

echo "Importing private SQLite COPY into isolated PostgreSQL"
runner python /repo/scripts/migrate_sqlite_to_postgresql.py \
  /work/source.sqlite --schema rehearsal --batch-size 500 \
  --target-is-disposable-staging

echo "Verifying second import changes no data"
runner python /repo/scripts/migrate_sqlite_to_postgresql.py \
  /work/source.sqlite --schema rehearsal --batch-size 500 \
  --target-is-disposable-staging

echo "Comparing source/target table schemas, row counts and sampled host identities"
runner python - <<'PY'
import hashlib
import sqlite3
from pathlib import Path
from app.db_backend import PostgreSQLBackend
from scripts.migrate_sqlite_to_postgresql import quote_identifier, source_tables, target_columns

src = Path("/work/source.sqlite")
assert hashlib.sha256(src.read_bytes()).hexdigest() == Path("/work/source.sha256").read_text()
source = sqlite3.connect(f"file:{src}?mode=ro", uri=True)
target = PostgreSQLBackend().connect(Path("/tmp/unused.sqlite"))
try:
    tables = source_tables(source)
    errors = []
    for name in tables:
        ident = quote_identifier(name)
        columns = {r[1] for r in source.execute(f"PRAGMA table_info({ident})")}
        missing_columns = columns - target_columns(target, name)
        if missing_columns:
            errors.append(f"{name}: missing target columns {sorted(missing_columns)}")
        src_count = source.execute(f"SELECT COUNT(*) FROM {ident}").fetchone()[0]
        pg_count = target.execute(f"SELECT COUNT(*) FROM {ident}").fetchone()[0]
        if src_count != pg_count:
            errors.append(f"{name}: SQLite count {src_count}, PostgreSQL count {pg_count}")
    assert not errors, "Migration reconciliation failed:\n" + "\n".join(errors)
    sample = source.execute("SELECT ip,asn,org FROM hosts ORDER BY ip LIMIT 5").fetchall()
    for original in sample:
        migrated = target.execute(
            "SELECT ip,asn,org FROM hosts WHERE ip=?", (original[0],)
        ).fetchone()
        assert migrated is not None, "A sampled host is missing after migration"
        assert original == tuple(migrated[k] for k in ("ip","asn","org")), (
            "One sampled host has different values after migration"
        )
    status = target.execute("SELECT status FROM sqlite_migration_runs").fetchone()
    assert status and status[0] == "completed"
    print(f"PASS: {len(tables)} tables reconciled (schema and counts); {len(sample)} hosts checked; import ledger complete")
finally:
    target.close()
    source.close()
PY

echo "Testing the actual v2 API against the migrated PostgreSQL COPY"
runner python /repo/scripts/validate_migrated_postgresql_app.py

echo "Testing fake, non-scanning worker API contract on migrated PostgreSQL"
runner python /repo/scripts/validate_migrated_postgresql_worker_protocol.py

echo "Verifying guarded production importer in its OWN disposable schema"
FROZEN_SOURCE_SHA=$(cat "$WORK_DIR/original.sha256")
runner python /repo/scripts/import_production_sqlite_snapshot.py /work/backup_original.sqlite \
  --source-sha256 "$FROZEN_SOURCE_SHA" --expected-host postgres \
  --expected-database scanlattice --schema production_rehearsal
runner python /repo/scripts/import_production_sqlite_snapshot.py /work/backup_original.sqlite \
  --source-sha256 "$FROZEN_SOURCE_SHA" --expected-host postgres \
  --expected-database scanlattice --schema production_rehearsal \
  --execute --acknowledge-writers-frozen
echo "Verifying the guarded importer remains idempotent for the completed source"
runner python /repo/scripts/import_production_sqlite_snapshot.py /work/backup_original.sqlite \
  --source-sha256 "$FROZEN_SOURCE_SHA" --expected-host postgres \
  --expected-database scanlattice --schema production_rehearsal \
  --execute --acknowledge-writers-frozen

echo "Testing REST API against a separate disposable SQLite rollback COPY"
runner python - <<'PY'
import hashlib
import os
import sqlite3
from pathlib import Path

original = Path("/work/backup_original.sqlite")
assert hashlib.sha256(original.read_bytes()).hexdigest() == Path("/work/original.sha256").read_text(), "Original copy changed"
rollback = Path("/work/rollback.sqlite")
db = sqlite3.connect(rollback)
try:
    assert db.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
    host = db.execute("SELECT ip FROM hosts ORDER BY ip LIMIT 1").fetchone()
finally:
    db.close()
os.environ["DATABASE_BACKEND"] = "sqlite"
os.environ["DATABASE_PATH"] = str(rollback)
os.environ["ADMIN_TOKEN"] = "local-rehearsal-admin"
os.environ["ENROLLMENT_TOKEN"] = "local-rehearsal-enrollment"
os.environ["SEED_DEMO"] = "false"
from app import database
database.DB_PATH = rollback
from app.main import app
from fastapi.testclient import TestClient
with TestClient(app) as client:
    assert client.get("/api/health").status_code == 200
    if host is not None:
        assert client.get("/api/hosts/" + host[0]).status_code == 200
print("PASS: rollback SQLite copy and offline API smoke test")
PY

echo "PASS: private SQLite backup migration, schema/count checks, idempotence and rollback rehearsal"
echo "Original private backup left unchanged; temporary PostgreSQL will be removed"
