#!/bin/sh
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$ROOT"
COMPOSE=compose.postgresql-staging.yaml
: "${STAGING_ADMIN_TOKEN:?Set a unique staging-only STAGING_ADMIN_TOKEN}"
: "${STAGING_ENROLLMENT_TOKEN:?Set a different staging-only STAGING_ENROLLMENT_TOKEN}"
: "${STAGING_POSTGRES_PASSWORD:?Set a staging-only STAGING_POSTGRES_PASSWORD}"
PORT=${STAGING_PORT:-18081}
PROJECT=${STAGING_PROJECT:-scanlattice-pg-validation-$$}
STAGING_PORT=$PORT
STAGING_PROJECT=$PROJECT
export STAGING_ADMIN_TOKEN STAGING_ENROLLMENT_TOKEN STAGING_POSTGRES_PASSWORD STAGING_PORT STAGING_PROJECT
if ! command -v docker >/dev/null 2>&1; then echo 'Docker is required for PostgreSQL staging validation.' >&2; exit 2; fi
if ! docker compose version >/dev/null 2>&1; then echo 'Docker Compose v2 is required for PostgreSQL staging validation.' >&2; exit 2; fi
case "$PORT" in *[!0-9]*|'') echo 'STAGING_PORT must be numeric.' >&2; exit 2;; esac
case "$PROJECT" in *[!a-z0-9_-]*|'') echo 'STAGING_PROJECT must contain lowercase letters, numbers, underscores, or hyphens.' >&2; exit 2;; esac
python3 - "$PORT" <<'PY'
import socket,sys
port=int(sys.argv[1]);sock=socket.socket()
try:sock.bind(("127.0.0.1",port))
except OSError:
 print(f"127.0.0.1:{port} is already occupied; choose a staging-only STAGING_PORT.",file=sys.stderr);sys.exit(2)
finally:sock.close()
PY
compose() { docker compose --env-file /dev/null -p "$PROJECT" -f "$COMPOSE" "$@"; }
existing=$(compose ps -q 2>/dev/null || true)
if [ -n "$existing" ]; then echo "Compose project $PROJECT already has containers; choose a fresh STAGING_PROJECT." >&2; exit 2; fi
volume_name="${PROJECT}_postgres_staging_data"
if docker volume inspect "$volume_name" >/dev/null 2>&1; then echo "Staging volume $volume_name already exists; choose a fresh STAGING_PROJECT." >&2; exit 2; fi
compose config --format json | python3 -c 'import json,sys; c=json.load(sys.stdin); assert set(c["services"])=={"postgres","web-staging"}; db=c["services"]["postgres"]; web=c["services"]["web-staging"]; assert not db.get("ports"); assert all(p.get("host_ip")=="127.0.0.1" for p in web["ports"]); assert web["environment"]["DATABASE_BACKEND"]=="postgresql"; assert all(v.get("source") not in {"web_scanlattice_data","worker_worker_state"} for s in c["services"].values() for v in s.get("volumes",[])); assert all(not v.get("external",False) for v in c.get("volumes",{}).values()); print("PostgreSQL staging isolation passed: private database network, loopback web port, project-scoped volume, no production volumes.")'
cleanup() {
  if [ "${KEEP_STAGING:-false}" != "true" ]; then
    compose down --volumes >/dev/null 2>&1 || true
    printf 'PostgreSQL staging containers and temporary project-scoped volume removed: %s_postgres_staging_data\n' "$PROJECT"
  else
    printf 'PostgreSQL staging left running under project %s on 127.0.0.1:%s\n' "$PROJECT" "$PORT"
  fi
}
trap cleanup EXIT INT TERM
compose up -d --build
attempt=0
while [ "$attempt" -lt 60 ]; do
  if curl --fail --silent "http://127.0.0.1:$PORT/api/health" >/dev/null; then break; fi
  attempt=$((attempt+1)); sleep 2
done
if [ "$attempt" -eq 60 ]; then echo 'PostgreSQL staging health check timed out.' >&2; compose logs --no-color --tail=150; exit 1; fi
curl --fail --silent "http://127.0.0.1:$PORT/api/stats" >/dev/null
STAGING_URL="http://127.0.0.1:$PORT" python3 scripts/staging_e2e.py
compose exec -T postgres psql -U scanlattice -d scanlattice -v ON_ERROR_STOP=1 -Atc "SELECT count(*) FROM schema_migrations" | python3 -c 'import sys; count=int(sys.stdin.read().strip()); assert count>=1, f"expected a schema migration, got {count}"; print(f"PostgreSQL schema migrations applied: {count}")'
printf 'PostgreSQL staging health, public API, release E2E, and schema migration checks passed. No target network connections were made.\n'
