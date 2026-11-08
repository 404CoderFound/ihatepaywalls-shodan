#!/bin/sh
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$ROOT"
COMPOSE=compose.staging.yaml
: "${STAGING_ADMIN_TOKEN:?Set a unique staging-only STAGING_ADMIN_TOKEN}"
: "${STAGING_ENROLLMENT_TOKEN:?Set a different staging-only STAGING_ENROLLMENT_TOKEN}"
PORT=${STAGING_PORT:-18080}
PROJECT=${STAGING_PROJECT:-scanlattice-v1-validation-$$}
STAGING_PORT=$PORT
STAGING_PROJECT=$PROJECT
export STAGING_ADMIN_TOKEN STAGING_ENROLLMENT_TOKEN STAGING_PORT STAGING_PROJECT
if ! command -v docker >/dev/null 2>&1; then echo 'Docker is required for container validation.' >&2; exit 2; fi
if ! docker compose version >/dev/null 2>&1; then echo 'Docker Compose v2 is required for container validation.' >&2; exit 2; fi
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
# Refuse to attach to pre-existing containers under an explicitly reused project.
existing=$(compose ps -q 2>/dev/null || true)
if [ -n "$existing" ]; then echo "Compose project $PROJECT already has containers; choose a fresh STAGING_PROJECT." >&2; exit 2; fi
volume_name="${PROJECT}_scanlattice_staging_data"
if docker volume inspect "$volume_name" >/dev/null 2>&1; then echo "Staging volume $volume_name already exists; choose a fresh STAGING_PROJECT to avoid reusing data." >&2; exit 2; fi
compose config --format json | python3 -c 'import json,sys; c=json.load(sys.stdin); assert set(c["services"])=={"web-staging"}; s=c["services"]["web-staging"]; assert all(p.get("host_ip")=="127.0.0.1" for p in s["ports"]); assert all(v.get("source")!="web_scanlattice_data" and v.get("source")!="worker_worker_state" for v in s.get("volumes",[])); assert all(not v.get("external",False) for v in c.get("volumes",{}).values()); print("Compose isolation config passed: one loopback web service, project-scoped named data volume, no production volumes.")'
cleanup() {
  if [ "${KEEP_STAGING:-false}" != "true" ]; then
    compose down >/dev/null 2>&1 || true
    printf 'Staging containers stopped; project-scoped data volume retained: %s_scanlattice_staging_data\n' "$PROJECT"
  else
    printf 'Staging left running under project %s on 127.0.0.1:%s\n' "$PROJECT" "$PORT"
  fi
}
trap cleanup EXIT INT TERM
compose up -d --build
attempt=0
while [ "$attempt" -lt 60 ]; do
  if curl --fail --silent "http://127.0.0.1:$PORT/api/health" >/dev/null; then break; fi
  attempt=$((attempt+1)); sleep 2
done
if [ "$attempt" -eq 60 ]; then echo 'Staging health check timed out.' >&2; exit 1; fi
curl --fail --silent "http://127.0.0.1:$PORT/api/stats" >/dev/null
STAGING_URL="http://127.0.0.1:$PORT" python3 scripts/staging_e2e.py
printf 'Staging container health, public API, release E2E and worker-protocol fixture validation passed. No target network connections were made.\n'
