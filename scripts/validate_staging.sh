#!/bin/sh
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$ROOT"
PROJECT=scanlattice-validation
COMPOSE=compose.staging.yaml
: "${STAGING_ADMIN_TOKEN:?Set a staging-only STAGING_ADMIN_TOKEN}"
: "${STAGING_ENROLLMENT_TOKEN:?Set a staging-only STAGING_ENROLLMENT_TOKEN}"
PORT=${STAGING_PORT:-18080}
if ! command -v docker >/dev/null 2>&1; then echo 'Docker is required for container validation.' >&2; exit 2; fi
STAGING_PORT=$PORT docker compose -p "$PROJECT" -f "$COMPOSE" config >/dev/null
STAGING_PORT=$PORT docker compose -p "$PROJECT" -f "$COMPOSE" up -d --build
cleanup() { STAGING_PORT=$PORT docker compose -p "$PROJECT" -f "$COMPOSE" down >/dev/null 2>&1 || true; }
trap cleanup EXIT INT TERM
attempt=0
while [ "$attempt" -lt 60 ]; do
  if curl --fail --silent "http://127.0.0.1:$PORT/api/health" >/dev/null; then break; fi
  attempt=$((attempt+1)); sleep 2
done
if [ "$attempt" -eq 60 ]; then echo 'Staging health check timed out.' >&2; exit 1; fi
curl --fail --silent "http://127.0.0.1:$PORT/api/stats" >/dev/null
printf 'Staging health and public stats passed on port %s. Named volume retained: scanlattice_staging_data.\n' "$PORT"
