#!/usr/bin/env bash
set -euo pipefail
# Debian reconciliation: new fingerprints -> V2 index assessment -> OVAL merge
# -> main site overlay -> operational health.
exec 9>/run/lock/scanlattice-cve-v3-reconcile.lock
flock -n 9 || { echo "Reconciliation already running"; exit 0; }

CODE=/usr/local/lib/scanlattice/cve_v3
CID=scanlattice-v2-prodweb-web-1
docker inspect "$CID" >/dev/null

echo "Importing fresh authenticated-host OVAL evidence"
python3 "$CODE/vendor_import.py"

echo "Enriching only explicitly versioned services (existing CPEs untouched)"
docker exec -e APPLY=1 -i "$CID" python - < "$CODE/fingerprint.py"

echo "Reassessing full NVD configuration index"
scanlattice-cve-v2 assess

echo "Reconciling fresh vendor evidence against remote-only findings"
python3 "$CODE/merge_report.py"

echo "Publishing updated V3 main-site panel with production backup"
python3 "$CODE/publish.py" install

echo "Checking pipeline health"
python3 "$CODE/doctor.py" --role debian \
  --output /var/lib/scanlattice-cve/pipeline-health.json || true
