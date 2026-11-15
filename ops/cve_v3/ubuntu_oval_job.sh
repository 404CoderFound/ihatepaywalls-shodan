#!/usr/bin/env bash
set -euo pipefail
# Run locally on a managed Ubuntu server. No remote scan, no guessed CPE.
CONF=/etc/scanlattice/ubuntu-oval.env
SCANLATTICE_HOST_IP=""
SCANLATTICE_EVIDENCE_SSH_DEST=""
SCANLATTICE_SSH_KEY=""
[[ -f "$CONF" ]] || { echo "Missing local Ubuntu OVAL configuration: $CONF"; exit 1; }
set -a
source "$CONF"
set +a
if [[ -z "$SCANLATTICE_HOST_IP" ]]; then
  echo "Set SCANLATTICE_HOST_IP in $CONF"; exit 1
fi
OUT=/var/lib/scanlattice-oval/host-evidence.json
python3 /usr/local/lib/scanlattice/cve_v3/vendor_oval.py \
  --ip "$SCANLATTICE_HOST_IP" --output "$OUT"
if [[ -n "$SCANLATTICE_EVIDENCE_SSH_DEST" ]]; then
  # Configure a dedicated SSH key and pinned known_hosts out-of-band.
  # No insecure StrictHostKeyChecking=no.
  [[ -f "$SCANLATTICE_SSH_KEY" ]] || {
    echo "SSH evidence key missing; local report retained"; exit 1; }
  scp -q -o BatchMode=yes -o StrictHostKeyChecking=yes \
    -o ConnectTimeout=15 -i "$SCANLATTICE_SSH_KEY" "$OUT" \
    "$SCANLATTICE_EVIDENCE_SSH_DEST"
  echo "Uploaded local OVAL result to configured ScanLattice SSH inbox"
else
  echo "No SSH destination configured; local OVAL result available at $OUT"
fi
