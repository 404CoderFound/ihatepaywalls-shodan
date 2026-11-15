#!/usr/bin/env bash
set -euo pipefail
# Install only. No production image modification, scanning, or timer activation
# unless --enable explicitly requested.
ROOT="$(cd "$(dirname "$0")" && pwd)"
DEST="/usr/local/lib/scanlattice/cve_v2"
ACTION="install"
if (( $# > 0 )); then ACTION="$1"; fi
[[ "$ACTION" == "install" || "$ACTION" == "--enable" || "$ACTION" == "--disable" ]] || {
  echo "Usage: sudo bash install.sh [install|--enable|--disable]"; exit 2;
}
[[ "$EUID" -eq 0 ]] || { echo "Run as root with sudo"; exit 1; }
if [[ "$ACTION" == "--disable" ]]; then
  systemctl disable --now scanlattice-cve-v2-refresh.timer scanlattice-cve-v2-assess.timer || true
  echo "ScanLattice CVE V2 timers disabled. Data and reports retained."
  exit 0
fi
command -v docker >/dev/null
command -v python3 >/dev/null
python3 -c 'import ijson' || { echo "Install Debian python3-ijson first"; exit 1; }
python3 - <<'PY'
import json
from pathlib import Path
path=Path("/var/lib/scanlattice-cve/nvd-feeds.state.json")
assert path.exists() and json.loads(path.read_text()).get("complete") is True, "Full NVD feed import incomplete"
PY
[[ -f /etc/scanlattice/v2-prodweb/admin-token ]] || { echo "Missing control-plane token"; exit 1; }
IMAGE="$(docker inspect -f '{{.Config.Image}}' scanlattice-v2-prodweb-web-1)"
[[ "$IMAGE" == "scanlattice-prodweb:cve-bulk-v1" ]] || {
  echo "Production image is $IMAGE, expected cve-bulk-v1. No changes made."; exit 1;
}
python3 -m unittest discover -s "$ROOT" -p "test_applicability.py" -v
install -d -m 0755 "$DEST"
install -d -m 0700 /var/lib/scanlattice-cve
install -m 0644 "$ROOT/applicability.py" "$DEST/applicability.py"
install -m 0755 "$ROOT/runner.py" "$DEST/runner.py"
ln -sfn "$DEST/runner.py" /usr/local/sbin/scanlattice-cve-v2

cat > /etc/systemd/system/scanlattice-cve-v2-refresh.service <<'EOF'
[Unit]
Description=ScanLattice updated NVD/CISA feed import with full applicability preservation
Wants=network-online.target docker.service
After=network-online.target docker.service

[Service]
Type=oneshot
User=root
ExecStart=/usr/local/sbin/scanlattice-cve-v2 refresh
TimeoutStartSec=0
NoNewPrivileges=true
EOF
cat > /etc/systemd/system/scanlattice-cve-v2-refresh.timer <<'EOF'
[Unit]
Description=Hourly ScanLattice NVD and CISA KEV updates

[Timer]
OnCalendar=hourly
RandomizedDelaySec=10m
Persistent=true
Unit=scanlattice-cve-v2-refresh.service

[Install]
WantedBy=timers.target
EOF
cat > /etc/systemd/system/scanlattice-cve-v2-assess.service <<'EOF'
[Unit]
Description=Read-only ScanLattice CVE applicability reassessment
After=docker.service
Wants=docker.service

[Service]
Type=oneshot
User=root
ExecStart=/usr/local/sbin/scanlattice-cve-v2 assess
TimeoutStartSec=0
NoNewPrivileges=true
EOF
cat > /etc/systemd/system/scanlattice-cve-v2-assess.timer <<'EOF'
[Unit]
Description=Reassess scanned host CPEs every 20 minutes and overnight

[Timer]
OnCalendar=*:0/20
Persistent=true
Unit=scanlattice-cve-v2-assess.service

[Install]
WantedBy=timers.target
EOF
systemctl daemon-reload
echo "Installed. No active scan scheduled; website unchanged."
echo "Next: sudo scanlattice-cve-v2 index"
echo "Then: sudo scanlattice-cve-v2 assess"
if [[ "$ACTION" == "--enable" ]]; then
  if systemctl is-enabled --quiet scanlattice-cve-sync.timer 2>/dev/null; then
    echo "Old scanlattice-cve-sync.timer is enabled; disable it manually first."
    exit 1
  fi
  [[ -s /var/lib/scanlattice-cve/applicability-v2-report.json ]] || {
    echo "Run initial index and assessment before enabling."; exit 1;
  }
  systemctl enable --now scanlattice-cve-v2-refresh.timer scanlattice-cve-v2-assess.timer
  echo "Hourly CVE refresh and 20-minute read-only reassessment enabled."
fi
