#!/usr/bin/env bash
set -euo pipefail
# Run on AWS EC2. Installs code and timer, but does not enable active scans
# until --enable is given AND explicit authorized_cidrs are configured.
ROOT="$(cd "$(dirname "$0")" && pwd)"
ACTION="install"
if (( $# > 0 )); then ACTION="$1"; fi
[[ "$ACTION" == "install" || "$ACTION" == "--enable" || "$ACTION" == "--disable" ]] || {
  echo "Usage: sudo bash install.sh [install|--enable|--disable]"; exit 2;
}
[[ $EUID -eq 0 ]] || { echo "Run as root via sudo"; exit 1; }
if [[ "$ACTION" == "--disable" ]]; then
  systemctl disable --now scanlattice-inventory-rescan.timer || true
  echo "Nightly AWS inventory rescan disabled; scanner jobs already queued remain separate."
  exit 0
fi
test -x /usr/local/bin/scanlattice-v3 || { echo "Go scanner v3 missing"; exit 1; }
test -f /etc/scanlattice-v3/config.json || { echo "Scanner config missing"; exit 1; }
python3 -m unittest discover -s "$ROOT" -p "test_nightly.py" -v
install -d -m 0755 /usr/local/lib/scanlattice/inventory_rescan
install -m 0644 "$ROOT/nightly.py" /usr/local/lib/scanlattice/inventory_rescan/nightly.py
cat >/usr/local/sbin/scanlattice-inventory-rescan <<'EOF'
#!/bin/sh
exec /usr/bin/python3 /usr/local/lib/scanlattice/inventory_rescan/nightly.py "$@"
EOF
chmod 0755 /usr/local/sbin/scanlattice-inventory-rescan
install -d -m 0750 /etc/scanlattice-v3
if [[ ! -e /etc/scanlattice-v3/inventory-rescan.json ]]; then
  install -m 0600 "$ROOT/config.example.json" /etc/scanlattice-v3/inventory-rescan.json
fi

cat >/etc/systemd/system/scanlattice-inventory-rescan.service <<'EOF'
[Unit]
Description=Queue night-time scans for all explicitly authorized indexed ScanLattice hosts
Wants=network-online.target scanlattice-v3.service
After=network-online.target scanlattice-v3.service

[Service]
Type=oneshot
User=root
ExecStart=/usr/local/sbin/scanlattice-inventory-rescan --enqueue
TimeoutStartSec=0
NoNewPrivileges=true
EOF
cat >/etc/systemd/system/scanlattice-inventory-rescan.timer <<'EOF'
[Unit]
Description=Nightly bounded ScanLattice website inventory rescan queue

[Timer]
OnCalendar=*:0/15
Persistent=false
Unit=scanlattice-inventory-rescan.service

[Install]
WantedBy=timers.target
EOF
systemctl daemon-reload
echo "AWS inventory scheduler installed. It has NOT queued scans."
echo "Edit /etc/scanlattice-v3/inventory-rescan.json to authorize the owned IP ranges."
echo "Preview: sudo scanlattice-inventory-rescan"
if [[ "$ACTION" == "--enable" ]]; then
  python3 - <<'PY'
import json
p="/etc/scanlattice-v3/inventory-rescan.json"
cfg=json.load(open(p))
assert cfg.get("authorized_cidrs"), "Explicit authorized_cidrs required before enabling"
PY
  /usr/local/sbin/scanlattice-inventory-rescan
  systemctl enable --now scanlattice-inventory-rescan.timer
  echo "Nightly queue enabled. Only eligible in-scope hosts are scanned."
fi
