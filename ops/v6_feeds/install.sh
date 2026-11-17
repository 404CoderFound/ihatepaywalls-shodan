#!/usr/bin/env bash
set -euo pipefail
# ScanLattice V6 passive dataset intake, Debian only. Does not modify Docker.
ROOT="$(cd "$(dirname "$0")" && pwd)"
ACTION="install"; if [[ $# -gt 0 ]]; then ACTION="$1"; fi
case "$ACTION" in install|--enable|--disable) ;; *)
  echo "Usage: sudo bash install.sh [install|--enable|--disable]" >&2; exit 2 ;;
esac
[[ "$EUID" -eq 0 ]] || { echo "Run with sudo" >&2; exit 2; }
if [[ "$ACTION" == --disable ]]; then
  systemctl disable --now scanlattice-v6-feeds.timer
  echo "V6 feed polling disabled; database and downloaded snapshots preserved."
  exit 0
fi

python3 -m unittest discover -s "$ROOT" -p 'test_v6.py' -v
python3 -m py_compile "$ROOT/ingest.py"

install -d -m 0750 /usr/local/lib/scanlattice/v6-feeds
install -m 0755 "$ROOT/ingest.py" /usr/local/lib/scanlattice/v6-feeds/ingest.py
install -m 0755 "$ROOT/ingest.py" /usr/local/sbin/scanlattice-v6-feeds
install -d -m 0700 /etc/scanlattice/v6-feeds
install -d -m 0700 /var/lib/scanlattice-feeds /var/lib/scanlattice-feeds/inbox /var/lib/scanlattice-feeds/snapshots
if [[ ! -f /etc/scanlattice/v6-feeds/config.json ]]; then
  install -m 0600 "$ROOT/config.example.json" /etc/scanlattice/v6-feeds/config.json
fi

cat >/etc/systemd/system/scanlattice-v6-feeds.service <<'EOF'
[Unit]
Description=ScanLattice V6 incremental passive feed importer
Wants=network-online.target
After=network-online.target

[Service]
Type=oneshot
User=root
ExecStart=/usr/local/sbin/scanlattice-v6-feeds
TimeoutStartSec=1800
NoNewPrivileges=true
PrivateTmp=true
ProtectHome=true
ProtectSystem=strict
ReadWritePaths=/var/lib/scanlattice-feeds
UMask=0077
EOF
cat >/etc/systemd/system/scanlattice-v6-feeds.timer <<'EOF'
[Unit]
Description=Check approved datasets for new ScanLattice service observations

[Timer]
OnBootSec=2min
OnUnitInactiveSec=5min
AccuracySec=30s
Persistent=true
Unit=scanlattice-v6-feeds.service

[Install]
WantedBy=timers.target
EOF
systemctl daemon-reload
if [[ "$ACTION" == --enable ]]; then
  test -s /etc/scanlattice/v6-feeds/admin-token || {
    echo "Missing root-only admin-token file; configure it first." >&2; exit 2;
  }
  python3 - <<'PY'
import json
from pathlib import Path
config=json.loads(Path('/etc/scanlattice/v6-feeds/config.json').read_text())
assert config.get('sources'), 'Configure at least one licensed data source before enabling'
PY
  systemctl enable --now scanlattice-v6-feeds.timer
  echo "V6 incremental feed timer enabled."
else
  echo "V6 installed but not enabled. Configure one approved feed, then re-run with --enable."
fi
