#!/usr/bin/env bash
set -euo pipefail
# Run on Amazon Linux 2023 worker. This only installs health checks.
ROOT="$(cd "$(dirname "$0")" && pwd)"
ACTION="install"
if (( $# > 0 )); then ACTION="$1"; fi
[[ $EUID -eq 0 ]] || { echo "Run using sudo"; exit 1; }
if [[ "$ACTION" == "--disable" ]]; then
  systemctl disable --now scanlattice-aws-health.timer || true
  exit 0
fi
[[ "$ACTION" == "install" || "$ACTION" == "--enable" ]] || {
  echo "Usage: sudo bash install_aws_health.sh [install|--enable|--disable]"; exit 2; }
test -f /etc/scanlattice-v3/config.json
test -x /usr/local/bin/scanlattice-v3
install -d -m 0755 /usr/local/lib/scanlattice/cve_v3
install -m 0644 "$ROOT/doctor.py" "$ROOT/verify_ingestion.py" /usr/local/lib/scanlattice/cve_v3/
cat >/usr/local/sbin/scanlattice-aws-health <<'EOF'
#!/bin/sh
exec /usr/bin/python3 /usr/local/lib/scanlattice/cve_v3/doctor.py --role aws \
  --output /var/lib/scanlattice-v3/health.json
EOF
chmod 0755 /usr/local/sbin/scanlattice-aws-health
cat >/etc/systemd/system/scanlattice-aws-health.service <<'EOF'
[Unit]
Description=ScanLattice AWS nightly scanner health and completion monitoring
Wants=network-online.target
After=network-online.target scanlattice-v3.service

[Service]
Type=oneshot
User=root
EnvironmentFile=-/etc/scanlattice-v3/health.env
ExecStart=/usr/local/sbin/scanlattice-aws-health
ExecStartPost=/usr/bin/python3 /usr/local/lib/scanlattice/cve_v3/verify_ingestion.py
TimeoutStartSec=120
NoNewPrivileges=true
EOF
cat >/etc/systemd/system/scanlattice-aws-health.timer <<'EOF'
[Unit]
Description=Validate AWS worker and ScanLattice job progress

[Timer]
OnCalendar=*:0/30
Persistent=true
Unit=scanlattice-aws-health.service

[Install]
WantedBy=timers.target
EOF
systemctl daemon-reload
echo "AWS health checker installed, no scanning configuration changed."
echo "Run: sudo /usr/local/sbin/scanlattice-aws-health"
if [[ "$ACTION" == "--enable" ]]; then
  systemctl enable --now scanlattice-aws-health.timer
  echo "AWS health checking enabled every 30 minutes."
fi
