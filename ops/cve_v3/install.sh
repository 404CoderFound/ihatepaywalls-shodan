#!/usr/bin/env bash
set -euo pipefail
# Install safely on ScanLattice Debian, never on AWS.
ROOT="$(cd "$(dirname "$0")" && pwd)"
DEST=/usr/local/lib/scanlattice/cve_v3
ACTION="install"
if (( $# > 0 )); then ACTION="$1"; fi
[[ $EUID -eq 0 ]] || { echo "Run via sudo"; exit 1; }
case "$ACTION" in install|--activate|--disable|--restore) ;; *)
  echo "Usage: sudo bash install.sh [install|--activate|--disable|--restore]"; exit 2;; esac
if [[ "$ACTION" == "--disable" || "$ACTION" == "--restore" ]]; then
  systemctl disable --now scanlattice-cve-v3-reconcile.timer scanlattice-cve-v3-health.timer || true
  if [[ "$ACTION" == "--restore" ]]; then
    python3 "$DEST/publish.py" rollback
  fi
  echo "V3 timers disabled. Historical CVEs and host observations preserved."
  exit 0
fi

test -f /var/lib/scanlattice-cve/applicability-v2.sqlite3 || {
  echo "Run scanlattice-cve-v2 index first"; exit 1; }
test -x /usr/local/sbin/scanlattice-cve-v2 || {
  echo "Existing V2 runner missing"; exit 1; }
docker inspect scanlattice-v2-prodweb-web-1 >/dev/null
python3 -m unittest discover -s "$ROOT" -p "test_v3.py" -v
python3 -m py_compile "$ROOT/vendor_oval.py" "$ROOT/merge_report.py" \
  "$ROOT/doctor.py" "$ROOT/publish.py" "$ROOT/fingerprint.py" "$ROOT/vendor_import.py"
if command -v node >/dev/null 2>&1; then node --check "$ROOT/cve-v3.js"; fi

install -d -m 0755 "$DEST"
install -m 0644 "$ROOT/vendor_oval.py" "$ROOT/merge_report.py" \
  "$ROOT/doctor.py" "$ROOT/publish.py" "$ROOT/fingerprint.py" "$ROOT/vendor_import.py" \
  "$ROOT/cve-v3.js" "$ROOT/site-clean.css" "$DEST/"
install -m 0755 "$ROOT/reconcile.sh" "$DEST/reconcile.sh"
install -d -m 0700 /var/lib/scanlattice-cve/vendor \
  /var/lib/scanlattice-cve/site-v3-backups
if id -u ihatepaywalls >/dev/null 2>&1; then
  install -d -o ihatepaywalls -g ihatepaywalls -m 0700 \
    /home/ihatepaywalls/scanlattice-vendor-inbox
fi

cat >/usr/local/sbin/scanlattice-cve-v3 <<'EOF'
#!/bin/sh
case "$1" in
  reconcile) exec /bin/bash /usr/local/lib/scanlattice/cve_v3/reconcile.sh ;;
  doctor) shift; exec /usr/bin/python3 /usr/local/lib/scanlattice/cve_v3/doctor.py "$@" ;;
  publish) shift; exec /usr/bin/python3 /usr/local/lib/scanlattice/cve_v3/publish.py "$@" ;;
  *) echo "Usage: scanlattice-cve-v3 {reconcile|doctor --role debian|publish install|publish retire-explorer|publish rollback}" >&2; exit 2 ;;
esac
EOF
chmod 0755 /usr/local/sbin/scanlattice-cve-v3

cat >/etc/systemd/system/scanlattice-cve-v3-reconcile.service <<'EOF'
[Unit]
Description=ScanLattice V3 fingerprint CVEs and publish evidence-based main UI
Wants=docker.service
After=docker.service

[Service]
Type=oneshot
User=root
ExecStart=/usr/local/sbin/scanlattice-cve-v3 reconcile
TimeoutStartSec=0
NoNewPrivileges=true
EOF
cat >/etc/systemd/system/scanlattice-cve-v3-reconcile.timer <<'EOF'
[Unit]
Description=Reconcile ScanLattice CVEs against fresh service fingerprints

[Timer]
OnCalendar=*-*-* *:07,27,47:00
Persistent=true
Unit=scanlattice-cve-v3-reconcile.service

[Install]
WantedBy=timers.target
EOF

cat >/etc/systemd/system/scanlattice-cve-v3-health.service <<'EOF'
[Unit]
Description=ScanLattice V3 health and freshness validation
Wants=network-online.target
After=network-online.target

[Service]
Type=oneshot
User=root
EnvironmentFile=-/etc/scanlattice/cve-v3-health.env
ExecStart=/usr/local/sbin/scanlattice-cve-v3 doctor --role debian --output /var/lib/scanlattice-cve/pipeline-health.json
TimeoutStartSec=180
NoNewPrivileges=true
EOF
cat >/etc/systemd/system/scanlattice-cve-v3-health.timer <<'EOF'
[Unit]
Description=Check ScanLattice control-plane health twice hourly

[Timer]
OnCalendar=*-*-* *:12,42:00
Persistent=true
Unit=scanlattice-cve-v3-health.service

[Install]
WantedBy=timers.target
EOF
systemctl daemon-reload
echo "Installed V3 on Debian; nothing activated yet."
echo "Preview fingerprint candidates before activation:"
echo "  sudo docker exec -i scanlattice-v2-prodweb-web-1 python - < $DEST/fingerprint.py"
echo "Enable after preview: sudo bash $ROOT/install.sh --activate"
if [[ "$ACTION" == "--activate" ]]; then
  /usr/local/sbin/scanlattice-cve-v3 reconcile
  systemctl enable --now scanlattice-cve-v3-reconcile.timer scanlattice-cve-v3-health.timer
  echo "V3 reconciliation and monitoring enabled."
fi
