#!/usr/bin/env bash
set -euo pipefail
# Run on each Ubuntu host you administer; not on AWS and not on Debian control.
ROOT="$(cd "$(dirname "$0")" && pwd)"
ACTION="install"
if (( $# > 0 )); then ACTION="$1"; fi
[[ $EUID -eq 0 ]] || { echo "Run as root"; exit 1; }
if [[ "$ACTION" == "--disable" ]]; then
  systemctl disable --now scanlattice-ubuntu-oval.timer || true
  exit 0
fi
[[ "$ACTION" == "install" || "$ACTION" == "--enable" ]] || {
  echo "Usage: sudo bash install_ubuntu_oval.sh [install|--enable|--disable]"; exit 2; }
source /etc/os-release
[[ "$ID" == "ubuntu" ]] || { echo "Ubuntu only"; exit 1; }
command -v oscap >/dev/null || {
  echo "Install Ubuntu package openscap-scanner first"; exit 1; }
command -v scp >/dev/null || {
  echo "Install openssh-client before configuring remote evidence upload"; exit 1; }
install -d -m 0755 /usr/local/lib/scanlattice/cve_v3
install -d -m 0700 /var/lib/scanlattice-oval
install -d -m 0700 /etc/scanlattice
install -m 0644 "$ROOT/vendor_oval.py" /usr/local/lib/scanlattice/cve_v3/vendor_oval.py
install -m 0755 "$ROOT/ubuntu_oval_job.sh" /usr/local/lib/scanlattice/cve_v3/ubuntu_oval_job.sh
if [[ ! -e /etc/scanlattice/ubuntu-oval.env ]]; then
  cat >/etc/scanlattice/ubuntu-oval.env <<'EOF'
# The host's IP as shown in ScanLattice; set once for local package assessment.
SCANLATTICE_HOST_IP=
# Optional authenticated upload via SSH; set known_hosts and SSH key yourself.
SCANLATTICE_EVIDENCE_SSH_DEST=
SCANLATTICE_SSH_KEY=
EOF
  chmod 0600 /etc/scanlattice/ubuntu-oval.env
fi
cat >/etc/systemd/system/scanlattice-ubuntu-oval.service <<'EOF'
[Unit]
Description=Check local Ubuntu package vulnerabilities against Canonical USN OVAL
Wants=network-online.target
After=network-online.target

[Service]
Type=oneshot
User=root
ExecStart=/bin/bash /usr/local/lib/scanlattice/cve_v3/ubuntu_oval_job.sh
TimeoutStartSec=0
NoNewPrivileges=true
EOF
cat >/etc/systemd/system/scanlattice-ubuntu-oval.timer <<'EOF'
[Unit]
Description=Nightly local Ubuntu OpenSCAP package assessment

[Timer]
OnCalendar=*-*-* 03:15:00
Persistent=true
Unit=scanlattice-ubuntu-oval.service

[Install]
WantedBy=timers.target
EOF
systemctl daemon-reload
echo "Ubuntu OVAL installed. Set SCANLATTICE_HOST_IP in /etc/scanlattice/ubuntu-oval.env."
if [[ "$ACTION" == "--enable" ]]; then
  source /etc/scanlattice/ubuntu-oval.env
  [[ -n "$SCANLATTICE_HOST_IP" ]] || {
    echo "Set local indexed IP before enabling"; exit 1; }
  systemctl enable --now scanlattice-ubuntu-oval.timer
  echo "Nightly Ubuntu OVAL scanning enabled for this local host."
fi
