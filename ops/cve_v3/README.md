# ScanLattice V3: finish the five pipeline workstreams

This is a **staged** upgrade to the running PostgreSQL ScanLattice
production installation. GitHub's default application tree and Docker Compose
files are NOT identical to production. Never replace the production Compose
stack with the GitHub default.

### Read-only Docker rootfs: production-compatible publication

The publisher DOES NOT copy files into the running Docker rootfs (which is
read-only). It copies the entire original static directory to
/var/lib/scanlattice-cve/site-v3-static, adds a single script and JSON report,
then creates /etc/scanlattice/v2-prodweb/cve-v3.readonly.override.yaml.
A one-time Docker Compose recreation of the web service binds that entire
host static directory as read-only. Other original volumes and services remain.
The existing image stays scanlattice-prodweb:cve-bulk-v1.

Reconciliation refreshes cve-v3-public.json atomically in that host directory
and does NOT recreate Docker every 20 minutes. Rollback uses the original
Compose file only, recreating the web service without the V3 mount. No base
Compose file, original Docker image, or PostgreSQL data is overwritten.

Preflight: the publisher refuses to proceed when the running image differs
from the original Compose image or when another existing mount occupies static/.
It validates Compose config and the actual production DOM, and attempts an
automatic rollback if the new website fails public health checks.

The V3 static mount becomes the authoritative copy of the original website
assets. After a future production image update, rebuild the static staging
directory from the newly deployed image before re-enabling V3.

The package covers:
1. Ubuntu Canonical USN OVAL local package verification and conservative
   merging with NVD CPE signals.
2. Debian and AWS runtime health/freshness diagnostics.
3. Main website host/CVE assessment panels, catalog search, reversible UI
   publishing and optional retirement of standalone CVE Explorer.
4. Conservative Apache/nginx/OpenSSH banner-to-CPE identification.
5. Reconciliation timers, operational monitoring and optional webhook alerts.

Remote CPE version matches are POTENTIAL, NOT proof of vulnerability. OS
backports require authenticated local package checks.

## Debian production control plane

~~~bash
git clone --depth 1 \
 --branch feature/finish-cve-pipeline-ui-monitor-v3 \
 https://github.com/404CoderFound/ihatepaywalls-shodan.git \
 ~/scanlattice-finish
sudo bash ~/scanlattice-finish/ops/cve_v3/install.sh
~~~

Inspect proposed CPE fingerprints without changing PostgreSQL:

~~~bash
sudo docker exec -i scanlattice-v2-prodweb-web-1 python - \
  < ~/scanlattice-finish/ops/cve_v3/fingerprint.py
~~~

Only explicit versions from stored banners can be used. When checks are
satisfactory, activate:

~~~bash
sudo bash ~/scanlattice-finish/ops/cve_v3/install.sh --activate
~~~

This does NOT replace the Docker image. It adds a reversible script and
report to the current container's static folder. It writes only previously
empty service CPEs derived from explicit banners; does not write to the old
host_vulnerability_matches table.

Check the report and main-site navigation:

~~~bash
curl -fsSI https://scanlattice.plezi.eu/static/cve-v3.js
curl -fsS https://scanlattice.plezi.eu/static/cve-v3-public.json | head -c 500
~~~

Open the website's existing Vulnerabilities tab and the indexed host page.
Only after visually confirming the main V3 panel works, remove the old
temporary standalone Explorer with the guarded command:

~~~bash
sudo scanlattice-cve-v3 publish retire-explorer
~~~

It requires working public V3 assets before removal.

## AWS EC2

Your existing nightly scan scheduler already targets all eligible indexed
public IPs using the selected 91-port profile. This V3 package does not
change its targets, scope or network scan profile.

Install a separate AWS monitoring timer:

~~~bash
git clone --depth 1 \
 --branch feature/finish-cve-pipeline-ui-monitor-v3 \
 https://github.com/404CoderFound/ihatepaywalls-shodan.git \
 ~/scanlattice-finish
sudo bash ~/scanlattice-finish/ops/cve_v3/install_aws_health.sh --enable
sudo /usr/local/sbin/scanlattice-aws-health
sudo scanlattice-v3 jobs
~~~

The monitor checks scheduler/daemon health, completed job age, job failure
counts and website inventory reachability. It cannot prove every indexed
host was scanned until those jobs actually finish and upload observations.

## Ubuntu package verification (optional, for locally managed hosts)

Canonical's official USN OVAL data can detect missing security patches on a
local Ubuntu machine, even when its exposed upstream software version looks
old. To use it, install the OpenSCAP package and the local exporter on
each Ubuntu host you administer:

~~~bash
sudo apt update
sudo apt install -y openscap-scanner openssh-client
git clone --depth 1 \
 --branch feature/finish-cve-pipeline-ui-monitor-v3 \
 https://github.com/404CoderFound/ihatepaywalls-shodan.git \
 ~/scanlattice-finish
sudo bash ~/scanlattice-finish/ops/cve_v3/install_ubuntu_oval.sh
sudo nano /etc/scanlattice/ubuntu-oval.env
~~~

Set SCANLATTICE_HOST_IP to the host's IP as indexed by ScanLattice
(e.g. 185.220.213.51 on the previously examined Ubuntu machine). A separate
CIDR allowlist is NOT needed.

For unattended evidence upload, optionally configure
SCANLATTICE_EVIDENCE_SSH_DEST as an SSH destination filename inside
/home/ihatepaywalls/scanlattice-vendor-inbox/ on Debian, plus
SCANLATTICE_SSH_KEY pointing to your own verified dedicated SSH key.
SSH host key verification is required; this release never disables it.

Run a local evaluation:

~~~bash
sudo bash /usr/local/lib/scanlattice/cve_v3/ubuntu_oval_job.sh
sudo bash ~/scanlattice-finish/ops/cve_v3/install_ubuntu_oval.sh --enable
~~~

Without SSH upload, transfer the resulting local file
/var/lib/scanlattice-oval/host-evidence.json to the Debian inbox securely
and run sudo scanlattice-cve-v3 reconcile on Debian.

The importer uses only fresh reports (48 hours). A negative OVAL test means
the vendor rule was not satisfied; it does NOT always prove a patch
was installed. Positive results are reported as local package-test affected
with provenance, not as demonstrated remote exploitability.

## Health, recovery, rollback

Debian:

~~~bash
sudo scanlattice-cve-v3 doctor --role debian
sudo journalctl -u scanlattice-cve-v3-reconcile.service -n 100 --no-pager
sudo journalctl -u scanlattice-cve-v2-refresh.service -n 100 --no-pager
systemctl list-timers 'scanlattice-cve-*'
~~~

AWS:

~~~bash
sudo /usr/local/sbin/scanlattice-aws-health
sudo journalctl -u scanlattice-inventory-rescan.service -n 100 --no-pager
~~~

For optional webhook alerts, set SCANLATTICE_HEALTH_WEBHOOK to an HTTPS
JSON-accepting endpoint in the root-only systemd EnvironmentFile:
on Debian /etc/scanlattice/cve-v3-health.env; on AWS
/etc/scanlattice-v3/health.env. No alert URL is invented by the installer.

Disable V3 timers:

~~~bash
sudo bash ~/scanlattice-finish/ops/cve_v3/install.sh --disable
~~~

Restore backed-up main UI and optional former Explorer:

~~~bash
sudo bash ~/scanlattice-finish/ops/cve_v3/install.sh --restore
~~~

The existing hourly CVE V2 refresh and AWS scanner schedules are separate,
and remain enabled unless you explicitly disable them.

## Known limits

* This is a staged release. The website overlay must be republished after
  a Docker container is recreated; bake it into the next verified image.
* Existing old host-vulnerability associations are not written or upgraded.
* Public hosts can be banner-fingerprinted only when the returned evidence
  actually identifies a software version. Unknown systems remain unknown.
* Ubuntu vendor OVAL evidence cannot be generated remotely without a local
  agent, package inventory, and a trusted delivery path.
* Until the first actual AWS scan uploads and CVE timers finish on the
  user's running machines, end-to-end deployment is not verified.
