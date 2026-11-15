# ScanLattice CVE V2: staged deployment

This branch provides a **full-tree NVD 2.0 applicability evaluator**, a
resumable local index of the 26 JSON feeds, an hourly NVD modified-feed +
CISA KEV updater, and recurring re-evaluation of hosts from the live service
database. It also provides an optional Go v3.2 source patch for full TCP ports
on **one explicitly allowlisted IP**.

**Safety:** These are potential software/version signals, not verified
vulnerabilities. Version banners cannot prove installed Ubuntu patch levels.
No findings are written into the existing host_vulnerability_matches table by
this release. No active port scans or jobs are created on installation.

## Debian quick start

Run on ScanLattice Debian (not AWS):

~~~bash
sudo apt update
sudo apt install -y git python3-ijson
git clone --depth 1 --branch feature/nvd-full-applicability-v1 \
  https://github.com/404CoderFound/ihatepaywalls-shodan.git \
  ~/scanlattice-next
sudo bash ~/scanlattice-next/ops/cve_v2/install.sh
sudo scanlattice-cve-v2 index
sudo scanlattice-cve-v2 assess
sudo scanlattice-cve-v2 status
~~~

It reads your existing downloaded gzip feeds from
/srv/scanlattice-data/nvd-feeds and saves an index to
/var/lib/scanlattice-cve/applicability-v2.sqlite3. The initial index can take
several minutes; it doesn't alter PostgreSQL.

Check the report:

~~~bash
sudo python3 - <<'PY'
import json
p="/var/lib/scanlattice-cve/applicability-v2-report.json"
d=json.load(open(p))
print("Hosts:",d["hosts_checked"],"potential:",d["potential"],
      "needs evidence:",d["needs_evidence"])
for row in d["findings"][:25]:
    print(row["ip"],row["cve"],row["status"])
PY
~~~

Review results before enabling scheduled updates. A potential match is not
proof of exploitability; needs_evidence means an AND/platform constraint or
other information has not been observed.

## Enable hourly updates and recurring assessment

~~~bash
sudo bash ~/scanlattice-next/ops/cve_v2/install.sh --enable
systemctl list-timers 'scanlattice-cve-v2-*'
~~~

The refresh timer checks NVD modified feed hourly (with random delay), uses
the official checksum, imports changed/new records into PostgreSQL through
the existing authenticated local API, updates its full-config local index,
refreshes CISA KEV, and reassesses. It refuses an unsupported website image
or a more-than-six-day missed refresh interval.

The assessment timer reruns every 20 minutes, including overnight, and uses
only observed product CPEs and NVD full-tree AND/OR conditions. It is
READ-ONLY and doesn't trigger active port scans or modify website badges.

~~~bash
sudo journalctl -u scanlattice-cve-v2-refresh.service -n 50 --no-pager
sudo journalctl -u scanlattice-cve-v2-assess.service -n 50 --no-pager
~~~

Disable safely:

~~~bash
sudo bash ~/scanlattice-next/ops/cve_v2/install.sh --disable
~~~

The installer requires the completed historic-feed state and existing
cve-bulk-v1 website image. If the old scanlattice-cve-sync.timer is already
enabled, it refuses to enable another updater until you disable the old one.

## AWS: native nightly scanning of authorized hosts

Your existing Go scanner v3.2 already supports recurring scans. On AWS,
plan first and use only IPs you administer or are authorized to scan:

~~~bash
sudo scanlattice-v3 plan --ip YOUR_AUTHORIZED_PUBLIC_IP --ports extended
sudo scanlattice-v3 scan --ip YOUR_AUTHORIZED_PUBLIC_IP --ports extended --every 24h
sudo scanlattice-v3 schedules
~~~

This scans 91 known TCP ports, not all 65,535. It does not support UDP.

### Optional full TCP 1..65535 (one approved host)

The included patch_scanner_full_tcp.py modifies Go **source only**, not your
running service. It adds the all-tcp profile for --ip targets ONLY, requires
the target IP in explicit allowed_cidrs even with public mode, and requires
a conscious max_ports=65535 change to your existing AWS config.

On AWS, after ensuring the existing v3.2 source is present:

~~~bash
ls ~/ScanLattice-CVE-Upgrade-v1/aws-v3.2/go.mod
python3 ~/scanlattice-next/ops/cve_v2/patch_scanner_full_tcp.py \
  --source ~/ScanLattice-CVE-Upgrade-v1/aws-v3.2
cd ~/ScanLattice-CVE-Upgrade-v1/aws-v3.2
go test ./...
CGO_ENABLED=0 go build -o /tmp/scanlattice-v3-next ./cmd/scanlattice
sudo cp -a /usr/local/bin/scanlattice-v3 /usr/local/bin/scanlattice-v3.before-full-tcp
sudo install -m 0755 /tmp/scanlattice-v3-next /usr/local/bin/scanlattice-v3
sudo systemctl restart scanlattice-v3.service
~~~

Install Go on AWS if missing, and clone this branch onto AWS separately.
Edit /etc/scanlattice-v3/config.json manually to set max_ports to 65535
and allow only an owned IP /32 via allowed_cidrs, without removing existing
exclusions, rate limits or worker credentials. Then:

~~~bash
sudo scanlattice-v3 reload
sudo scanlattice-v3 plan --ip YOUR_ALLOWLISTED_IP --ports all-tcp
sudo scanlattice-v3 scan --ip YOUR_ALLOWLISTED_IP --ports all-tcp --every 24h
sudo scanlattice-v3 schedules
~~~

At your small instance's per-network rate a full scan can take hours per host,
so do not schedule more targets than can be completed in 24 hours. AWS cannot
directly discover home-LAN devices behind NAT without a reachable, authorized
network path or a local scanner.

AWS executable rollback:

~~~bash
sudo cp -a /usr/local/bin/scanlattice-v3.before-full-tcp /usr/local/bin/scanlattice-v3
sudo systemctl restart scanlattice-v3.service
~~~

## Vendor-aware validation

For Ubuntu servers you administer, Canonical recommends Ubuntu OVAL to
verify installed packages and security updates. On the Ubuntu machine:

~~~bash
sudo apt install -y bzip2 libopenscap25 || sudo apt install -y bzip2 libopenscap8
CODE="$(. /etc/os-release; echo "$VERSION_CODENAME")"
wget "https://security-metadata.canonical.com/oval/com.ubuntu.$CODE.usn.oval.xml.bz2"
bunzip2 -f "com.ubuntu.$CODE.usn.oval.xml.bz2"
oscap oval eval --report ubuntu-security-report.html \
  "com.ubuntu.$CODE.usn.oval.xml"
~~~

If the oscap command is not available, install the suitable OpenSCAP CLI
package for your Ubuntu release. OVAL results are authenticated local evidence;
they are **not yet imported into the ScanLattice website by this branch**.

## Remaining integration work

* New read-only results are not yet integrated with the main website.
* Ubuntu/package OVAL evidence must be ingested separately before any
  fixed/affected labels can be made authoritative.
* The temporary CVE Explorer stays online until the replacement interface
  and verified findings are working; then remove it from the production image.
* No Internet-wide scans, automatic unsolicited scans, or unsupported UDP
  coverage are added.
* This code does not change the old PostgreSQL CVE flattening format; it
  maintains the full applicability configuration in a separate indexed DB.

## Tests

~~~bash
cd ~/scanlattice-next/ops/cve_v2
python3 -m unittest -v test_applicability
python3 -m py_compile runner.py applicability.py patch_scanner_full_tcp.py
~~~
