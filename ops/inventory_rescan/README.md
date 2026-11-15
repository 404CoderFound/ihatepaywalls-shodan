# ScanLattice: AWS automatic re-scan of website inventory

**Purpose:** Every night, AWS finds the current IP hosts in ScanLattice's
main search index, then schedules one-shot scans for in-scope hosts that
are due. It does NOT require adding each host individually.

This reads the public GET /api/search?sort=ip&limit=100&page=N
response (which comes from the hosts table). Passive-only IP mentions are
not part of the scanned-host inventory. Reading the website is **not**
authorization to scan a host.

The scheduler uses existing v3 daemon persistent queue. It never modifies
the Docker image, PostgreSQL, or CVE correlation tables.

## Install on **AWS EC2** (not Debian)

~~~bash
sudo dnf install -y git
git clone --depth 1 --branch feature/nvd-full-applicability-v1 \
  https://github.com/404CoderFound/ihatepaywalls-shodan.git \
  ~/scanlattice-inventory-upgrade
sudo bash ~/scanlattice-inventory-upgrade/ops/inventory_rescan/install.sh
~~~

Before enabling, edit the authorized scope:

~~~bash
sudo nano /etc/scanlattice-v3/inventory-rescan.json
~~~

Set authorized_cidrs to the ranges you own or are expressly
authorized to scan. Do not use 0.0.0.0/0 or your entire ASN merely because
an IP appears in the website. The AWS scanner's own excludes always apply,
as does an additional public-address filter. Private LAN IPs require a
separately deployed local scanner.

Keep ports=extended until the all-TCP scanner changes are tested. The
current v3.2 extended profile checks **91 TCP ports**.

Preview (never queues jobs):

~~~bash
sudo scanlattice-inventory-rescan
~~~

Then enable the periodic scheduler:

~~~bash
sudo bash ~/scanlattice-inventory-upgrade/ops/inventory_rescan/install.sh --enable
systemctl list-timers scanlattice-inventory-rescan.timer
sudo journalctl -u scanlattice-inventory-rescan.service -n 60 --no-pager
~~~

The timer runs every 15 minutes, but only **queues** new jobs inside the
UTC overnight window (00:00–05:00 UTC by default). The Go daemon performs
the scans and uploads observations through the existing collector gateway.
The Debian scanlattice-cve-v2-assess.timer separately reassesses new
scanner evidence every 20 minutes.

Jobs are created on demand, not with per-host --every 24h recurring jobs,
so removing a host from the website inventory stops future scheduling.
Previously queued jobs do not automatically cancel.

## Coverage limits and scheduling

The example config defaults to:
- max 5,000 indexed website hosts (fail closed if larger)
- at most 3 new jobs each 15-minute tick
- at most 3 active/pending jobs
- at most 100 jobs and 12,000 TCP checks each UTC night
- 24-hour host cooldown
- scheduling only inside UTC 00:00–05:00

These limits are **not** a promise of rescanning unlimited hosts every
night. If the website grows beyond AWS t3.small capacity, the scheduler
shows a backlog and prioritizes hosts with oldest completed scans.
Review throughput before expanding the worker fleet or resource budgets.

Keep provider scanning rules, AWS security-group rules, exclusions, and
abuse-contact policy aligned with authorized target scope.

## Disable new jobs

~~~bash
sudo bash ~/scanlattice-inventory-upgrade/ops/inventory_rescan/install.sh --disable
~~~

Disabling the timer does not cancel jobs already accepted by Go.

## Verify end-to-end

1. On AWS: sudo scanlattice-inventory-rescan to preview hosts.
2. On AWS: sudo scanlattice-v3 jobs to inspect active/completed jobs.
3. Website /api/hosts/IP shows uploaded services.
4. On Debian: sudo scanlattice-cve-v2 assess evaluates new fingerprints
   against the local full NVD configuration index (read-only).

The 99 potential CVEs on the one currently fingerprinted Ubuntu host
are NOT verified vulnerabilities, and this scheduler does not publish them
as if confirmed. Vendor package evidence is needed.
