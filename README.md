# ScanLattice v0.4

Open-source network intelligence index with a passive-only FastAPI control plane and separate outbound-connected scanning workers. The interface follows the compact, utilitarian search style of the mid-2010s without using Shodan code or assets.

Public visitors can search a normalized host/service index and trigger asynchronous, cached passive enrichment without authentication. Search pages contain exactly 10 hosts, while ASN prefixes and passive metadata use independent pagination. Exact ASN, IP, CIDR, domain, and hostname queries create a persistent, deduplicated enrichment job and the browser updates automatically. Administrative operations use an HttpOnly, Secure, SameSite=Strict session cookie plus a CSRF token, or the existing `X-Admin-Token` header for automation.

## Safety boundary

The web image contains only `app/`; it has no scanner code and never contacts target application services. It may contact explicitly approved intelligence-provider APIs. The worker image contains `worker/` and accepts jobs only when both the control server and worker confirm that the target is inside the job's explicit authorization. Limits default to 4,096 addresses per ordinary job, 256 addresses per Deep Recon batch, 65,536 addresses per authorized campaign, 100 ports, bounded timeouts and rates, three lease attempts, TCP connect only, and no authentication, exploitation, stealth, or shell execution.

## Layout

```text
app/                 FastAPI control plane, database, search, static interface
worker/agent/        Enrollment, heartbeat, polling and job execution
worker/scanners/     Conservative protocol modules
tests/               Control-plane, scheduling, indexing and local scanner tests
compose.web.yaml     WebServer role only
compose.worker.yaml  scanner role only
.env.example         WebServer configuration template
.env.worker.example  scanner configuration template
```

`worker-legacy/` remains beside this repository as the migration backup. It is not used by either v0.4 Compose file.

## Local tests

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
.venv/bin/pytest -q
RUN_PROVIDER_INTEGRATION=1 .venv/bin/pytest -q -m integration tests/test_provider_integration.py
docker compose -f compose.web.yaml config -q
docker compose -f compose.worker.yaml config -q
```

Tests use only reserved documentation addresses and a loopback TCP fixture; they never scan public targets.

## WebServer installation or upgrade

Back up the named volume before an upgrade. Database migrations are additive and retain v0.2 observations, sessions, workers, jobs, and credentials.

```bash
cd /opt
git clone https://github.com/404CoderFound/ihatepaywalls-shodan.git scanlattice
cd /opt/scanlattice
cp .env.example .env
openssl rand -hex 32   # ADMIN_TOKEN
openssl rand -hex 32   # different ENROLLMENT_TOKEN
nano .env
docker compose -f compose.web.yaml up -d --build
docker compose -f compose.web.yaml ps
curl http://127.0.0.1:8080/api/health
```

For the existing WebServer, stop the writer and create a consistent backup before pulling:

```bash
cd /opt/scanlattice
docker compose -f compose.web.yaml stop web
mkdir -p backups
docker run --rm -v scanlattice_scanlattice_data:/data:ro -v /opt/scanlattice/backups:/backup alpine:3.20 sh -c 'tar -czf /backup/scanlattice-pre-v04-2026-11-08.tgz -C /data .'
git pull --ff-only
cp .env.example .env.example.review
# Add the PASSIVE_ENRICHMENT, queue, campaign and batch variables from .env.example to .env.
docker compose -f compose.web.yaml up -d --build
docker compose -f compose.web.yaml logs --tail=100 web
curl http://127.0.0.1:8080/api/health
```

Caddy continues to proxy `https://scanlattice.plezi.eu` to `127.0.0.1:8080`. Do not expose port 8080 publicly.

## Scanserver01 installation or upgrade

Use the same repository, but only the worker Compose file:

```bash
cd /opt
git clone https://github.com/404CoderFound/ihatepaywalls-shodan.git scanlattice
cd /opt/scanlattice
cp .env.worker.example .env.worker
nano .env.worker
docker compose -f compose.worker.yaml up -d --build
docker compose -f compose.worker.yaml ps
docker compose -f compose.worker.yaml logs -f worker
```

The worker Compose file reuses the standard legacy volume name `worker-legacy_worker_state`, retaining `registration.json` across the monorepo switch. If the old Compose project used a custom project name, inspect `docker volume ls`, copy that registration file securely, or re-enroll once. On first enrollment, set `ENROLLMENT_TOKEN` to the WebServer value. After enrollment, rotate the shared enrollment secret at the control plane; each worker uses its own stored credential. Upgrade with:

```bash
cd /opt/scanlattice
docker compose -f compose.worker.yaml stop worker
mkdir -p backups
docker run --rm -v worker-legacy_worker_state:/data:ro -v /opt/scanlattice/backups:/backup alpine:3.20 sh -c 'tar -czf /backup/scanner01-state-pre-v04-2026-11-08.tgz -C /data .'
git pull --ff-only
docker compose -f compose.worker.yaml up -d --build
docker compose -f compose.worker.yaml logs --tail=100 worker
```

Workers require outbound HTTPS to `https://scanlattice.plezi.eu`; no inbound worker port, Docker socket, privileged mode, or extra capability is used.

## Authorized test scan

1. Log in to `https://scanlattice.plezi.eu/#admin` with `ADMIN_TOKEN`.
2. Verify Scanner01 is online and advertises `tcp-connect`.
3. Add a CIDR you own or have written permission to test. Prefer a single host (`x.x.x.x/32`).
4. Search that IP, click **Deep Recon**, choose **Quick Recon**, preview authorization coverage, select the target, and launch.
5. Observe `queued → assigned → running → completed`. If no worker is online, the job safely remains queued.
6. Open the completed target from search (`ip:x.x.x.x`). Confirm source `active-scan`, timestamps, service data, history, worker/job identity, and admin progress.

## Passive imports

JSON accepts up to 1,000 records and requires provenance:

```bash
curl -X POST https://scanlattice.plezi.eu/api/admin/import \
  -H "X-Admin-Token: $ADMIN_TOKEN" -H 'Content-Type: application/json' \
  -d '{"provenance":"licensed internal export 2026-11-08","observations":[{"ip":"192.0.2.10","port":443,"service":"https","product":"nginx"}]}'
```

CSV uses `POST /api/admin/import/csv?provenance=...` with `Content-Type: text/csv`. Every observation retains its source and timestamp. Demo rows use RFC 5737 addresses, source `example`, and `is_demo=1`.

Passive-only intelligence uses `POST /api/admin/passive/import`. Records can represent an IP, domain, ASN, or network and include their record type, structured value, source, observation time, and optional cache TTL. Provider definitions are managed through `GET/POST/PUT /api/admin/passive/providers`; configuration rejects embedded API keys and other secrets.

Built-in enrichment uses RIPEstat for ASN overview, announced prefixes, IP routing and CIDR prefix overview, and RDAP bootstrap for IP/network registration and domain registration. Results cache for 24 hours; failed jobs cool down for five minutes. The persistent queue deduplicates a canonical query such as `asn:30925` and `asn:AS30925`, limits retries, bounds outstanding work, and preserves partial provider success.

RIPEstat requires attribution and its service terms restrict redistribution and commercial use. Review the current RIPE NCC terms before public or commercial deployment and disable the provider through the authenticated provider API if your use is not permitted. Certificate Transparency can be enabled as a cached crt.sh provider; passive DNS currently uses imported provider data. Direct DNS is not presented as passive DNS.

## Search

Supported filters: `port`, `asn`, `country`, `org`, `product`, `service`, `ip`, `net`, `source`, `hostname`, and `domain`. `asn:30925` and `asn:AS30925` normalize identically. Filters combine with AND, quoted values work, and malformed filters return HTTP 400.

Public search returns stable host pagination metadata: `page`, `per_page`, `total`, `total_pages`, `has_next`, `has_previous`, `range_start`, and `range_end`. `per_page` is always 10. Hosts are ordered by last observation and normalized IP keys. ASN responses additionally contain an `asn_intelligence` object with overview, counts, sources, 25-prefix pagination, passive-metadata pagination, and independent indexed host/service totals. Announced addresses are never expanded into fictional hosts.

Host/service dataset pages can be ingested resumably through `POST /api/admin/datasets/ingest`. Each dataset has a cursor, progress count, provenance, and idempotent page retries. Recurring passive refreshes are managed through `GET/POST /api/admin/indexing/schedules`; this scheduler only creates passive enrichment work.

## GitHub publishing

Do not commit `.env`, `.env.worker`, SQLite files, `.venv`, caches, or worker registration state.

```bash
cd /opt/scanlattice
git status --short
git add app worker tests compose.web.yaml compose.worker.yaml Dockerfile requirements.txt README.md .env.example .env.worker.example .gitignore pytest.ini
git commit -m "Implement ScanLattice v0.4 host indexing and ASN pagination"
git push origin main
```

## Current limitations

SQLite and the persistent in-process enrichment/indexing executors are appropriate for v0.4 but should move behind PostgreSQL plus a dedicated queue before high-volume or multi-control-plane deployment. TLS collection currently records protocol, cipher, and SHA-256 certificate fingerprint rather than a complete parsed certificate chain. Certificate Transparency has an optional, administrator-enabled crt.sh adapter. Live passive DNS and commercial host-intelligence APIs are not bundled; permitted datasets can be ingested through the resumable dataset endpoint. Provider data is never converted into invented hosts or open services.
