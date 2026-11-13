# ScanLattice v1.0

> **v2 release-candidate status (2026-11-13):** PostgreSQL compatibility,
> guarded SQLite snapshot migration, isolated Debian staging and local Docker
> backup/restore/fake-worker rehearsal are under review on a feature branch.
> Production has not been changed and is not approved for cutover. Follow
> [V2_RELEASE_RUNBOOK.md](V2_RELEASE_RUNBOOK.md) for the tested local flow and
> remaining manual gates.

Open-source network intelligence index with a passive-only FastAPI control plane and separate authorized scanning workers. The interface follows the compact, utilitarian search style of the mid-2010s without using Shodan code or assets.

Public visitors can search indexed observations and cached/passive intelligence without authentication. Public search may queue bounded enrichment through explicitly enabled passive providers, but it never launches an active scan or contacts a target application's services. Active jobs, worker management, dataset imports, provider configuration, monitoring management and vulnerability feed refresh require server-side administrator authorization. Browser administrators use an HttpOnly, SameSite=Strict session cookie plus a CSRF token; automation uses the `X-Admin-Token` header. The API key system is read-only and scope limited.

## Safety boundary

The web image contains only `app/`; it has no scanner code and never contacts target application services. It may contact explicitly approved intelligence-provider APIs. The worker image contains `worker/` and accepts jobs only when both the control server and worker confirm that the target is inside the job's explicit authorization. Limits default to 4,096 addresses per ordinary job, 256 addresses per Deep Recon batch, 65,536 addresses per authorized campaign, 100 ports, bounded timeouts and rates, three lease attempts, TCP connect only, and no authentication, exploitation, stealth, or shell execution.

Administrators can persist CIDR scan exclusions for opt-outs and sensitive networks. Exclusions override authorizations, cancel matching queued/leased jobs, and block future claims and result submissions. Disabling an exclusion does not revive cancelled jobs. This active-scan control does not delete or hide previously indexed observations. A worker may finish the small bounded batch already in progress; for an immediate stop, pause that authorized worker before adding the exclusion.


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

`worker-legacy/` remains beside this repository as the migration backup. It is not used by the v1.0 Compose files.

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
git commit -m "Implement ScanLattice v1.0 host indexing and ASN intelligence"
git push origin main
```

## Current limitations

SQLite and in-process enrichment/indexing executors are suitable for a single control-plane deployment, but should move behind PostgreSQL and a dedicated queue before high-volume or multi-control-plane operation. TLS observations retain the collected protocol, cipher, certificate fingerprint and available certificate metadata. Certificate Transparency and other passive providers must be explicitly enabled. Live passive DNS and commercial host-intelligence APIs are not bundled; permitted datasets can be ingested through the resumable dataset endpoint. Provider data is never converted into invented hosts or open services.

## v1.0 development additions

The v1.0 increment adds read-only API keys, resumable dataset ingestion, official vulnerability-feed adapters, evidence-based potential CPE matches, authorized monitoring and notification delivery, real indexed analytics, an offline interactive map, CSV export and browser controls for these features. Administrator APIs require server-side authorization; public search never schedules active scans. See the checklist for verified scope and known limitations.

The project provides an importable host index and configurable provider adapters; it does not claim commercial global host-index coverage. NVD and CISA KEV adapters, streaming dataset imports, potential CPE correlations, monitoring notifications, data-backed analytics, an offline interactive country choropleth and a private authorized-host screenshot library are implemented. Screenshots must be captured by an authorized operator workflow and uploaded; ScanLattice does not automatically browse target sites. See [FEATURE_CHECKLIST.md](FEATURE_CHECKLIST.md) for verified status and remaining work. The bundled map boundaries come from [Natural Earth](https://www.naturalearthdata.com/about/), whose vector and raster data are public domain.

### Python SDK and CLI

The dependency-free read client is in `sdk/client.py`. Example CLI calls:

```sh
export SCANLATTICE_URL=https://scanlattice.plezi.eu
python3 cli.py search 'port:443 country:NL'
python3 cli.py host 203.0.113.10
python3 cli.py history 203.0.113.10
python3 cli.py stats
```

Set `SCANLATTICE_API_KEY` to use a read-only key. Public search endpoints remain available without one.

### Isolated staging profile

`compose.staging.yaml` binds only to `127.0.0.1:18080` and uses the explicitly named `scanlattice_staging_data` volume. It does not read `.env` and disables passive network lookups by default. Start it with staging-only secrets:

```sh
STAGING_ADMIN_TOKEN='use-a-unique-staging-secret' \
STAGING_ENROLLMENT_TOKEN='use-a-different-staging-secret' \
docker compose -p scanlattice-staging -f compose.staging.yaml up -d --build
```

To test a database copy, make a verified backup first, place only the copy in `scanlattice_staging_data`, and set `DATABASE_PATH` to its copied filename. Do not attach `web_scanlattice_data` or `worker_worker_state` to staging. This checkout has not been supplied with a production database copy, so no restore has been run.

### PostgreSQL staging and migration

PostgreSQL is an optional backend; SQLite remains the default. The PostgreSQL profile uses its own internal database service, project-scoped volume, staging secrets, and loopback-only web port. It does not read `.env` or attach production volumes. Validate it with fresh, staging-only credentials:

```sh
export STAGING_PROJECT="scanlattice-pg-$(date +%s)"
export STAGING_PORT=18081
export STAGING_ADMIN_TOKEN="$(openssl rand -hex 32)"
export STAGING_ENROLLMENT_TOKEN="$(openssl rand -hex 32)"
export STAGING_POSTGRES_PASSWORD="$(openssl rand -hex 32)"
scripts/validate_postgresql_staging.sh
```

The validator builds the PostgreSQL-backed web image, checks the API and schema migration, then runs the reserved-address staging E2E. By default it removes its project-scoped containers and volume on exit; set `KEEP_STAGING=true` to leave the isolated staging environment running for manual review. Never reuse a production project or volume name.

To rehearse an existing SQLite migration, first make an authorized sanitized copy and point `DATABASE_URL` at a **new, disposable staging database**. The importer takes a consistent SQLite backup, streams batches, commits rowid cursors with each batch, and resumes using the source fingerprint. It refuses a non-empty target and requires the staging confirmation flag:

```sh
DATABASE_BACKEND=postgresql \
DATABASE_URL='postgresql://scanlattice:<staging-password>@localhost:5432/scanlattice' \
DATABASE_SCHEMA=public \
python3 scripts/migrate_sqlite_to_postgresql.py /path/to/sanitized-copy.sqlite \
  --schema public --target-is-disposable-staging
```

The source file is never modified. This rehearsal does not cut over a running application or authorize production migration. SQLite remains available for rollback; production adoption still requires a separately approved backup, restore, compatibility, load, and rollback exercise.

### Resumable dataset ingestion

Admin clients upload the file as consecutive raw chunks to `POST /api/admin/datasets/imports`. Required headers are `X-Import-Id`, `X-Import-Source`, `X-Import-Format` (`csv`, `json`, or `jsonl`), `X-Import-Encoding` (`identity` or `gzip`) and `Content-Range: bytes START-END/TOTAL`. The response includes `resume_offset`; retry from that exact offset after interruption. `GET /api/admin/datasets/imports` reports progress and `POST /api/admin/datasets/imports/{id}/resume` retries processing after an interrupted or partially processed upload. Chunks default to at most 8 MiB; compressed file size defaults to at most 20 GiB. Import files are spooled below the configured database directory and retained for resumability.

The importer accepts service observations (including common Shodan-style `ip_str`, `data`, `transport`, `product`, `banner`, `ssl`, `http`, `asn`, and `hostnames` fields) and host-only rows. Host-only records create host identity/history metadata, but never a service or port. Every service row is stored with the supplied dataset provenance and timestamp. Search examples include `http.title:"Admin Portal"`, `ssl.cert.subject.cn:example.org`, `cpe:nginx`, `os:linux`, `after:2025-01-01`, `port:80 OR port:443`, and `-country:US`.

### Vulnerability feeds

`POST /api/admin/vulnerabilities/refresh` accepts `{"providers":["nvd","kev"],"max_pages":20}`. NVD uses its official CVE API and KEV uses CISA's published catalog. NVD modified-date pagination is resumable across bounded runs; set `NVD_API_KEY` to use the registered API quota. Optional daily refresh starts only when `VULNERABILITY_AUTO_REFRESH=true`. Current feed health and cursor are available at `GET /api/admin/vulnerabilities/providers`. Feed network calls were not made during local tests; provider parsers and paging were tested with fixtures.
