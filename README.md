# ScanLattice v0.2

Open-source network intelligence index with a passive-only FastAPI control plane and separate outbound-connected scanning workers. The interface follows the compact, utilitarian search style of the mid-2010s without using Shodan code or assets.

Public visitors can search indexed observations and cached passive intelligence without authentication. Administrative operations use an HttpOnly, Secure, SameSite=Strict session cookie plus a CSRF token, or the existing `X-Admin-Token` header for automation. Every `/api/admin/*` data-management endpoint performs server-side authorization independently; hiding UI controls is not treated as security.

## Safety boundary

The web image contains only `app/`; it has no scanner code and never contacts targets. Search reads indexed data only. The worker image contains `worker/` and accepts jobs only when both the control server and worker confirm that the target is inside the job's explicit authorization. Limits default to 4,096 addresses, 100 ports, 50 concurrent sockets per job, bounded timeouts, three lease attempts, TCP connect only, and no authentication, exploitation, stealth, or shell execution.

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

`worker-legacy/` remains beside this repository as the migration backup. It is not used by either v0.2 Compose file.

## Local tests

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
.venv/bin/pytest -q
docker compose -f compose.web.yaml config -q
docker compose -f compose.worker.yaml config -q
```

Tests use only reserved documentation addresses and a loopback TCP fixture; they never scan public targets.

## WebServer installation or upgrade

Back up the named volume before an upgrade. Database migrations are additive and run at startup.

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

For an existing checkout:

```bash
cd /opt/scanlattice
docker compose -f compose.web.yaml down
git pull --ff-only
cp .env.example .env.example.review
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

The worker Compose file reuses the standard legacy volume name `worker-legacy_worker_state`, retaining `registration.json` across the monorepo switch. If the old Compose project used a custom project name, inspect `docker volume ls`, copy that registration file securely, or re-enroll once. On first v0.2 enrollment, set `ENROLLMENT_TOKEN` to the WebServer value. After enrollment, rotate the shared enrollment secret at the control plane; each worker uses its own stored credential. Upgrade with:

```bash
cd /opt/scanlattice
git pull --ff-only
docker compose -f compose.worker.yaml up -d --build
docker compose -f compose.worker.yaml logs --tail=100 worker
```

Workers require outbound HTTPS to `https://scanlattice.plezi.eu`; no inbound worker port, Docker socket, privileged mode, or extra capability is used.

## Authorized test scan

1. Log in to `https://scanlattice.plezi.eu/#admin` with `ADMIN_TOKEN`.
2. Verify Scanner01 is online and advertises `tcp-connect`.
3. Add a CIDR you own or have written permission to test. Prefer a single host (`x.x.x.x/32`).
4. Enter that IP as the job target, choose **Conservative**, optionally restrict ports, leave worker selection automatic, and submit.
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

Passive-only intelligence uses `POST /api/admin/passive/import`. Records can represent an IP, domain, ASN, or network and include their record type, structured value, source, observation time, and optional cache TTL. Provider definitions are managed through `GET/POST /api/admin/passive/providers`; configuration rejects embedded API keys and other secrets. Exact-IP searches may use an explicitly enabled RDAP provider, but only through the fixed HTTPS allowlist (`rdap.org` or RIPE's RDAP service). Results are cached for 24 hours, empty/error responses for five minutes, and per-provider request quotas are enforced. No request is made to the searched host itself. Passive DNS and Certificate Transparency definitions currently consume imported/cached data only.

## Search

Supported filters: `port`, `asn`, `country`, `org`, `product`, `service`, `ip`, `net`, `source`, `hostname`, and `domain`. Filters combine with AND, quoted values work, pagination is stable, and malformed/unknown filters return HTTP 400. Results separate historical **Indexed Observations** from **Passive Intelligence**. Public search and host endpoints are rate-limited per client IP and never enqueue work or import worker modules.

## GitHub publishing

Do not commit `.env`, `.env.worker`, SQLite files, `.venv`, caches, or worker registration state.

```bash
cd /opt/scanlattice
git status --short
git add app worker tests compose.web.yaml compose.worker.yaml Dockerfile requirements.txt README.md .env.example .env.worker.example .gitignore pytest.ini
git commit -m "Implement ScanLattice v0.2 control plane and workers"
git push origin main
```

## Current limitations

SQLite and in-process scheduling are appropriate for v0.2 but should move behind PostgreSQL plus a dedicated scheduler before high-volume deployment. TLS collection currently records protocol, cipher, and SHA-256 certificate fingerprint rather than a complete parsed certificate chain. ASN, organization, country, reverse DNS and public DNS data must arrive from documented imports; no third-party provider is bundled or fabricated.
