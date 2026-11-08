# ScanLattice — Web / Control Plane (MVP v0.1)

A classic 2015–2017-style web search interface with a **passive, local index** and authenticated worker enrollment/heartbeat. Original visual design inspired by the utilitarian era of search engines; not Shodan's code or assets.

> Important: This repository **cannot scan targets**. There is no Nmap/ZMap/scanning code or command execution. The worker repository is separate; active scans are not implemented in the v0.1 starter.

## Requirements
- Docker and Docker Compose
- A domain with HTTPS terminating in Caddy/Nginx for remote worker use; do not send tokens over plain HTTP.

## Quick start (local/SSH-tunnel demonstration)

```bash
cp .env.example .env
nano .env        # Set two DIFFERENT long random token values using: openssl rand -hex 32
sudo docker compose up -d --build
sudo docker compose ps
```

The web service listens **only on 127.0.0.1:8080**, not the public network.

From your Mac, tunnel to the web host:

```bash
ssh -L 8080:127.0.0.1:8080 ihatepaywalls@185.220.213.48
```

Then open `http://127.0.0.1:8080`. Admin page uses `ADMIN_TOKEN` (stored in tab sessionStorage). Example data is from reserved RFC 5737 documentation address blocks and is visibly marked DEMO DATA. Disable with `SEED_DEMO=false` and rebuild DB / remove demo rows for production.

## For a remote scanner to connect

Expose the web API using a trusted, **TLS-enabled reverse proxy** (e.g. Caddy) at a domain you control. Example Caddyfile:

```caddyfile
scan.example.com {
    encode zstd gzip
    reverse_proxy 127.0.0.1:8080
}
```

Point the domain A record at your control server; configure ports 80/443 and your hosting firewall. Keep database ports unexposed. Do not run the worker over plain HTTP or with disabled TLS verification.

## Manual passive data import

Use observations you control or have rights to import. Example:

```bash
curl -X POST https://scan.example.com/api/admin/import \
  -H 'Content-Type: application/json' -H "X-Admin-Token: $ADMIN_TOKEN" \
  -d '{"observations":[{"ip":"192.0.2.40","port":443,"asn":"AS64500","org":"Example Org","country":"NL","product":"nginx","banner":"HTTP/1.1 200 OK","source":"manual"}]}'
```

## Search grammar

`port:443`, `country:NL`, `asn:AS64500`, `ip:192.0.2.10`, `org:"Example Systems"`, `product:nginx`, `net:192.0.2.0/24` and free text. Query results come solely from **already indexed** observations.

## Safety and next milestones

This is a tested starter, **not production-hardened**: add HTTPS, proper log redaction, database backups, rate limiting, authenticated public accounts and a more scalable backend before public launch. Worker registration relies on a shared enrollment token. Rotate it after initial enrollment; per-worker tokens are unique. Add role-based authorization, scoped targets, job queue, and rate-limited authorized scan executor in later milestones. Web server remains passive-only.
