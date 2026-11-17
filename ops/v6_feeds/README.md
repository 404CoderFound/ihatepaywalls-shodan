# ScanLattice V6 — continuous passive dataset ingestion (first release)

This is a **staged add-on for Debian**, not a new web image or an internet-wide
scanner. It checks explicitly approved local files or HTTPS feed URLs on a
five-minute systemd timer, imports at most 200 small batches per run using the
current `/api/admin/datasets/imports` endpoint, and resumes progress across
restarts. **No probes of dataset IP addresses are performed.**

The current production installation is not identical to GitHub's default
Compose files. Do not run the repository's default web Compose installation
over production. This installer affects only the dedicated V6 feed service.

## What the feed must contain

Input is UTF-8 JSONL or CSV, optionally gzip compressed. A record must include
a real `ip`; an observed port/banners are optional:

```json
{"ip":"192.0.2.10","port":443,"service":"https","product":"nginx","banner":"HTTP/1.1 200 OK","http":{"headers":{"Server":"nginx/1.24.0"}},"tls":{"cert":{"subject":"example.test"}},"observed_at":"2026-11-16T08:00:00Z"}
```

Multiple observations for one host can be represented as multiple records or
a host with a `services` array as supported by the backend importer. Do not
invent open ports when the source only provides an IP. CVE IDs from raw
remote fingerprints are unverified correlations, not confirmed vulnerabilities.

These are **synthetic RFC 5737 example addresses**. The service does not
automatically download Censys, Rapid7 or Shodan's commercial bulk datasets.
Acquire access and confirm licensing and redistributability separately.
Convert a source's native schema to ScanLattice JSONL/CSV before registration.

## Installation on Debian

```bash
git clone --depth 1 --branch feature/v6-continuous-feed-ingest \
  https://github.com/404CoderFound/ihatepaywalls-shodan.git \
  ~/scanlattice-v6-feeds
sudo bash ~/scanlattice-v6-feeds/ops/v6_feeds/install.sh
```

Initial install runs offline tests, installs an isolated worker and timer,
but **does not enable** it until configuration is supplied.

The service uses the live loopback API, not a publicly exposed admin token.
Copy the already-configured admin token *without printing it in the terminal*:

```bash
sudo sh -c 'umask 077; docker exec scanlattice-v2-prodweb-web-1 python -c \
  "import os,pathlib; print(pathlib.Path(os.environ[\"ADMIN_TOKEN_FILE\"]).read_text().strip())" \
  > /etc/scanlattice/v6-feeds/admin-token'
sudo chmod 0600 /etc/scanlattice/v6-feeds/admin-token
```

Do not paste the resulting secret into a chat, issue or repository. If the
Docker container uses a different secret arrangement, create that file
manually from the existing server-side secret without exposing it.

Configure `/etc/scanlattice/v6-feeds/config.json`. For a local source you
have permission to import:

```json
{
  "api_base": "http://127.0.0.1:8080",
  "admin_token_file": "/etc/scanlattice/v6-feeds/admin-token",
  "state_dir": "/var/lib/scanlattice-feeds",
  "allowed_https_hosts": [],
  "batch_records": 250,
  "batch_bytes": 524288,
  "max_source_bytes": 1073741824,
  "max_batches_per_run": 200,
  "sources": [{
    "id": "approved_export",
    "path": "/var/lib/scanlattice-feeds/inbox/approved.jsonl",
    "format": "jsonl",
    "compression": "identity",
    "rights_confirmed": true
  }]
}
```

Place the licensed, correctly formatted export in the inbox using a temporary
filename and atomic rename; this avoids a poll reading an unfinished file.
For a feed URL, replace `path` with a fixed HTTPS `url`, include the
exact DNS hostname in `allowed_https_hosts`, and confirm your subscription
permits downloading, storing and exposing the data. Redirects and non-public
download host IPs are rejected; no arbitrary link fetching is performed.

Enable only after adding a real source:

```bash
sudo bash ~/scanlattice-v6-feeds/ops/v6_feeds/install.sh --enable
sudo systemctl start scanlattice-v6-feeds.service
sudo scanlattice-v6-feeds --status
sudo journalctl -u scanlattice-v6-feeds.service -n 100 --no-pager
sudo systemctl list-timers scanlattice-v6-feeds.timer
```

`--status` shows the committed batch cursor, completion state and latest error
per source. An acknowledged batch is independently visible through the current
dataset import API before all other batches are finished. Batch imports have
deterministic IDs and the importer resumes staged uploads after failures.

## Limitations before any production-scale import

- The running production endpoint must be verified with one small, licensed
  test feed. Local tests are **not** production Docker or API tests.
- Snapshot-level change detection skips unchanged files (including ETag/304).
  If the *entire file changes*, V6 replays that snapshot in small batches;
  database upsert semantics and observation deduplication must be verified on
  production. A future record-level delta adapter can avoid reprocessing
  unchanged entries in large snapshots.
- Full global Shodan-like coverage depends on actual data-provider entitlements.
  Many sources provide only IP/ports/CPE data and no raw banners, screenshots,
  or authenticated vulnerability evidence.
- The live V3 CVE assess/reconcile timers continue independently. Detection
  from banner versions is *research evidence*, never a verified vulnerability.
- The importer repairs NUL characters in **its own inbound JSON**, but the
  separate AWS scanner's original upload path still needs the permanent
  server-side binary-banner ingestion fix.
- HTTPS feed-host allowlists and DNS public-address screening are a defense
  layer, not an unrestricted URL downloader. Do not register untrusted URLs.
- The initial runner holds an exclusive local lock, retains last snapshots and
  checkpoints, and imports one feed at a time. Capacity planning, indexes,
  bulk-native formats (Avro/Parquet/zstd) and live provider adapters are later
  milestones.

## Stop / rollback

```bash
sudo bash ~/scanlattice-v6-feeds/ops/v6_feeds/install.sh --disable
```

This stops new imports; it does not delete previously indexed observations,
the import checkpoint SQLite DB or saved source snapshots. It does not touch
existing Docker services, scanner jobs or CVE timers.
