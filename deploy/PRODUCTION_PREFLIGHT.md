# ScanLattice v2 — production preflight (READ ONLY)

Production is currently v1: `web-web-1` with `web_scanlattice_data:/data`,
`web_default`, and **two** Compose files:
`/opt/scanlattice/web/compose.web.yaml` plus
`/home/ihatepaywalls/scanlattice-release-v1/compose.release.yaml`.
The AWS project `scanlattice-aws` uses external Docker volume
`worker_worker_state`.

`scripts/preflight_production_debian.py` performs read-only Docker
`inspect` and `compose config` queries; checks actual runtime network,
published port, named volume, Compose source files and image reference.
It does NOT run `docker compose up`, `down`, `restart`, create volumes,
read any raw secret into user-visible output, or execute migration steps.
All resolved Compose environment values remain inside a local process pipe.
The script deliberately FAILS CLOSED if project, runtime resource, release
overlay or new PostgreSQL volume differs from the expected deployment.

## First run

Copy this standalone Python file from the approved development Git checkout
to the Debian server via an authenticated transport such as scp. Do not clone
a test branch into the active v1 checkout.

On Debian, with access to Docker (e.g. as root):

```bash
python3 /tmp/scanlattice-preflight.py
```

Share ONLY the printed preflight summary, not any `.env` file or
unfiltered `docker compose config` / `docker inspect` output.

## What this does NOT authorize

- Starting the new PostgreSQL container or creating its volume
- Stopping the current `web` container or AWS worker
- Migrating active SQLite files or using a stale rehearsal backup
- Modifying the reverse proxy, DNS or the production worker token
- Merging PR #7 to main or activating any new scanners

## Subsequent steps, only with explicit separate approvals

1. Prepare a reviewed, standalone PostgreSQL Compose project, private
   credentials and dedicated persistent volume; verify no public 5432 bind.
2. Create a pinned v2 web image and a new overlay that preserves the
   exact existing web Compose file pair and v1 rollback image.
3. Rehearse the complete cutover from a *new, frozen* SQLite snapshot,
   including draining the AWS worker; never switch a live-writable DB.
4. Keep post-cutover PostgreSQL writes frozen until the operator accepts
   the rollback limitations. Old SQLite snapshots cannot recover new PG writes.
5. Perform a separate GO/NO-GO and only then change production endpoints.

Latest prior Mac proof: private SQLite import, real API, fake worker,
guarded production importer, `pg_dump` restore into a separate database
with 43 table-content comparisons and 19 sequences. This is meaningful
rehearsal evidence, not production backup coverage.
