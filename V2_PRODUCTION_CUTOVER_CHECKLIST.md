# ScanLattice v2: controlled production cutover checklist

Status: **PREPARATION ONLY / NOT APPROVED FOR PRODUCTION**. No server, `main`, worker or volume changes are performed by this document.

## Verified inventory (operator-provided, November 11, 2026)

| Item | Debian control-plane | AWS worker |
| --- | --- | --- |
| Host | Debian 13 | Amazon Linux 2023 |
| Docker Compose project | `web` | `scanlattice-aws` |
| Current service | `web-web-1` | `scanlattice-aws-worker-1` |
| Current DB | SQLite at `/data/scanlattice.db` | None (control-plane API client) |
| Persistent volume | `web_scanlattice_data:/data` | `worker_worker_state:/data` |
| Network | `web_default` | Compose default |
| Compose files | `/opt/scanlattice/web/compose.web.yaml` + `/home/ihatepaywalls/scanlattice-release-v1/compose.release.yaml` | `/home/ec2-user/scanlattice-aws-worker/compose.worker.yaml` |
| Capacity | 6 CPUs, 15 GiB RAM, 218 GiB disk available | 2 CPUs, 1.9 GiB RAM |
| PostgreSQL on host | no listener on TCP 5432 at last check | not required |

The **existing** web release override pins `scanlattice/release:v1.0.0-d0c969f`, binds host `127.0.0.1:8080`, and carries production env keys. Do **not** replace or omit this override without reviewing the merged Compose configuration. Never run `docker compose down -v`, `docker volume prune`, or `docker system prune --volumes` during this cutover.

The worker Compose project resolves `worker_state` to the external Docker volume `worker_worker_state` (verified by both `docker inspect` and `docker compose config`). Preserve it exactly; do not rename the project or the volume. Worker `CONTROL_URL` must remain the existing public control-plane address rather than a Docker-internal PostgreSQL host. Keep worker credentials out of screenshots, logs and source control.

## Completed development evidence

- Frozen v0.4 SQLite fixture imported into disposable PostgreSQL; 40 tables reconciled; rollback API and repeat-import passed.
- A separate consistent SQLite production backup (~20 MB) was copied to the operator's Mac and imported into disposable PostgreSQL; 40 source tables passed schema/count checks and five hosts were compared.
- The actual v2 FastAPI API was exercised against that migrated PostgreSQL **copy** (health, stats, search, host detail, admin auth, jobs, worker listings). No scan job creation; SQLite rollback copy smoke passed; exit 0.
- Live PostgreSQL worker handshake, active-job lifecycle (with no external probing), production reverse-migration of post-cutover writes, production Compose overlays, and operational monitoring/backups have **not** yet been verified.

## Phase 0: release preparation (no production changes)

1. Freeze a reviewed and immutable v2 release commit/tag from `feature/v2-integrated-pg-scanner` **only after explicit approval**. Keep `main` unchanged until then; PR #7 remains draft.
2. Build/pin an x86_64 compatible web image matching the production release commit and separately validate the worker's expected API contract; no GitHub Actions requirement.
3. Prepare a **separate** PostgreSQL Compose service with persistent named volume and internal Docker networking. Do not expose TCP 5432 on the host or public firewall. Use the existing `web_default` network as needed and a dedicated project to avoid automatically recreating `web-web-1` while preparing the database. Any new Compose files must be diffed against actual on-server configuration.
4. Set strong unique DB credentials in root-owned (mode 0600) out-of-Git secret files; avoid echoing them or posting resolved `docker compose config` to chat. Preserve existing `ADMIN_TOKEN`, `ENROLLMENT_TOKEN`, session configuration and proxy routing unless explicitly rotated with a coordinated worker update.
5. Decide how to deploy the PostgreSQL importer safely. **Current `scripts/migrate_sqlite_to_postgresql.py` explicitly requires `--target-is-disposable-staging`; do not abuse this acknowledgement on production.** Add a separately reviewed production migration entrypoint with hard checks for source path, host/volume, destination identity, backup availability, write freeze and checkpointing before cutover. Alternatively use a new isolated, empty target for a rehearsed import, then promote that target after verifying it.
6. Test the worker enrollment/heartbeat and job contract against a throwaway, seeded, isolated PostgreSQL test database with a fake worker; never probe external IPs in this test.
7. Validate read-only v2 web startup and reverse proxy routing on a distinct loopback port, without altering the production proxy or worker control URL.

## Phase 1: backup + drain (requires separate operator authorization)

1. Schedule a maintenance window and communicate an anticipated write pause.
2. Inspect active/leased/queued jobs before stopping anything. Drain or explicitly record them; do not terminate a live scan mid-task. Suspend the AWS worker only after it is idle, then freeze all control-plane data writers (including admin mutations, passive enrichment and schedulers).
3. Stop the old web writer with the **currently deployed** Compose file pair and **project `web`** only after approvals; avoid `down` and `-v`.
4. Take a **new consistent final SQLite snapshot** after the last writer is stopped, plus a separate archive/copy of the existing external worker registration volume (no token printout). The November 11 backup is a staging reference, **not** the cutover backup.
5. Record `PRAGMA integrity_check`, per-table row counts, source file checksum, image tag, Compose-file checksums, and encrypted off-host backup location. Reopen the saved backup to confirm it is recoverable. Retain all pre-cutover assets.

## Phase 2: import + verification (under continued write freeze)

1. Import from the final frozen SQLite **copy** into a fresh PostgreSQL database/namespace using the approved production migration procedure. Do not import into an occupied schema.
2. Reconcile **every** source table's count and the known FK/identity relationships; verify record samples and original scan job/worker IDs, authorization and admin access. Check sequence high-water marks and that imports are idempotent.
3. Connect the pinned v2 web service to that exact imported DB/schema on an isolated test endpoint. Confirm health/stats/search/host details/admin auth, and validate worker-compatible API behavior with a test identity. Prohibit any real active scans.
4. Take a PostgreSQL snapshot/backup before enabling writes. Verify restores to an empty target.
5. **GO / NO-GO** decision: if any check fails, do not switch the production endpoint or allow worker reconnect.

## Phase 3: cutover and observation (separate explicit approval)

1. Update the `web` service to the reviewed v2 image via a carefully inspected Compose overlay, preserving `web_scanlattice_data`, project `web`, host `127.0.0.1:8080`, existing proxy rules and admin/enrollment configuration. Keep PostgreSQL private on Docker network.
2. Validate public and admin UI, search, data counts, authentication, job queue, and logs before reconnecting the AWS worker.
3. Resume the AWS worker on its **existing** `scanlattice-aws` project and external `worker_worker_state`. Confirm stable worker ID, no re-registration/token change, successful heartbeat, and no unexpected job claims. Carefully authorize any live scanning separately.
4. Resume remaining writers only once PostgreSQL backups, monitoring, and incident response are known good.

## Rollback policy

- **Before any new writes on PostgreSQL:** stop v2 web and workers, restore the exact old v1 image + two-file Compose configuration, point it to the retained SQLite volume and verify application endpoints before allowing writes. Do not overwrite or delete the PostgreSQL target or the final SQLite snapshot.
- **After new writes on PostgreSQL:** the old SQLite snapshot is **stale**. Rolling back to it discards those writes. A lossless rollback requires a separately tested reverse data sync/export or reprocessing procedure, including worker job state and authentication changes. If none exists, freeze writes and **do not automatically revert**; restore v2/PostgreSQL from its latest safe point or explicitly accept the loss with operator approval.
- Log decision times and exact immutable image IDs; keep the backup off-host.

## Production readiness blockers / TODO

- [ ] Production Compose override, PostgreSQL network/secret/volume definition reviewed.
- [ ] Production-safe import procedure written and rehearsed without reusing the staging-only flag.
- [ ] PostgreSQL writes/worker protocol test with no external network probes.
- [ ] Final backup verified and off-host; PostgreSQL restore tested.
- [ ] Exact release commit, image digest and rollback deploy plan pinned.
- [ ] Operator approves downtime and cutover explicitly.
- [ ] Release documentation brought up to date (`POSTGRES_MIGRATION_PLAN.md` still describes PostgreSQL as a plan; `MIGRATION_GUIDE.md` contains historic `worker-v02` instructions that must **not** be followed blindly on the current `scanlattice-aws` deployment).
