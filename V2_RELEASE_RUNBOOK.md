# ScanLattice v2 release-candidate runbook

**State: staging deployment prepared; production cutover is NO-GO.** This
release candidate has not been deployed to Debian or AWS. Use the reviewed PR
head and the immutable image recorded in `deploy/debian-v2-staging-image.lock`.
Do not use `main`, PR #7, or any old worker-v02 instructions as a deployment
source. No command below authorizes production work; production actions need a
separate written approval naming the host, commit/image, data snapshot, target,
maintenance window and rollback plan.

## 1. Local release validation

On a developer machine with local Docker Engine/Compose and Python:

```sh
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -r requirements.txt
python -m pytest -q

docker buildx build --platform linux/amd64 --load \
  --build-arg VCS_REF=<source-commit-from-image-lock> \
  -f Dockerfile.debian-staging \
  -t scanlattice-v2-candidate:<source-commit-from-image-lock> .
python3 scripts/smoke_debian_v2_staging.py \
  --image <immutable-image-id-from-lock>
```

For a full importer and fake-worker rehearsal, first create a synthetic SQLite
fixture in a private temporary directory. Do not substitute any production
file or backup:

```sh
WORK_DIR=$(mktemp -d /tmp/scanlattice-v2-rehearsal.XXXXXX)
chmod 700 "$WORK_DIR"
trap 'rm -rf "$WORK_DIR"' EXIT
DATABASE_BACKEND=sqlite DATABASE_PATH="$WORK_DIR/synthetic.sqlite" python3 - <<'PY'
import os
from pathlib import Path
from app import database
database.DB_PATH = Path(os.environ["DATABASE_PATH"])
database.init_db(False)
with database.connection() as db:
    database.upsert_host_identity(db, "192.0.2.77", "synthetic-local-rehearsal", database.utc_now())
PY
bash scripts/rehearse_postgresql_from_backup.sh "$WORK_DIR/synthetic.sqlite"
```

The rehearsal owns a unique disposable Compose project, PostgreSQL volume,
credentials and loopback port and removes only those resources. Its fake probe
callback is constrained to TEST-NET documentation space; it does not open
probe sockets. GitHub Actions and paid CI are intentionally not part of this
procedure.

## 2. Approved isolated Debian staging

Use a Debian 13 host only after a separate staging GO. First perform the
read-only inventory from `deploy/DEBIAN_V2_STAGING_RUNBOOK.md`; the expected
first-run project is `scanlattice-v2-staging`, web bind is `127.0.0.1:8081`,
PostgreSQL has no published port and is on an internal network. Preserve the
existing v1 project, port 8080, `web_scanlattice_data`, `web_default`, reverse
proxy/DNS and AWS worker/volume.

Prepare fresh root-protected secret files and `/etc/scanlattice-v2-staging/compose.env`
as described in the detailed runbook. Load and verify the approved immutable
AMD64 image ID. Then, and only after infrastructure preparation GO, create
stopped staging containers/networks/volumes:

```sh
sudo docker compose --project-name scanlattice-v2-staging \
  --env-file /etc/scanlattice-v2-staging/compose.env \
  -f deploy/compose.debian-v2-staging.yaml \
  create --no-build --no-recreate postgres web
```

Verify both containers are stopped, the database network is internal, the
staging bridge is `slv2stage0`, no DB port is published, and only fresh staging
volumes/resources appear. Install the repository's scoped nftables policy and
systemd unit exactly as documented, then require `--check`, enabled/active unit,
and a second GO before starting either service. The guard drops staging traffic
to host services and forwarding to every other interface; it does not change
Docker chains or other host firewall tables.

After startup GO:

```sh
sudo docker compose --project-name scanlattice-v2-staging \
  --env-file /etc/scanlattice-v2-staging/compose.env \
  -f deploy/compose.debian-v2-staging.yaml \
  up -d --no-recreate postgres web
curl --fail --silent http://127.0.0.1:8081/api/health
```

Complete all API/admin/search/persistence/firewall checks and separate empty
PostgreSQL backup/restore verification in the detailed staging runbook. Do not
enroll the real AWS worker or enable active scanning. Staging rollback: stop
only this named project without `-v`, retain the PostgreSQL volume and backup,
and restore the previously recorded staging image only after operator review.

## 3. Production migration gates (not approved or run)

There is no reviewed production Compose overlay or tested lossless reverse
migration after PostgreSQL accepts writes. Therefore production startup, import,
service replacement, worker reconnect and traffic cutover are presently **NO-GO**.
Do not issue production `docker compose up`, importer `--execute`, proxy/DNS
changes, or AWS worker changes as part of this release-candidate PR.

If a later change obtains explicit approval, prepare a final consistent SQLite
snapshot only after the approved drain and writer freeze, and a distinct
independently verified rollback copy. The app importer refuses live volume
paths, symlinks, sidecars, mismatched hashes, non-empty or unrelated targets,
other database clients and interrupted imports. Run its dry-run first, with
credentials supplied through an approved secret manager (never a command-line
password):

```sh
python3 scripts/import_production_sqlite_snapshot.py \
  /secure/frozen/scanlattice-snapshot.sqlite \
  --source-sha256 <snapshot-sha256> \
  --rollback-backup /secure/rollback/scanlattice-snapshot.sqlite \
  --rollback-backup-sha256 <independent-backup-sha256> \
  --expected-host <approved-postgresql-host> \
  --expected-database <approved-database> \
  --schema <new-empty-migration-schema>
```

The dry-run makes no target changes. Execute only after the operator records
GO for that exact source checksum, host/database/schema, approval reference and
maintenance window:

```sh
python3 scripts/import_production_sqlite_snapshot.py \
  /secure/frozen/scanlattice-snapshot.sqlite \
  --source-sha256 <snapshot-sha256> \
  --rollback-backup /secure/rollback/scanlattice-snapshot.sqlite \
  --rollback-backup-sha256 <independent-backup-sha256> \
  --expected-host <approved-postgresql-host> \
  --expected-database <approved-database> \
  --schema <new-empty-migration-schema> \
  --execute --acknowledge-writers-frozen \
  --go-approval-reference <recorded-change-id>
```

The exact production Compose overlay, service image switch, proxy routing and
worker resume commands must be prepared and reviewed separately against the
actual Debian two-file Compose configuration before a future cutover. Do not
guess or omit either file. GO requires count/ID/sequence reconciliation, empty
restore test, health/admin/search verification, worker identity and heartbeat
verification without real jobs, backup/checksum retention, monitoring and
operator approval.

### Rollback decision

Before PostgreSQL accepts application writes, stop the candidate services and
return to the preserved v1 image, exact two Compose files, original SQLite
volume, port and proxy configuration after a health check. Keep the PostgreSQL
target and final SQLite snapshot untouched. Never use `down -v`, broad prune or
volume replacement.

After PostgreSQL accepts writes, the original SQLite snapshot is stale. There
is no tested reverse synchronization in this release candidate. Freeze writers
and keep PostgreSQL authoritative; do not automatically switch v1 back to
SQLite. Any decision to discard PostgreSQL writes requires explicit operator
acceptance of data loss. A lossless reverse path is a hard blocker before
production GO.

## 4. Required manual actions before production GO

1. Approve a maintenance window and separately authorize the production drain,
   writer freeze, final snapshot and rollback-copy creation.
2. Review production-specific Compose/network/secret/backup configuration and
   provision PostgreSQL only after that approval.
3. Run dry-run, review reconciliation plan, then explicitly approve guarded
   import for the exact snapshot/target identity.
4. Resolve/test post-write reverse migration, or accept the defined no-reverse
   freeze-and-recover strategy before routing any writes.
5. Separately approve v2 service/traffic switch and AWS worker resume. Preserve
   the stable worker identity/volume, keep jobs and scans disabled until the
   operator authorizes them.
6. Review data-source licenses, provider quotas, retention, capacity,
   monitoring, alerting and incident response. Synthetic tests do not establish
   global data coverage or provider access.
