# Isolated Debian 13 staging runbook (approval gated)

This runbook prepares only the separate Compose project `scanlattice-v2-staging`.
It does not modify the v1 Compose project, `web_scanlattice_data`, port 8080,
reverse proxy, DNS, AWS worker, or production PostgreSQL. Do not run it against
production data. PostgreSQL is only on the internal database network. Web joins
that private network and a separate host-ingress bridge with IP masquerading
disabled; the application kill switch blocks worker/job execution and no worker
service is included. The host firewall must also deny forwarding from the
staging bridge to external interfaces before the GO gate passes.

## Explicit GO gates

The operator must record **GO** for each item before starting services:

1. Confirm the image `source_commit` in the lock file is an ancestor of the
   reviewed staging PR head, and that no `app/`, `migrations/`, staging
   Dockerfile, or runtime dependency-lock changes occurred after that source
   commit. Confirm the x86_64 image ID/digest in the lock matches the Compose
   `SCANLATTICE_WEB_IMAGE` value.
2. Confirm the project name, network names and volume names below do not exist
   already, and that nothing uses `127.0.0.1:8081`.
3. Confirm all three fresh staging-only secret files exist outside Git, are
   `root:<dedicated-gid-10001-group>` mode `0440`, and are readable in-container
   by UID/GID 10001.
   Password/token values must not be put in the Compose env file or command line.
4. Select an empty disposable PostgreSQL target or separately obtained and
   independently verified SQLite **backup copy**. Never point at, freeze, copy,
   or inspect the live production SQLite database automatically. This runbook
   starts empty PostgreSQL; importing any backup is a separate reviewed action.
5. Confirm no scan/worker credentials or AWS worker are connected, active
   scanning is false, and host firewall policy blocks forwarding from the
   project-specific staging bridge to external interfaces. The Docker network
   must have IP masquerading disabled as defense in depth.
6. Approve the staging-only startup command below. Production deployment still
   requires separate explicit authorization.

Any failed or unknown item is **NO-GO**.

## Local validation before the Debian GO gate

Run these checks on a developer machine with a local Unix-socket Docker
context, never on a production Docker context. Use the image ID produced from
the reviewed source commit:

```bash
python3 scripts/smoke_debian_v2_staging.py \
  --image sha256:<recorded-image-config-id>
```

The smoke test generates disposable credentials, uses a unique Compose project
and volumes, verifies the live API/admin/search/scan-kill-switch behavior,
restarts PostgreSQL and the web container to check persistence, backs up and
restores into a separate empty PostgreSQL service, checks logs for the generated
credentials, and removes only its own resources. It refuses remote Docker
contexts and refuses to use port 8081 when already occupied.

Also exercise the full guarded SQLite-to-PostgreSQL importer and fake-worker
contract using only a synthetic database with TEST-NET documentation data. Do
not substitute a production database or production backup:

```bash
WORK_DIR=$(mktemp -d /tmp/scanlattice-v2-rehearsal.XXXXXX)
trap 'python3 -c "import shutil,sys; shutil.rmtree(sys.argv[1], ignore_errors=True)" "$WORK_DIR"' EXIT
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

The rehearsal starts its own disposable PostgreSQL project and verifies table
schemas/counts, IDs, sequences, import idempotence, PostgreSQL backup/restore,
API/search/admin behavior, fake worker registration/heartbeat/empty claim, and
SQLite rollback. The live app configuration remains scan-disabled; only the
isolated fake-worker test client enables the registration protocol, and it
uses no scan-capable worker or target.

## Read-only preflight and inventory

Run from the reviewed source checkout. These commands only inspect local state:

```bash
git status --short --branch
git rev-parse HEAD
docker context show
docker info --format 'OS={{.OSType}} ARCH={{.Architecture}}'
docker compose version
docker ps -a --filter label=com.docker.compose.project=scanlattice-v2-staging
docker volume ls --filter label=com.docker.compose.project=scanlattice-v2-staging
docker network ls --filter label=com.docker.compose.project=scanlattice-v2-staging
docker ps --filter publish=8081
```

All Compose project inventory commands must return no pre-existing resources on
first setup. If any exist, stop and identify/record their owner; do not remove
them. Verify that the active Docker context is the intended Debian host and
that the architecture is `x86_64`/`amd64`. Do not use a context pointing at the
production host for local build validation.

## Prepare image and secrets

Build from the exact reviewed source commit on an x86_64 builder, then record
the resulting image config ID. Buildx must use the pinned `linux/amd64` base
manifest and fully pinned Python dependency lock:

```bash
git checkout --detach <reviewed-commit>
docker buildx build --platform linux/amd64 --load \
  --build-arg VCS_REF=<reviewed-commit> \
  -f Dockerfile.debian-staging -t scanlattice-v2-staging:<reviewed-commit> .
docker image inspect scanlattice-v2-staging:<reviewed-commit> \
  --format 'IMAGE_ID={{.Id}} ARCH={{.Architecture}} OS={{.Os}}'
docker save scanlattice-v2-staging:<reviewed-commit> \
  -o /tmp/scanlattice-v2-staging-<reviewed-commit>.tar
sha256sum /tmp/scanlattice-v2-staging-<reviewed-commit>.tar
```

The image built for this PR is pinned in
[`debian-v2-staging-image.lock`](debian-v2-staging-image.lock): source commit
`f2468f9415b45beec032380b8e387b7ede7c48c2`, platform `linux/amd64`, Docker
image ID `sha256:a0345b9c98c5ba20383cd3307defc41cac3d90c0a0e30f0340830bad520f0773`,
and AMD64 manifest `sha256:2463340970919e7afc7b15da11ed4dc901805a28514263e9d9f940ba5f83d4ca`.
The image label records the source commit. Rebuild and update this lock whenever
the app, Dockerfile, or dependency lock changes; verify the label and
architecture before deployment. Set `SCANLATTICE_WEB_IMAGE` to the exact
`docker_image_id` value from this lock.

Compare the output to `linux/amd64`, record `IMAGE_ID=sha256:...` and set
`SCANLATTICE_WEB_IMAGE` to that immutable local image ID in the root-only
Compose env file. Never substitute a floating tag. Transfer of image archives,
if required, must use an approved authenticated channel and verify a separately
recorded SHA-256 archive checksum before loading on Debian.

On Debian, check the archive checksum, then load and inspect the image before
use:

```bash
sha256sum --check /path/to/approved-image.tar.sha256
sudo docker load --input /path/to/approved-image.tar
sudo docker image inspect sha256:<recorded-image-config-id> \
  --format 'IMAGE_ID={{.Id}} ARCH={{.Architecture}} OS={{.Os}}'
```

Create fresh random values locally on the Debian host (never paste them into
chat or a shell command argument). Use your approved secret manager or a
root-only editor to create:

- `/etc/scanlattice-v2-staging/db-password`
- `/etc/scanlattice-v2-staging/admin-token`
- `/etc/scanlattice-v2-staging/enrollment-token`

Each file must contain one value, have no trailing output in logs, and be at
least 32 random bytes (tokens should be URL-safe). Set owner `root:<dedicated
host group with GID 10001>`, mode `0440`, and make the directory inaccessible
to other users. The staging image runs web as UID/GID 10001; map that dedicated
host group as GID 10001. Verify `stat` and container readability without
printing file contents. Do not grant world access. PostgreSQL reads the DB
password as root before dropping privileges.

Create `/etc/scanlattice-v2-staging/compose.env` with only these path/image
references (no secret values), mode `0600`, root-owned:

```dotenv
SCANLATTICE_WEB_IMAGE=sha256:<recorded-image-config-id>
SCANLATTICE_DB_PASSWORD_FILE=/etc/scanlattice-v2-staging/db-password
SCANLATTICE_ADMIN_TOKEN_FILE=/etc/scanlattice-v2-staging/admin-token
SCANLATTICE_ENROLLMENT_TOKEN_FILE=/etc/scanlattice-v2-staging/enrollment-token
```

The `scanlattice-deploy` user must not receive unrestricted Docker access. Run
Compose through the reviewed root-owned, fixed-project wrapper or a controlled
root session. Docker daemon access is effectively root. Do not grant Docker
group membership merely to simplify the deployment.

## Validate Compose, then request GO

With the protected env file, render the resolved Compose model. Rendering may
show secret **file paths** but must never show secret values:

```bash
sudo docker compose --env-file /etc/scanlattice-v2-staging/compose.env \
  -f deploy/compose.debian-v2-staging.yaml config
```

Review the resolved configuration and confirm all of the following before GO:

- only project `scanlattice-v2-staging` and its newly scoped resources appear;
- `web` publishes only `127.0.0.1:8081` to container port 8080;
- no service publishes 5432; PostgreSQL is attached only to `staging_private`,
  whose `internal` flag is true. Web attaches to this and `staging_loopback`, a
  separate bridge whose IP masquerading is disabled and whose host binding
  defaults to `127.0.0.1`;
- only the dedicated `postgres_data` and optional restore-test volumes are
  referenced; no v1 or AWS volumes are referenced;
- web image is the recorded immutable x86_64 image ID;
- DB/admin/enrollment values are file-backed, not environment values;
- `ACTIVE_SCANNING_ENABLED`, passive enrichment, scheduled monitoring,
  vulnerability refresh and demo seeding are all disabled;
- no worker service or AWS credentials exist in the resolved model.

Before starting services, install/verify the host firewall rule in the
approved Debian firewall management system so forwarded packets arriving from
the `staging_loopback` Docker bridge cannot leave through another host
interface. Identify the bridge using
`docker network inspect --format '{{.Id}}' scanlattice-v2-staging_staging_loopback`
(`br-` plus the first 12 ID characters on Debian). Read back the effective
nftables/iptables policy and confirm it drops `iif=<that bridge>` to any
non-bridge output interface while permitting the loopback-published web path.
Do not change shared Docker chains or production rules without a separate
reviewed staging firewall change. If the active firewall cannot express and
verify this scoped deny, stop: **NO-GO**.

If Compose shows any resolved password/token value, any public bind, or any
existing production volume/network, stop: **NO-GO**.

## Start isolated staging (manual approval required)

Only after an operator records staging GO, start the named project:

```bash
sudo docker compose --project-name scanlattice-v2-staging \
  --env-file /etc/scanlattice-v2-staging/compose.env \
  -f deploy/compose.debian-v2-staging.yaml up -d postgres web
```

Then verify health, loopback-only port mapping, private/internal DB network,
host firewall egress-deny policy, and that the web health response reports
`active_scanning: false`:

```bash
sudo docker compose --project-name scanlattice-v2-staging \
  --env-file /etc/scanlattice-v2-staging/compose.env \
  -f deploy/compose.debian-v2-staging.yaml ps
sudo docker inspect scanlattice-v2-staging-web-1 --format '{{json .NetworkSettings.Ports}}'
curl --fail --silent http://127.0.0.1:8081/api/health
sudo docker network inspect scanlattice-v2-staging_staging_private
sudo docker network inspect scanlattice-v2-staging_staging_loopback
sudo docker volume ls --filter label=com.docker.compose.project=scanlattice-v2-staging
```

Inspect logs only after confirming redaction; never use `set -x`, dump container
environment, print secret files, or attach command output containing credentials
to issue/PR logs. Do not configure a proxy or DNS route as part of this runbook.

## Backup, isolated restore check, and rollback

Take a PostgreSQL custom-format backup to a root-only location; this example
does not print a credential or expose the DB port:

```bash
umask 077
sudo sh -c 'docker compose --project-name scanlattice-v2-staging \
  --env-file /etc/scanlattice-v2-staging/compose.env \
  -f deploy/compose.debian-v2-staging.yaml exec -T postgres \
  pg_dump -U scanlattice_staging -Fc scanlattice_staging \
  > /var/backups/scanlattice-v2-staging.dump'
```

Start the optional restore service, a separate empty PostgreSQL container with
its own volume, then restore without destructive `--clean` flags:

```bash
sudo docker compose --project-name scanlattice-v2-staging \
  --env-file /etc/scanlattice-v2-staging/compose.env \
  -f deploy/compose.debian-v2-staging.yaml --profile backup-restore-test \
  up -d postgres-restore-test
sudo sh -c 'docker compose --project-name scanlattice-v2-staging \
  --env-file /etc/scanlattice-v2-staging/compose.env \
  -f deploy/compose.debian-v2-staging.yaml exec -T postgres-restore-test \
  pg_restore -U scanlattice_restore --exit-on-error --no-owner --role=scanlattice_restore \
  -d restore_empty < /var/backups/scanlattice-v2-staging.dump'
sudo docker compose --project-name scanlattice-v2-staging \
  --env-file /etc/scanlattice-v2-staging/compose.env \
  -f deploy/compose.debian-v2-staging.yaml exec -T postgres-restore-test \
  psql -U scanlattice_restore -d restore_empty -c \
  'SELECT count(*) FROM schema_migrations;'
```

Compare table counts, key IDs, sequences, schema migrations, and application
read/search behavior against the source before accepting the restore. Retain
the dump and checksum according to the staging retention policy.

Application rollback is to the previously recorded staging image ID only;
preserve PostgreSQL volume and dump. Stop staging using the same explicit
project/file pair. Do **not** pass `-v`, run `docker volume prune`, or remove
anything by broad name. Destructive volume removal requires a separate review
after a verified restorable backup and explicit authorization. Production
rollback remains governed by its separate cutover approval and is out of scope.

## Release status

No Debian deployment, production database start, migration, worker enrollment,
proxy/DNS edit, or CI run is authorized by this preparation. The local image
build, Compose/API/persistence checks, PostgreSQL backup/restore, and synthetic
SQLite migration/fake-worker rehearsal passed. Debian staging remains **NO-GO**
until its read-only preflight, fresh external secrets, exact image ID check,
project resource inventory, and scoped egress-deny firewall rule are verified
and the operator records explicit staging approval.
