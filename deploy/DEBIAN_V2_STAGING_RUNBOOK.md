# Isolated Debian 13 staging runbook (approval gated)

This runbook prepares only the separate Compose project `scanlattice-v2-staging`.
It does not modify the v1 Compose project, `web_scanlattice_data`, port 8080,
reverse proxy, DNS, AWS worker, or production PostgreSQL. Do not run it against
production data. The staging web container has no external network route, active
worker API is disabled, and no worker service is included.

## Explicit GO gates

The operator must record **GO** for each item before starting services:

1. Confirm the current source branch and exact commit are the reviewed staging PR
   commit; confirm the x86_64 image ID/digest was built from that commit and
   matches the Compose `SCANLATTICE_WEB_IMAGE` value.
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
   scanning is false, and the app cannot reach external networks.
6. Approve the staging-only startup command below. Production deployment still
   requires separate explicit authorization.

Any failed or unknown item is **NO-GO**.

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
  whose `internal` flag is true;
- only the dedicated `postgres_data` and optional restore-test volumes are
  referenced; no v1 or AWS volumes are referenced;
- web image is the recorded immutable x86_64 image ID;
- DB/admin/enrollment values are file-backed, not environment values;
- `ACTIVE_SCANNING_ENABLED`, passive enrichment, scheduled monitoring,
  vulnerability refresh and demo seeding are all disabled;
- no worker service or AWS credentials exist in the resolved model.

If Compose shows any resolved password/token value, any public bind, or any
existing production volume/network, stop: **NO-GO**.

## Start isolated staging (manual approval required)

Only after an operator records staging GO, start the named project:

```bash
sudo docker compose --project-name scanlattice-v2-staging \
  --env-file /etc/scanlattice-v2-staging/compose.env \
  -f deploy/compose.debian-v2-staging.yaml up -d postgres web
```

Then verify health, loopback-only port mapping, internal network, and that the
web health response reports `active_scanning: false`:

```bash
sudo docker compose --project-name scanlattice-v2-staging \
  --env-file /etc/scanlattice-v2-staging/compose.env \
  -f deploy/compose.debian-v2-staging.yaml ps
sudo docker inspect scanlattice-v2-staging-web-1 --format '{{json .NetworkSettings.Ports}}'
curl --fail --silent http://127.0.0.1:8081/api/health
sudo docker network inspect scanlattice-v2-staging_staging_private
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
  pg_restore --exit-on-error --no-owner --role=scanlattice_restore \
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
proxy/DNS edit, or CI run is authorized by this preparation. Local Docker
Compose validation, an actual disposable PostgreSQL restore, and the image ID
must be recorded from a Docker-capable isolated builder before the staging GO
gate can pass.
