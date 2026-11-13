# Standalone production PostgreSQL preparation

**Preparation only.** This guide and its Compose template do not create a
Docker network or volume, start PostgreSQL, change the Debian v1 service, or
run a migration. PR #26's read-only Debian preflight passed; that result is
not permission to make production changes.

## Isolation and compatibility

`compose.postgresql-production.yaml` defines only a PostgreSQL service in a
separate Compose project. It publishes no host ports and joins the dedicated
Docker bridge `scanlattice_postgresql_private`, marked `internal: true`. The
existing v1 web container is deliberately not attached to this network, so
this standalone preparation does not change its network access or database.
Connecting a future v2 web container requires a separate reviewed Compose
change and explicit approval.

The database uses the named persistent volume
`scanlattice_v2_postgresql_data`. PostgreSQL credentials are read from a
root-owned file outside the repository. Compose receives only the file path
through `SCANLATTICE_PG_PASSWORD_FILE`; no password belongs in a tracked file,
shell history, command output, or chat.

Keep the production v1 web project and its exact two-file configuration
untouched:

- `/opt/scanlattice/web/compose.web.yaml`
- `/home/ihatepaywalls/scanlattice-release-v1/compose.release.yaml`

The release override pins `scanlattice/release:v1.0.0-d0c969f`. Do not omit,
rewrite, or recreate that v1 service while preparing PostgreSQL. The AWS
scanner project and its state volume are outside this procedure.

## Credential and configuration preparation

Perform these steps only on the production host after the operator approves
creating the secret file. They do not start a service:

```sh
sudo install -d -o root -g root -m 700 /etc/scanlattice/secrets
sudo sh -c 'umask 077; openssl rand -hex 48 > /etc/scanlattice/secrets/postgres-password'
sudo chown root:root /etc/scanlattice/secrets/postgres-password
sudo chmod 600 /etc/scanlattice/secrets/postgres-password
```

In the same controlled shell used for validation, set the path without
printing or sourcing a production `.env` file:

```sh
sudo env SCANLATTICE_PG_PASSWORD_FILE=/etc/scanlattice/secrets/postgres-password \
  docker compose --env-file /dev/null -p scanlattice-postgresql \
  -f deploy/compose.postgresql-production.yaml config --quiet
```

`config --quiet` only validates Compose interpolation and syntax. Do not post
rendered Compose output because it can expose paths and future configuration.
This standalone file does not change either v1 Compose file.

The password file is mode `0600` and root-owned, so Compose must run as root
to read it. Compose also needs Docker-daemon socket access. Docker-group
membership is effectively root; do not grant it to `scanlattice-deploy`.
Use a controlled `sudo` invocation or an explicitly reviewed root-owned
wrapper restricted to this Compose file and project. Do not make the secret
group-readable or world-readable to support an unprivileged command.

## Approval-gated startup and verification

Starting PostgreSQL is a separate production change and is **not approved by
this PR**. Before an operator starts it, require all of the following:

1. Explicit approval for the named project, network, volume, image tag,
   credential-file location, and maintenance window.
2. A current backup/restore plan and enough disk space for the dedicated
   volume. No production database copy or migration is part of this step.
3. Review of the rendered Compose configuration confirming that `ports` is
   absent, the service uses only `scanlattice_postgresql_private`, and the
   only data mount is `scanlattice_v2_postgresql_data` at
   `/var/lib/postgresql/data`.
4. Confirmation that no v1 app Compose command, `.env`, reverse proxy, DNS,
   worker, or existing volume is included in the change.

Only after those approvals, the operator may start the isolated database with:

```sh
sudo env SCANLATTICE_PG_PASSWORD_FILE=/etc/scanlattice/secrets/postgres-password \
  docker compose --env-file /dev/null -p scanlattice-postgresql \
  -f deploy/compose.postgresql-production.yaml up -d postgres
```

Verify its state without printing environment values:

```sh
sudo env SCANLATTICE_PG_PASSWORD_FILE=/etc/scanlattice/secrets/postgres-password \
  docker compose --env-file /dev/null -p scanlattice-postgresql \
  -f deploy/compose.postgresql-production.yaml ps
sudo env SCANLATTICE_PG_PASSWORD_FILE=/etc/scanlattice/secrets/postgres-password \
  docker compose --env-file /dev/null -p scanlattice-postgresql \
  -f deploy/compose.postgresql-production.yaml exec -T postgres \
  pg_isready -U scanlattice -d scanlattice
sudo docker volume inspect scanlattice_v2_postgresql_data
sudo docker network inspect scanlattice_postgresql_private
sudo docker inspect --format '{{json .NetworkSettings.Ports}}' \
  "$(sudo env SCANLATTICE_PG_PASSWORD_FILE=/etc/scanlattice/secrets/postgres-password docker compose --env-file /dev/null -p scanlattice-postgresql \
    -f deploy/compose.postgresql-production.yaml ps -q postgres)"
```

The port inspection must show no host binding for TCP 5432. The network must
report `Internal: true`; the volume must have the exact dedicated name. Any
web-to-PostgreSQL connection, schema creation/import, migration, v2 image,
proxy change, or cutover needs its own review and explicit approval.

## Rollback

Before any application cutover, rollback is limited to stopping the isolated
PostgreSQL project. Preserve the data volume for investigation or an approved
restore; do not use `down -v`, volume prune, or a project name used by v1:

```sh
sudo env SCANLATTICE_PG_PASSWORD_FILE=/etc/scanlattice/secrets/postgres-password \
  docker compose --env-file /dev/null -p scanlattice-postgresql \
  -f deploy/compose.postgresql-production.yaml stop postgres
sudo env SCANLATTICE_PG_PASSWORD_FILE=/etc/scanlattice/secrets/postgres-password \
  docker compose --env-file /dev/null -p scanlattice-postgresql \
  -f deploy/compose.postgresql-production.yaml down
```

The existing v1 service, its two Compose files, pinned image, SQLite volume,
network, proxy, and AWS worker remain the rollback path. A future app/database
cutover and any restore from PostgreSQL require a separately approved,
rehearsed runbook; this preparation is not that approval.
