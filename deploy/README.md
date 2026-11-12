# PostgreSQL production template — not yet approved

This file is for review **only**. Nothing here deploys a service, edits the
existing Docker project, or makes a production schema migration.

`deploy/compose.postgresql-production.yaml` defines a separate PostgreSQL 17
container with persistent volume `scanlattice_v2_postgresql_data`, joining
only the dedicated internal Docker bridge `scanlattice_postgresql_private`.
TCP 5432 is **not** published onto the host or internet. The existing SQLite
volume `web_scanlattice_data` is never mounted, referenced or modified. The
v1 web service is not attached to the PostgreSQL network by this preparation.

A strong database password must be stored in a root-protected file **outside**
the repository and supplied by the
`SCANLATTICE_PG_PASSWORD_FILE` environment variable. The existing
control-plane `web` project uses two Compose files and must not be
recreated or overridden while preparing PostgreSQL. Existing AWS worker
project `scanlattice-aws` and external volume `worker_worker_state`
remain unchanged; the worker does not connect to PostgreSQL directly.

The secret file should be `root:root` with mode `0600`. Compose must be able
to read that file and access the Docker daemon socket. Use a controlled root
invocation such as `sudo env SCANLATTICE_PG_PASSWORD_FILE=/etc/scanlattice/secrets/postgres-password docker compose ...`.
The `scanlattice-deploy` SSH key does not grant these rights. Do not add that
account to the `docker` group, since Docker access is effectively root. If
delegated access is required, use a reviewed root-owned wrapper restricted to
the fixed Compose project and file; do not weaken the secret-file mode.

## Local validation before any deployment

Run the production Compose safety tests with the normal pytest suite. They
check that 5432 is not published, the network is internal, the PostgreSQL
data directory uses its dedicated persistent volume, and credentials come
from an external file path. When Docker Compose is available, an additional
test renders the Compose file with a temporary local-only secret file; it
does not create resources. For a real but disposable local smoke test, run
`python3 scripts/smoke_postgresql_production_template.py`. It requires a local
Unix-socket Docker context, uses unique resources and a temporary secret, and
removes only what it created. It never targets a server context. See
[`PRODUCTION_POSTGRES_PREPARATION.md`](PRODUCTION_POSTGRES_PREPARATION.md)
for the approval-gated host steps, verification, and rollback.

On the Mac testing checkout, run:

```bash
cd ~/scanlattice-v2-staging
git fetch origin
git switch --track origin/feature/v2-integrated-pg-scanner
bash scripts/rehearse_postgresql_from_backup.sh \
  ~/scanlattice-private/scanlattice-backup.db
echo "Migration + fake worker test exit: $?"
```

The rehearsal imports the private SQLite backup **copy** into isolated
PostgreSQL, checks the v2 API, then registers a fake worker without scan
capabilities; its heartbeat and claim APIs are tested without any real
network probes. The disposable PostgreSQL volume is removed after the test.

**Blockers before production:** a separate production-safe importer (the
existing importer refuses real production without staging-only flag),
verified PostgreSQL backup/restore and final frozen SQLite backup, drained
AWS worker and writers, immutable image pinning, complete Compose/proxy
review, and explicit operator approval. Never run `down -v` or
`docker volume prune` against production.
