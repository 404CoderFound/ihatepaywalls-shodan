# PostgreSQL production template — not yet approved

This file is for review **only**. Nothing here deploys a service, edits the
existing Docker project, or makes a production schema migration.

`deploy/compose.postgresql-production.yaml` defines a separate PostgreSQL 17
container with persistent volume `scanlattice_v2_postgresql_data`, joining
only the externally managed network `web_default`. TCP 5432 is **not**
published onto the host or internet. The existing SQLite volume
`web_scanlattice_data` is never mounted, referenced or modified.

A strong database password must be stored in a root-protected file **outside**
the repository and supplied by the
`SCANLATTICE_PG_PASSWORD_FILE` environment variable. The existing
control-plane `web` project uses two Compose files and must not be
recreated or overridden while preparing PostgreSQL. Existing AWS worker
project `scanlattice-aws` and external volume `worker_worker_state`
remain unchanged; the worker does not connect to PostgreSQL directly.

## Local validation before any deployment

On the Mac testing checkout, run:

```bash
cd ~/scanlattice-v2-staging
git fetch origin
git switch --track origin/prep/v2-postgresql-prod-template-worker-contract
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
