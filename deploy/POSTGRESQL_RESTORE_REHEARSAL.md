# ScanLattice v2 — PostgreSQL backup/restore drill

**Development/rehearsal only. This does not back up or restore a production database.**

After the guarded importer has populated `production_rehearsal` in the
disposable Mac Docker PostgreSQL server, the private rehearsal now:

1. Runs `pg_dump -Fc` for that schema, with owner/ACL metadata suppressed.
   Writes the custom archive into its private `/tmp` rehearsal workspace.
2. Reads the archive's table of contents with `pg_restore --list`.
3. Creates a **different, new database** named `scanlattice_restore` in the
   same disposable Docker PostgreSQL instance.
4. Restores the archive into that empty database using `pg_restore
   --exit-on-error` (never using `--clean`, `--create`, or
   `--if-exists`).
5. Compares every PostgreSQL user table in `production_rehearsal` between
   source and restored DB, including exact row count and order-independent
   MD5 aggregate of each row's canonical JSON; also compares sequence
   names/last values and checks the migration completion ledger.
6. Runs the existing SQLite rollback API smoke test and removes the **entire
   disposable Compose project**, archive and temporary folder.

It does not connect to Debian or AWS, use production credentials, mount
`web_scanlattice_data` or `worker_worker_state`, or expose port 5432.

### Operator Mac test

```bash
cd ~/scanlattice-v2-staging
git fetch origin
git switch --track origin/test/v2-postgresql-backup-restore
bash scripts/rehearse_postgresql_from_backup.sh \
  ~/scanlattice-private/scanlattice-backup.db
echo "PostgreSQL backup + restore exit: $?"
```

The prior guarded importer, API and fake worker steps passed on the user's
Mac. **This new pg_dump/pg_restore step has not yet been run there.**

### Still required for a production cutover

- Final frozen and verified SQLite backup AFTER draining AWS worker and
  pausing all SQLite writers.
- Actual production `pg_dump` + an **off-host encrypted copy** and
  independently verified restore, tested against the deployed version of
  PostgreSQL (not just this disposable staging database).
- PostgreSQL credential/permissions and network review; no public 5432.
- Pinned release image digest, control-plane Compose override and reverse
  proxy review, and a complete maintenance / rollback runbook.
- Explicit approval for any web/worker production changes.
- A lossless recovery strategy for any writes accepted in PostgreSQL after
  cutover. Reverting to a pre-cutover SQLite backup without a reverse sync
  would lose that later data.

**Do not use `docker compose down -v`, `docker volume prune`, or
`docker system prune --volumes` on production.**
