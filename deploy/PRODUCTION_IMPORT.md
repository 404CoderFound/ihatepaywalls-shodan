# Guarded SQLite to PostgreSQL migration procedure

**Runbook preparation only. PostgreSQL startup, migration, traffic changes, and
deployment are separate operator-approved production actions.** This importer
does not stop writers, start services, deploy images, run scans, or switch
traffic. Its dry-run is read-only against PostgreSQL. The execute path only
writes to the exact database/schema supplied and refuses any non-empty or
unrelated target.

## Source and target safety

The importer requires all of the following before either dry-run or execute:

- A frozen SQLite snapshot outside the checkout, created from a consistent
  SQLite backup after all writers have been drained and stopped.
- A separate verified rollback copy stored in the operator-approved backup
  location. Both files must be regular, non-symlinked, single-link files with
  mode `0600` or stricter, pass `PRAGMA integrity_check`, have no WAL/journal
  sidecars, and match the supplied SHA-256. Snapshot and rollback copy must be
  byte-identical but have distinct file identities.
- An explicit PostgreSQL DSN host and database matching both the operator's
  `--expected-host`/`--expected-database` values and the connected database.
  Do not place credentials in command arguments or shell history.
- A target schema that is empty, or a schema containing only a completed,
  checksum-matching import of this exact snapshot. Existing tables, views,
  foreign tables, materialized views, unrelated sequences, partial imports,
  other client sessions, and mismatched import ledgers are rejected.

The import preserves source IDs. Before declaring success it verifies source
and target table inventories, source-column coverage, row counts, bounded
order-independent ID fingerprints and maxima, host identity samples, and
PostgreSQL identity-sequence alignment. The import ledger makes a matching
completed invocation idempotent. Interrupted or inconsistent imports require
manual investigation; do not drop or overwrite a schema to make a retry pass.

## GO / NO-GO gates

**GO requires written operator approval for this exact source SHA, target
host/database/schema, maintenance window, and rollback plan, plus every check
below.** If any check fails or is unknown, the decision is NO-GO.

1. Drain ScannerAWS01 and stop every process that can write to the v1 SQLite
   database. Verify there are no active or queued writers and scanning is
   paused. Keep the v1 service and worker available only as explicitly planned
   for the maintenance window; no scanner work may run during this procedure.
2. Create a consistent SQLite backup using SQLite's backup API after the
   write freeze. Copy it to a separate, protected rollback location. Record
   both SHA-256 values independently; they must match. Store files mode `0600`
   or stricter and retain an additional protected backup according to the
   site's backup policy.
3. Verify SQLite integrity, required ScanLattice tables, file ownership and
   permissions, no sidecars, and unchanged hashes. Preserve the exact frozen
   backup; never point this importer at the live `scanlattice.db` or a
   production Docker volume path.
4. Verify the target host/database/schema through a read-only preflight. The
   PostgreSQL service must already exist in an approved isolated environment;
   this runbook does not start production PostgreSQL. Confirm the schema is
   empty and there are no other database clients.
5. Rehearse the same backup hash and migration build against disposable local
   PostgreSQL, including rollback and restore checks. Do not run discovery or
   external scanning during rehearsal.
6. Obtain explicit written GO approval. Record its change/ticket reference.
   Only then run the execute command with `--execute`,
   `--acknowledge-writers-frozen`, and `--go-approval-reference <approved-id>`.
   The importer refuses execute without all three gates. They do not grant
   deployment or traffic-switch permission.

Example dry-run. Keep the DSN in a protected environment or service manager;
never echo it or put its password in a command line:

```sh
export DATABASE_URL='postgresql://<secret-managed-user>@<approved-host>:5432/<approved-db>'
python3 scripts/import_production_sqlite_snapshot.py \
  /secure/frozen/scanlattice-snapshot.sqlite \
  --source-sha256 '<snapshot-sha256>' \
  --rollback-backup /secure/rollback/scanlattice-snapshot.sqlite \
  --rollback-backup-sha256 '<independently-verified-backup-sha256>' \
  --expected-host '<approved-postgresql-host>' \
  --expected-database '<approved-database>' \
  --schema '<new-empty-migration-schema>'
```

The execute command is the same invocation with `--execute
--acknowledge-writers-frozen --go-approval-reference <approved-id>`, and is
allowed only after the GO gates and written approval. Do not run it as part of
a deployment hook.

## Rehearsal and tests

For a private SQLite backup copy, the local rehearsal script starts its own
uniquely named disposable Docker Compose project, generates staging-only
credentials, binds the web test port to loopback, imports into PostgreSQL,
checks API/worker behavior without scanner capabilities, verifies IDs,
counts and sequences, and tears down only that project's resources. The
script refuses a backup inside the checkout and never connects to a server.
It also tests the guarded importer in dry-run mode, executes it only against a
separate disposable schema with the frozen-writer acknowledgement, and checks
completed-import idempotence.

```sh
bash scripts/rehearse_postgresql_from_backup.sh \
  /private/local-copy/scanlattice-backup.sqlite
```

The standalone local tests for the guarded importer use synthetic SQLite
files and fake PostgreSQL connections; they do not contact a live database.
The Docker rehearsal is the integration check against disposable PostgreSQL.
No GitHub Actions or CI run is required for this runbook.

## Rollback and NO-GO

Before PostgreSQL accepts application writes, the rollback point is the
preserved frozen SQLite backup and the unchanged v1 Compose pair. Stop the
candidate app/database only under the approved runbook and restore v1 routing
manually after validating SQLite integrity and the v1 API/worker health.
Never overwrite the original SQLite file or its only backup.

After PostgreSQL accepts application writes, pointing v1 back to the old
SQLite snapshot would lose those writes. Stop the cutover and keep PostgreSQL
as the authoritative copy until a separately rehearsed reverse-export and
reconciliation has produced and verified a new SQLite rollback copy. That
reverse migration and all service/proxy changes are outside this importer.

NO-GO conditions include any changed source hash, missing rollback copy,
active writer/scanner, target identity mismatch, any unexpected target
object/client, reconciliation or sequence mismatch, failed health checks,
insufficient backup/storage verification, or absent operator approval.
Production v1, AWS worker, secrets, PostgreSQL startup, network/proxy/DNS,
migrations and traffic remain untouched until their own explicit approvals.
