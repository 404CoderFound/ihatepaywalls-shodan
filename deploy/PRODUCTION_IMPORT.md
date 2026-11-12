# ScanLattice v2 — guarded production-import candidate

**Preparation only. Not approved for a production cutover.**

The existing migration script requires --target-is-disposable-staging, which
MUST NOT be used against the permanent PostgreSQL service.

New entrypoint: scripts/import_production_sqlite_snapshot.py

- Defaults to a read-only preflight and does not deploy anything.
- Requires an independently frozen SQLite backup with an operator-provided
  SHA-256. Explicitly refuses a live scanlattice.db file, symlinks, hardlinks,
  WAL/journal sidecars, source files inside the code checkout, failed SQLite
  integrity, and files in known production volume paths.
- Requires the exact expected PostgreSQL host and database, no other
  PostgreSQL clients, and an empty target schema. An already completed,
  checksum-matching import can be reverified. Unrelated or partial imports
  are refused and require manual recovery.
- A real import requires BOTH --execute and --acknowledge-writers-frozen.
  Only an upgraded scratch COPY is imported. The source is never modified.
- After import, all SQLite table counts and source column coverage are
  reconciled with PostgreSQL. Five sample host identities are checked.
- Does not restart the Debian web service, switch reverse proxy routing, or
  connect to the real AWS scanner.

## Offline Docker rehearsal

The existing rehearsal script now additionally runs this new entrypoint,
first in preflight-only mode, then executes and verifies an import into a
SEPARATE new schema called production_rehearsal in its own disposable
PostgreSQL Docker project. It reruns to validate completed-import behavior.
It does not use the real PostgreSQL production volume.

On Mac (private SQLite copy outside repository, as previously used):

    cd ~/scanlattice-v2-staging
    git fetch origin
    git switch --track origin/prep/v2-guarded-production-import
    bash scripts/rehearse_postgresql_from_backup.sh ~/scanlattice-private/scanlattice-backup.db
    echo "Guarded importer rehearsal exit status: $?"

No GitHub Actions are required.

## Release blockers before any production run

- Drain AWS worker + all SQLite writers, verify jobs and capture final
  frozen source snapshot SHA-256. The earlier snapshot is stale.
- Review immutable image builds, web Compose override files, database
  secrets and internal network.
- Rehearse a PostgreSQL backup AND restore to a different empty database.
- Verify worker compatibility beyond fake no-scanning registration, including
  a deterministic offline result-batch life-cycle.
- Approve maintenance and no-loss rollback strategy. After PostgreSQL
  accepts writes, the SQLite snapshot is stale.
- Production execution should be a separate explicitly authorized step:
  never run --execute from instructions alone.
