# ScanLattice v1.0 Implementation Plan

1. Preserve the v0.4 baseline and production boundary: complete; no production system or volume accessed.
2. Add additive API key, DNS-history, CVE, monitoring, saved-search, import and host-index schema: implemented and exercised against disposable test DBs.
3. Public/admin APIs, query filters, aggregates, host history, CSV and data-backed browser sections: implemented to the scope in `FEATURE_CHECKLIST.md`.
4. Streaming/resumable CSV, JSON/JSONL and gzip ingestion, official NVD/KEV adapters, evidence-based potential CPE correlation, monitor event outbox, notifications and optional schedulers: implemented with deterministic fixtures and regression tests.
5. Python SDK/CLI, endpoint documentation, provider controls, import UI, offline interactive country map and authorized private screenshot library: implemented; automated capture remains external to the application.
6. Isolated staging Compose, CI checks and validation script: defined. Local Docker runtime and restore tests are blocked by Docker unavailability and the lack of an operator-provided database copy.

7. v2 index scheduler milestone: implemented on `feature/v2-index-scheduler`. The DB connection seam defaults to SQLite; additive generations, refresh requests and scan tasks reuse v1 worker jobs; bounded indexed-host planning, idempotency, lease/retry synchronization, protected admin status APIs and the Administration panel are covered by tests. Full suite: 69 passed, 1 opt-in provider test skipped. See `V2_INDEX_SCHEDULER.md`.

## Release readiness checkpoint (2026-11-08)

- Local integrated pytest suite: 59 passed, 1 skipped, 3 framework/client deprecation warnings.
- Local loopback end-to-end harness passed using fresh SQLite state and reserved TEST-NET fixtures; it verified imports/search/ASN/history/CVE/monitoring/maps/screenshots/API/CLI/sessions/worker scheduling and bounded result ingestion.
- Frozen v0.4 snapshot migration check passed without losing fixture rows; no operator database was supplied.
- CSRF now requires a valid session token on browser mutations even if a bad admin header is supplied. The admin monitoring run-once route is protected and included in the API reference inventory.
- Docker Engine/Compose is unavailable in the current environment. No image build or container test has been claimed. `scripts/validate_staging.sh` and `RELEASE_READINESS.md` contain the isolated staging execution path.

### Exact remaining release gates

1. Run `scripts/validate_staging.sh` on an isolated Debian 13 Docker host with unique staging-only credentials; retain command output and logs.
2. Validate the deployed Scanner01 worker registration/claim/result protocol and upgrade compatibility on staging.
3. Restore an authorized sanitized v0.4 database copy into staging; verify integrity, row counts, representative searches, worker registration, backup restore, and rollback.
4. Validate actual NVD/KEV and approved passive-provider refreshes with operator credentials, quotas, and licensing/usage approval. Validate SMTP/webhook delivery and retry behavior.
5. Resolve or explicitly accept the one skipped automated test and approve any remaining limitations in `FEATURE_CHECKLIST.md`.
6. Review `MIGRATION_GUIDE.md`, backups, TLS/secure cookies, production secrets, provider/license requirements, and the production change plan. No production action is authorized or performed by this plan.

8. PostgreSQL milestone: in progress on `feat/postgresql-backend-v1`. This branch adds a psycopg connection adapter, versioned schema bootstrap, PostgreSQL CI/staging configuration, dialect handling for existing search SQL, and a batch-resumable SQLite snapshot importer. Full backend tests and isolated Docker staging are pending; no migration or deployment has run.
