# ScanLattice v1.0 Feature Checklist

Status records what is implemented in this checkout, not parity with a commercial global search service.

| Area | Status |
|---|---|
| Existing v0.4 schema/API/worker compatibility | Additive tables and route compatibility retained; migration tests use disposable DBs; full restored-production DB migration not tested |
| Public host search and ASN/prefix pagination | Implemented and covered by existing tests |
| Passive RIPEstat/RDAP/CT provider pipeline | Existing adapters retained; externally licensed dataset coverage is not included |
| Host/service observation history and imports | Resumable raw chunk uploads; streaming JSON array/object/JSONL/CSV and gzip; strict truncation/trailing-data validation; restart-idempotent records; indexed ASN/IP/service/provenance; fixture-tested |
| API key lifecycle | Admin create/list/revoke, hashed-at-rest tokens and read-only scopes implemented; per-user accounts/RBAC not implemented |
| Domain history | Imported/stored DNS and passive associations readable; direct DNS history import is admin-only; no application-service probing on public search |
| CVE catalog | Official NVD 2.0 and CISA KEV adapters; bounded retry; resumable NVD pagination; optional daily schedule; CPE range matching and potential-only host correlation; feed import/search/detail/stats tested. Initial full-catalog backfill and live network sync not run |
| Monitoring | Authorized IP/CIDR targets; new-service/software/certificate/vulnerability-change events; expiring certificate checks; optional scheduler; per-event cooldown, acknowledgement, email/webhook outbox, retry and delivery history implemented. Requires configured SMTP/webhook destinations and scheduler opt-in |
| Maps/trends/reports | Interactive offline choropleth using bundled Natural Earth 1:110m boundaries and real indexed country counts; country click-through, hover counts, actual observation-date trends, other aggregates and source-aware CSV export implemented |
| Saved searches | Admin saved-search storage API implemented; edit/delete/user ownership and UI remain incomplete |
| Python SDK/CLI | Dependency-free search/host/history/vulnerability/analytics client, resumable dataset upload and CLI implemented; `/api/docs` includes generated route inventory with public/admin/worker authorization classification; administrator operations beyond dataset ingestion remain REST-only |
| Separate authorized scanning workers | Web image remains scanner-free; worker enforces returned authorization CIDR; admin Scan Now is shown only when an admin-only server check confirms the target is currently within an enabled allowlist; job creation rechecks authorization; no new scan protocols in this work |
| Browser sections | Data-backed domains/network/maps/trends/CVE/monitor/reports/account/API views; provider toggles and resumable dataset upload in Admin; Images is an admin-only library for manually captured PNG/JPEG assets attached to indexed hosts inside an enabled authorization; access is revoked from the library if that authorization is disabled |
| Public API rate limiting | Applied across public `/api/*` reads; tested |
| Production-like staging restore / operator dataset | Isolated Compose file added; restore not run because no operator-provided database copy is available |
| Commercial host-intelligence coverage | Requires provider credentials/license and an approved redistributable dataset; not claimed |
| Production deployment | Not authorized and not performed |

## Verification evidence (2026-11-08)

- `./.venv/bin/python -m pytest -q`: 59 passed, 1 skipped, 3 dependency/framework deprecation warnings.
- `tests/test_v04_migration_readiness.py` builds the fixture from the v0.4 schema snapshot and verifies preserved row counts/representative records plus SQLite integrity after current initialization.
- `scripts/staging_e2e.py` passed against a fresh local loopback Uvicorn + SQLite instance. It covered chunk streaming import, search/ASN attribution, passive-only records, history, CVE correlation, monitoring/outbox, map analytics, screenshots, docs/API key/CLI, CSRF sessions, and worker schedule/lease/result-scope flow. It uses reserved TEST-NET addresses and makes no target connections.
- `.venv/bin/python -m py_compile app/*.py sdk/client.py cli.py scripts/staging_e2e.py`, `node --check app/static/app.js`, `node --check app/static/insights.js`, and `git diff --check` passed.
- `scripts/validate_staging.sh` builds and validates an isolated Compose profile, binds only to loopback, uses a project-scoped volume, and retains that volume after container teardown.
- Docker is unavailable locally; container tests have not been run. CI is configured to run the Compose validator on a Docker-capable runner, but no CI result is available in this audit.
- See `RELEASE_READINESS.md` for incomplete features, provider dependencies, exact Debian 13 staging steps, rollback, and production gates.
