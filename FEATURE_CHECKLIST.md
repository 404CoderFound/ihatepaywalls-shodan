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
| Python SDK/CLI | Dependency-free search/host/history/vulnerability/analytics client, resumable dataset upload and CLI implemented; administrator operations beyond dataset ingestion remain REST-only |
| Separate authorized scanning workers | Existing architecture preserved; no new scan protocols or scheduler expansion in this work |
| Browser sections | Data-backed domains/network/maps/trends/CVE/monitor/reports/account/API views; provider toggles and resumable dataset upload in Admin; image section explicitly reports no screenshots and does not probe remote hosts |
| Public API rate limiting | Applied across public `/api/*` reads; tested |
| Production-like staging restore / operator dataset | Isolated Compose file added; restore not run because no operator-provided database copy is available |
| Commercial host-intelligence coverage | Requires provider credentials/license and an approved redistributable dataset; not claimed |
| Production deployment | Not authorized and not performed |

## Verification evidence (2026-11-08)

- `./.venv/bin/pytest -q`: 53 passed, 1 skipped, 3 dependency/framework deprecation warnings.
- `python -m py_compile app/*.py sdk/client.py cli.py` and `node --check` are in CI.
- `scripts/validate_staging.sh` provides isolated Compose health/API validation and retains its named staging volume on teardown.
- Docker is not installed in the local development environment; the staging container workflow has not been run locally. CI is configured to run it on a Docker-capable runner.
