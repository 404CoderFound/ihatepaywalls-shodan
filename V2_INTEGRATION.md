# ScanLattice v2 integration branch

This draft integrates PR #4 (PostgreSQL backend/importer), PR #5 (service fingerprinting) and PR #6 (durable result batches) **without merging any of them to main**.

## Compatible runtime

- The v0.7 agent combines conservative service fingerprints and incremental result uploads. Existing v1 worker API remains available for existing workers.
- The controlplane supports batch status, ingestion, and completion. Both SQLite and PostgreSQL initialize the two new batch receipt tables (SQLite during bootstrap, PostgreSQL through versioned migration 003).
- Both database backends index the same observation and service fields. PostgreSQL support remains experimental until live container tests demonstrate parity.
- The new integration test sends synthetic HTTP and SSH observations through a fake worker and the FastAPI TestClient into the SQLite index. No public network scans occur.

## Validation gate before merge/deploy

1. Run all existing regression tests plus `tests/test_v2_integrated_worker.py`.
2. Run Docker staging for both SQLite and PostgreSQL, including worker enrollment and results, migration/resume and rollback tests.
3. Test worker reconnection between batches and across lease reassignment.
4. Validate schema, index performance, exact-once replays and backward compatibility.
5. Address failures, then only after approval merge a single integrated PR. Do not merge PRs 4/5/6 separately while integration is being validated.

**No production server, AWS worker, database, DNS record, or main branch was changed.**
