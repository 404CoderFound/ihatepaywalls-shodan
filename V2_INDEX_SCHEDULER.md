# v2 Index Scheduler milestone

This milestone adds an explicit, administrator-triggered asynchronous refresh workflow while keeping the v1 public search API and scanner worker protocol intact.

## Behavior and bounds

- Public `GET /api/search` remains read-only. It does not create refresh requests, generations, scan tasks, or active scan jobs.
- `POST /api/admin/refresh-requests` requires the existing admin token/session authorization and returns `202 Accepted`. Requests support exactly one `ip:`, `net:` (CIDR), or `asn:` target with an optional single `port:` filter.
- Exact IP requests target that IP. CIDR and ASN requests select only already-indexed hosts; CIDRs are never expanded and ASN requests do not fan out through announced prefixes.
- Targets outside enabled authorizations are excluded and returned in `rejected_targets`. If no target is authorized, the request fails closed. Defaults cap a request at 256 candidate hosts and 25,600 host/port checks (`MAX_REFRESH_TARGETS`, `MAX_REFRESH_CHECKS`); existing port/profile limits also apply.
- Revoking an authorization cancels its queued/leased/running v1 jobs, including v2-backed tasks. Worker claim and start paths also require an enabled authorization.
- Refresh request idempotency uses the `Idempotency-Key` header. When omitted, equivalent requests collapse within a five-minute bucket. Each per-host task has its own unique task key.
- Every v2 scan task is backed by one existing v1 `scan_jobs` row containing one IP and its bounded port set. Existing claim/start/progress/results APIs and Scanner01 remain the execution path. Result idempotency and worker leases remain enforced by v1 job APIs. Browser session+CSRF authorization works alongside the existing admin-token API.
- Task state mirrors its backing job. Lost leases and explicit worker failures requeue v2 jobs with bounded exponential delay, then stop after the existing maximum attempt count. V1 jobs retain the existing failure behavior.
- V2 jobs carry a `requested_worker_id` sentinel that the new scheduler recognizes. A rollback to the old v1 scheduler will not assign these queued jobs to workers accidentally; cancel/drain tasks before rollback as described below.

## Administrator API

- `POST /api/admin/refresh-requests` — queue a bounded refresh; body: `{"query":"asn:AS64496 port:443","profile_id":1}`; optional `ports` must match a `port:` filter.
- `GET /api/admin/refresh-requests` and `GET /api/admin/refresh-requests/{id}` — inspect request and generation status.
- `GET /api/admin/scan-generations` — status counters per generation.
- `GET /api/admin/scan-tasks` — task state, attempt number, target, ports, and worker name. Lease tokens are never returned.
- `POST /api/admin/scan-generations/{id}/cancel` — cancel queued/leased/running tasks through their backing v1 jobs.

The existing Administration page has an “Asynchronous indexed refresh” form and request status table. It reuses an idempotency key for a pending browser submission and reports targets excluded by authorization.

## Database and deployment

`DATABASE_BACKEND=sqlite` remains the default backend. The PostgreSQL connection backend, versioned bootstrap schema, compatibility SQL layer, isolated staging profile, CI service, and resumable SQLite snapshot importer are under development on the PostgreSQL milestone branch. Full backend parity and staging execution remain required before production use.

`init_db()` additively creates `scan_generations`, `scan_refresh_requests`, and `scan_tasks`. It does not rewrite existing v1 `scan_jobs`, observations, authorizations, worker credentials, or results. Upgrade steps:

1. Take and verify a normal backup of the SQLite database and worker registration state.
2. Deploy this branch to a non-production copy and let the normal application startup run `init_db()`.
3. Verify `PRAGMA integrity_check`, public search, worker heartbeat/claim/result calls, admin refresh statuses, and cancellation.
4. For a controlled production rollout, stop the application, take a final backup, deploy the commit, and restart. No production migration has been run as part of this branch.

## Rollback

1. Stop accepting new v2 refresh requests.
2. Cancel all nonterminal generations through the v2 admin endpoint. Wait for any already-running worker job to stop or expire; stop scanner workers during the application downgrade to avoid an in-flight result racing with rollback.
3. Deploy the prior v1 application. Its scheduler does not recognize `__scanlattice_v2_scheduler__`, so queued v2 jobs remain unassigned. Existing v1-created jobs continue to work.
4. Leave the three v2 tables and sentinel-marked rows in place. They are additive; do not delete or rename columns/tables during rollback. Restore the pre-upgrade database backup only if the migration itself damaged the database, after stopping all writers and verifying the backup.
5. To resume v2 later, redeploy the feature commit and inspect the retained generation/task status before submitting new requests.
