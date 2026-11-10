# Durable result batches — incremental v2 milestone

Status: draft feature branch. No deployment or database migration has occurred.

## What changed

- Existing v1 workers still use \`POST /api/worker/jobs/{id}/results\`. Existing wire fields, leases, and credentials remain valid.
- Updated workers (agent v0.6) use **batched result uploads** with a maximum of 128 endpoint checks and observations per batch.
- Workers spool each chunk to their persistent \`/data/batch-spool/<job UUID>\` volume **before** uploading. The spool uses atomic rename and file + directory fsync. Successful acknowledgements advance a durable checkpoint and free old chunks, keeping disk use bounded (128 MiB spool safety cap).
- Open-ended futures lists and whole-job observation arrays have been replaced by a bounded scanner thread pool and a lazy endpoint iterator. A worker only retains one small chunk in memory.
- The SQLite schema gains two additive tables (\`scan_result_batches\`, \`scan_result_finishes\`). Each accepted batch records a deterministic SHA-256 payload hash and monotonic cumulative check count in the same database transaction as observations.
- Lost HTTP replies replay safely: matching batch index and payload return \`already_processed\`, different payloads and missing earlier batches fail closed. A GET checkpoint allows a different worker to skip batches already acknowledged by the server.
- The finalization endpoint completes the original v1 job only when the full cumulative check count and exact number of consecutive batches are committed. Worker lease, scope, cancellation, and revocation checks still apply.

## HTTP worker API

1. Claim/start via existing v1 routes.
2. \`GET /api/worker/jobs/{id}/results/batches/status\` returns \`{status:"running", batch_count, checks_done, progress_total}\` with a valid current worker assignment and lease.
3. \`POST /api/worker/jobs/{id}/results/batches\` takes \`{lease_token, batch_index, checks_done, observations}\`. \`checks_done\` is cumulative, never a per-batch delta. Batches must be sequential; each may advance at most 128 checks. Empty observations are allowed for scans with no open ports.
4. \`POST /api/worker/jobs/{id}/results/complete\` takes \`{lease_token, batch_count, completed_checks}\` and seals the job once all checks are accounted for. Completion is idempotent.
5. A job cannot mix the legacy single result endpoint and batched result mode. v1 workers remain compatible.

## Deployment order and operational limits

1. Run the full local test suite and isolated Docker staging tests on the branch. GitHub Actions currently has an account billing blocker; no green CI is claimed.
2. Deploy the **server/controlplane first**, after backups and approval. \`init_db()\` creates additive tables. Do not deploy the worker first because its new API endpoints would not exist on an older controlplane.
3. Deploy new worker images one by one after the server is verified. Preserve the existing external named \`worker_worker_state\` volume; deleting it loses local unsent batches and registration state.
4. Monitor \`scan_result_batches\` growth, lease expiry, restart counts, partial job retries, and ingestion errors.
5. Roll back the worker image before the server. Stop/drain in-progress batch jobs and retain the added tables to avoid stranded work.

The existing target-scope policy is not changed. This milestone does **not** provide unbounded Internet-wide scanning, does not bypass any authorization checks, and has no PostgreSQL implementation yet. A future PostgreSQL integration must migrate both additive batch tables and preserve their unique keys.

## Known limitations

- A worker can resume from the last *committed* chunk on a different node, but an interrupted, uncommitted chunk may be probed again. Results are not lost from acknowledged chunks.
- Jobs still respect existing attempt limits and leases; terminally failed/cancelled jobs do not resume.
- A fully disconnected worker cannot renew its server lease; re-assignment occurs through the existing queue.
- TLS probing, service fingerprinting (PR #5), and PostgreSQL backend (PR #4) are separate unmerged features.
- Docker staging, full integration tests, and live worker upgrades have **not** been performed as part of this commit.
