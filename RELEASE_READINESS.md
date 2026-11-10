# ScanLattice v1.0 Release Readiness

**Status: not production-ready.** This audit verifies local application behavior and a frozen v0.4 migration fixture. Docker staging, an operator database restore, live provider synchronization, and production deployment were not performed.

## Verified working features

- Unauthenticated public search, passive-only host results, host details/history, ASN attribution, and advanced filters using imported TEST-NET data.
- Streaming/chunked resumable JSON import and indexed service/host profile output. The repo's tests also cover CSV, JSONL, gzip, truncation/retry, and restart behavior.
- NVD-shaped fixture ingestion, CPE-based potential host correlation, vulnerability search/statistics, and vulnerability-change monitor events.
- Admin session login, CSRF mutation checks, invalid-header rejection, authorized-scope job creation, and rejection outside the target allowlist.
- Monitoring service-change and certificate-expiry checks, event history, durable notification outbox, and manual run-once operation. The E2E verifies queued notification state, not delivery to a real SMTP or webhook endpoint.
- Offline map/analytics data, CSV report export, private screenshot upload/content access, API docs inventory, scoped API-key search, and Python CLI search.
- Worker registration, heartbeat scheduling, queued-to-assigned transition, lease claim/start/progress, rejection of out-of-scope job results, and ingestion of a labeled simulated worker result. The WebServer code has no scanner-worker imports; no active scanner module ran.
- Additive v0.4-to-current SQLite initialization against `tests/fixtures_v04_snapshot.sql`, preserving all fixture row counts and representative host, observation, job, service, import, and campaign records; `PRAGMA integrity_check` returned `ok`.
- Admin route authorization is represented in `/api/docs` inventory, including the separately registered intelligence router.

## Incomplete features

- No global host coverage is included. No commercial or licensed host dataset is bundled or claimed.
- Live NVD/KEV and passive-provider refreshes were not run. Full initial NVD catalog backfill and real provider quota behavior remain to be validated with operator-approved credentials/configuration.
- SMTP and webhook delivery to real destinations, retry behavior under an actual provider outage, and scheduled monitoring over a long-running service were not end-to-end exercised. Local tests and the E2E validate outbox/event behavior.
- Automated screenshot capture is not implemented; screenshots are manually supplied, and application access is restricted to authorized assets.
- Interactive map rendering/click-through was not browser-automated in this audit; the local E2E verified the map-backed aggregate API and bundled boundaries are covered by unit tests.
- Saved-search edit/delete and per-user ownership are absent; administrator operations are not all wrapped in the Python CLI/SDK. See `FEATURE_CHECKLIST.md` for the broader implemented scope and limitations.
- Docker image build, Compose deployment/health, container E2E, worker image compatibility in staging, and staging teardown/volume isolation have not been run locally because Docker is unavailable.
- No production or operator-provided database copy was inspected. The frozen fixture demonstrates data preservation for its v0.4 schema and records, not every possible production-specific database state.

## Actual test results

Environment: macOS development checkout, commit base `8fffcb57c4e643a6970371531802fd1d98b89c6a`; Python 3.14 virtual environment. All E2E service state was stored in a fresh `/tmp` SQLite file. Fixtures use documentation-only TEST-NET IP ranges.

- `.venv/bin/python -m pytest -q`: **59 passed, 1 skipped, 3 warnings**. Warnings are framework/client deprecations (`TestClient`/httpx and FastAPI `on_event`).
- `STAGING_URL=http://127.0.0.1:18083 STAGING_ADMIN_TOKEN=<local-test-token> STAGING_ENROLLMENT_TOKEN=<local-test-token> .venv/bin/python scripts/staging_e2e.py`: **passed** against a fresh local Uvicorn process. Covered chunk streaming/import, search, ASN host-only attribution, passive-only records, host history, CVE correlation, monitor events/outbox, analytics/map data, screenshots, docs/API key/CLI, CSRF sessions, and worker scheduling/result scope.
- `.venv/bin/python -m py_compile app/*.py sdk/client.py cli.py scripts/staging_e2e.py`: passed.
- `node --check app/static/app.js` and `node --check app/static/insights.js`: passed.
- `git diff --check`: passed.
- Docker availability check: no `docker` or `docker-compose` executable found. **No container test passed or was claimed.**

### CI failure investigation (2026-11-10)

- GitHub Actions run [42882609443](https://github.com/404CoderFound/ihatepaywalls-shodan/actions/runs/42882609443), commit `5732e5a019b76822d7aece4b2d5364e004da9777`, concluded `failure` before a runner started. The public check-run annotation says: **“The job was not started because your account is locked due to a billing issue.”** The job has runner ID `0` and no executed steps. This is an account/billing blocker, not a failing test or repository workflow command, so it cannot be repaired by a source change. Re-run CI after the repository owner restores Actions billing. This checkout is not authenticated to GitHub and cannot re-run the workflow or create the PR.
- Updated `worker/Dockerfile` to copy worker files with `COPY --chown=10001:10001`.
- Expanded `scripts/validate_staging.sh` to build and inspect the worker image (without starting the scanner loop), run the staged E2E including administrator job cancellation, and execute SQLite `PRAGMA integrity_check` inside the staging web container. These Docker steps remain unverified locally because Docker Engine/Compose are absent.

The local HTTP run used `SESSION_COOKIE_SECURE=false` only for loopback transport. The staging Compose profile sets the same staging-only value and binds its service to `127.0.0.1`; production cookie security is not changed.

### Follow-up on main (2026-11-10; branch `fix/v2-ci-staging`)

- Re-ran `.venv/bin/python -m pytest -q -rs`: **69 passed, 1 skipped, 3 warnings**. The skipped test is still the opt-in live RIPEstat integration. No tests were disabled.
- Python compilation for application/SDK/CLI and JavaScript syntax checks passed. The updated worker source is also covered by the worker-image runtime ownership probe in `scripts/validate_staging.sh`; that image probe needs Docker.
- Re-ran `scripts/staging_e2e.py` against a fresh loopback Uvicorn/SQLite instance after extending it to submit and cancel a separate authorized job: **passed**. The harness exercises worker enrollment, heartbeat/scheduling, claim/start/progress, out-of-scope result rejection, valid result ingestion, administrator cancellation, and public search/job separation. Its worker is a protocol fixture; no scanner module or target probe ran.
- Local `PRAGMA integrity_check`: **ok** on the fresh E2E database. `sh -n scripts/validate_staging.sh` and `git diff --check`: passed.
- `scripts/validate_staging.sh` was invoked and exited **2** with “Docker is required for container validation.” `docker` and `docker compose` are absent. Container builds, image ownership inspection, isolated Compose E2E, and in-container integrity checks remain unverified.
- Investigated CI run [42882609443](https://github.com/404CoderFound/ihatepaywalls-shodan/actions/runs/42882609443) for commit `5732e5a019b76822d7aece4b2d5364e004da9777`. The GitHub check annotation states that the job **was not started because the account is locked due to a billing issue**; runner ID is 0 and the job has no executed steps. This is not a code/test failure and cannot be fixed in the repo. Re-enable billing and rerun Actions before treating CI as passing.
- `worker/Dockerfile` now uses `COPY --chown=10001:10001`. The Docker staging validator builds and checks the worker image without starting its scanner loop. PostgreSQL groundwork is being implemented on a separate feature branch: its backend, schema, isolated profile, and importer are not yet validated by Docker or CI and are not part of this release-readiness result. See `POSTGRES_MIGRATION_PLAN.md` for the remaining gates.

## Docker tests still required

Run the isolated staging procedure below on a Docker-capable Debian 13 host. A passing local Python E2E does not substitute for these checks. Preserve the output of `scripts/validate_staging.sh`, `docker compose ps`, and staging logs for the release record.

- Compose config isolation, image build, container health, API checks, and the complete `scripts/staging_e2e.py` run.
- Worker image build and assertion that all `/srv/worker` paths and the runtime process use UID 10001.
- Administrator cancellation and SQLite `integrity_check` assertions added to the staging validator.
- Repeat using the `scanner01` worker image/configuration if its deployment is separate from this repository; verify existing registration/token compatibility and worker result ingestion.
- Validate upgrade and rollback from a copy of the intended v0.4 database. Never point staging at production data or production volumes.

## Data provider dependencies

- Dataset imports require an operator-supplied dataset and the rights to use it. The included E2E file is synthetic fixture data, not a coverage source.
- NVD CVE API v2 is public but quota-limited; an `NVD_API_KEY` is optional and improves quota. CISA KEV feed is public. Initial backfill volume, API quota, and feed terms must be accounted for before enabling scheduled refresh.
- RDAP/RIPEstat and Certificate Transparency/passive DNS adapters depend on provider availability, provider-specific usage terms, and configured endpoints/credentials. Cached/imported results work without live provider calls.
- No passive DNS subscription, Shodan license, commercial dataset, API credential, SMTP account, or webhook destination was provided or used for this audit.

## Known issues and release gates

- The app is a useful indexed-intelligence platform but is not equivalent to Shodan's global sensor coverage.
- The database migration check is a synthetic v0.4 snapshot test; a sanitized operator restore is still required to validate production-specific schema/data and restore procedure.
- The isolated staging profile intentionally disables passive live enrichment and background monitor/NVD schedulers. This prevents staging tests from using external providers; operator-configured provider validation is a separate staging gate.
- `compose.staging.yaml` disables the secure-cookie flag because its HTTP listener is bound only to loopback for local/staging E2E. Production must be behind TLS with secure cookies enabled.
- The single skipped test is the opt-in live RIPEstat integration (`RUN_PROVIDER_INTEGRATION=1`); it was intentionally skipped because external provider calls/credentials were outside this isolated audit. Run it during provider-enabled staging if its terms and quotas permit.
- Deprecation warnings should be addressed in a later compatibility update; they did not fail this test run.

Do not mark v1.0 production-ready until staging validation, restore/rollback rehearsal, provider/license review, external notification checks, and production prerequisites below have passed.

## Debian 13 staging deployment commands

Run from a clean checkout of the release commit on an isolated staging server. Docker Engine with the Compose v2 plugin and Python 3 are required. These commands do not read `.env`, mount production volumes, or connect to a production server. Port `18080` is bound on loopback only; change it if already used.

```sh
cd /opt/scanlattice/scanlattice
umask 077
export STAGING_PROJECT="scanlattice-v1-$(date +%s)"
export STAGING_PORT=18080
export STAGING_ADMIN_TOKEN="$(openssl rand -hex 32)"
export STAGING_ENROLLMENT_TOKEN="$(openssl rand -hex 32)"

docker compose --env-file /dev/null -p "$STAGING_PROJECT" \
  -f compose.staging.yaml config
docker compose --env-file /dev/null -p "$STAGING_PROJECT" \
  -f compose.staging.yaml up -d --build
curl --fail http://127.0.0.1:$STAGING_PORT/api/health
STAGING_URL="http://127.0.0.1:$STAGING_PORT" \
  STAGING_ADMIN_TOKEN="$STAGING_ADMIN_TOKEN" \
  STAGING_ENROLLMENT_TOKEN="$STAGING_ENROLLMENT_TOKEN" \
  python3 scripts/staging_e2e.py
docker compose --env-file /dev/null -p "$STAGING_PROJECT" \
  -f compose.staging.yaml ps
docker compose --env-file /dev/null -p "$STAGING_PROJECT" \
  -f compose.staging.yaml logs --no-color --tail=300
```

To run the complete isolated build/health/E2E validator automatically, use a fresh project and free port:

```sh
STAGING_PROJECT="scanlattice-v1-check-$(date +%s)" \
STAGING_PORT=18081 \
STAGING_ADMIN_TOKEN="$(openssl rand -hex 32)" \
STAGING_ENROLLMENT_TOKEN="$(openssl rand -hex 32)" \
scripts/validate_staging.sh
```

The validator stops the staging container/network on exit and retains the project-scoped named data volume for inspection. To keep its container running for manual review, set `KEEP_STAGING=true`; clean it up with the same Compose project and staging file. It refuses an occupied loopback port, an existing project container, or an existing same-name staging volume. Do not reuse any production project/volume name.

## Rollback procedure

1. Stop only the named staging project, preserving its volume:

   ```sh
   docker compose --env-file /dev/null -p "$STAGING_PROJECT" \
     -f compose.staging.yaml down
   ```

2. To discard staging test data, first inspect the exact volume and confirm its Compose project label is the staging project, then remove only that volume:

   ```sh
   docker volume inspect "${STAGING_PROJECT}_scanlattice_staging_data"
   docker volume rm "${STAGING_PROJECT}_scanlattice_staging_data"
   ```

3. To roll back a staging code upgrade, deploy the prior known-good release commit/image using a new staging project name. Keep the failed staging volume for diagnosis until its data is explicitly no longer needed.
4. For a future production migration rollback, stop production writes, restore the verified pre-migration database backup to a new path/volume, verify it with SQLite integrity checks and an application smoke test, then switch back only under an approved production change. **This procedure has not been rehearsed on production data and is not authorization to access production.** Do not attempt a down-migration or overwrite the only backup.

## Production deployment prerequisites

- Successful Docker staging and scanner worker compatibility validation, plus a restore/rollback rehearsal against an authorized sanitized copy of the real v0.4 database.
- Verified encrypted and restorable backups, disk capacity, migration duration/locking assessment, and named production data-volume inventory.
- Production-grade unique secrets; TLS termination; secure admin cookies; access restrictions and rate-limit sizing; admin credential rotation and recovery procedure.
- Approved data-provider credentials, licenses/redistribution rights, quotas, caching/retention policy, and provider-specific opt-in configuration.
- SMTP/webhook configuration and delivery/retry validation; monitoring, alert routing, and scheduler sizing.
- A production change window and explicit authorization. No production servers, secrets, volumes, or databases were accessed or changed during this work.
