# v1.0 Migration and Rollback Guide

This release uses additive SQLite migrations. Keep the old database and backup until integrity and row-count checks pass. Migration runs on application startup and does not drop existing tables.

## WebServer (`web`, `web_scanlattice_data`)

1. Inspect the deployed Compose file, env file, image tag, and volume attachment locally on the server; do not assume it matches this repository.
2. Stop only the web writer: `docker compose -p web -f compose.web.yaml stop web`.
3. Back up with SQLite's online backup API or a stopped-volume archive. Record `PRAGMA integrity_check`, host/service/observation/worker counts.
4. Stage a copy of the backup on isolated ports and a separate staging volume. Run the new image, then compare integrity and counts.
5. Review `.env` changes manually. Never overwrite the production file or create another project/volume name accidentally.
6. After approval, update the existing checkout and use `docker compose -p web -f compose.web.yaml up -d --build` with the existing project and volume.
7. Verify health, login/CSRF, search totals, worker online state, and database counts.

Rollback: stop the new app and restore the pre-migration database from backup. Because migrations are additive, the prior app can normally read the old columns; new data written after migration may not be understood by the old schema. Preserve the migrated database separately until rollback is accepted.

## Scanner01 (`worker-v02`, `worker_worker_state`)

Inspect the running container's mount and preserve the external `worker_worker_state` volume. Back up registration state. Use `docker compose -p worker-v02 -f compose.worker.yaml up -d --build`; do not use `down -v`, do not rename the project, and verify the existing worker identity and heartbeat afterward. The WebServer never runs the scanner package.

This guide is operator-reviewed; no production SSH, Docker, or volume operation is performed by this repository workflow.

## Isolated staging profile

`compose.staging.yaml` binds `127.0.0.1:18080`, uses the fixed volume `scanlattice_staging_data`, reads no production `.env`, and disables external passive refresh. Start with unique staging secrets: `STAGING_ADMIN_TOKEN=... STAGING_ENROLLMENT_TOKEN=... docker compose -p scanlattice-staging -f compose.staging.yaml up -d --build`. For migration validation, copy a verified SQLite backup into that staging volume and set `DATABASE_PATH` to the copied DB path. Do not mount `web_scanlattice_data` or `worker_worker_state`. This staging stack was defined but not launched in this environment.
