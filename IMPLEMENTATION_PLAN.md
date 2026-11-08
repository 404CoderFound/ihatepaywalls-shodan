# ScanLattice v1.0 Implementation Plan

1. Preserve the v0.4 baseline and production boundary: complete; no production system or volume accessed.
2. Add additive API key, DNS-history, CVE, monitoring, saved-search, import and host-index schema: implemented and exercised against disposable test DBs.
3. Public/admin APIs, query filters, aggregates, host history, CSV and data-backed browser sections: implemented to the scope in `FEATURE_CHECKLIST.md`.
4. Streaming/resumable CSV, JSON/JSONL and gzip ingestion, official NVD/KEV adapters, evidence-based potential CPE correlation, monitor event outbox, notifications and optional schedulers: implemented with deterministic fixtures and regression tests.
5. Python SDK/CLI, endpoint documentation, provider controls and import UI: implemented; remaining API parity and image/map capabilities are listed explicitly in the checklist.
6. Isolated staging Compose, CI checks and validation script: defined. Local Docker runtime and restore tests are blocked by Docker unavailability and the lack of an operator-provided database copy.

## Remaining work and exact handoff

- Run the full local suite, Python compilation, JavaScript syntax checks, Compose configuration check (when Docker is installed) and inspect migration behavior against an operator-provided sanitized production DB copy.
- Run `STAGING_ADMIN_TOKEN=... STAGING_ENROLLMENT_TOKEN=... scripts/validate_staging.sh` on a Docker-capable staging host using staging-only credentials.
- Build the interactive geographic map and authorized screenshot workflow before claiming those checklist rows complete.
- Run the NVD initial catalog backfill and provider integrations only after operators supply credentials, acceptable quotas, and licensed/redistributable dataset sources.
- Review `MIGRATION_GUIDE.md` before any future production cutover. No production action is authorized by this plan.

The production cutover, external API credentials, redistribution permissions, and a real owned scan target remain operator-controlled. No production system or volume is accessed here.
