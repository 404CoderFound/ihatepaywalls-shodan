# ScanLattice v1.0 Architecture

The WebServer remains the transactional control plane: FastAPI, SQLite/WAL, passive provider adapters, public search/read APIs, import jobs, monitoring rules, vulnerability catalog, admin APIs, and the static client. SQLite tables are additive so existing v0.4 observations, worker registrations, authorization records, sessions, and jobs remain in place.

The scanner image remains separate and outbound-only. Only worker endpoints receive scan tasks, and authorization is checked when jobs are created and when results return. Passive provider calls are host allowlisted and never target discovered application services.

Search and analytical reads use SQLite indexes and aggregates. Larger deployments can move the same logical records behind PostgreSQL/OpenSearch after measured data volumes justify operating them. Redis, ClickHouse, and object storage are not required for this single-node release.

Evidence is kept with source, timestamps, collection method, confidence, and current/stale status. CVE/banner correlations are potential matches and never prove exploitation. Geolocation is approximate. DNS lookups explicitly identify direct resolver results.
