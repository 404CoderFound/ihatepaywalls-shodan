# ScanLattice v1.0 Feature Checklist

Status records what is implemented in this checkout, not parity with a commercial global search service.

| Area | Status |
|---|---|
| Existing v0.4 schema/API/worker compatibility | Additive tables and route compatibility retained; full restored-production DB migration not tested |
| Public host search and ASN/prefix pagination | Implemented and covered by existing tests |
| Passive RIPEstat/RDAP/CT provider pipeline | Existing adapters retained; externally licensed dataset coverage is not included |
| Host/service observation history and imports | Existing observation store retained; JSON/CSV imports; large resumable streaming/GZIP imports remain incomplete |
| API key lifecycle | Admin create/list/revoke, hashed-at-rest tokens and read-only scopes implemented; per-user accounts/RBAC not implemented |
| Domain history | Imported/stored DNS and passive associations readable; direct DNS lookup/history ingestion interface not implemented |
| CVE catalog | Admin import and public search implemented; NVD/CISA automatic sync and host/CPE correlations remain incomplete |
| Monitoring | Authorized IP/CIDR targets and ingested new-service/software-change event inbox implemented; schedulers, cooldown/ack, notifications and domain/service policies remain incomplete |
| Maps/trends/reports | Real database aggregates and CSV export implemented; interactive geographic map and advanced time-series/facets remain incomplete |
| Saved searches | Admin saved-search storage API implemented; edit/delete/user ownership and UI remain incomplete |
| Python SDK/CLI | Basic dependency-free read client and CLI implemented |
| Separate authorized scanning workers | Existing architecture preserved; no new scan protocols or scheduler expansion in this work |
| Browser sections | Navigation and data-backed domains/network/maps/trends/CVE/monitor/reports/account/API views added; screenshots intentionally absent |
| Public API rate limiting | Applied across public `/api/*` reads; tested |
| Production-like staging restore / operator dataset | Isolated Compose file added; restore not run because no operator-provided database copy is available |
| Commercial host-intelligence coverage | Requires provider credentials/license and an approved redistributable dataset; not claimed |
| Production deployment | Not authorized and not performed |
