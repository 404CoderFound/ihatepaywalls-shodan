# ScanLattice worker protocol fingerprints (v0.5)

The worker now recognizes additional common TCP service greetings. It never authenticates to services or sends exploit payloads.

- **Passive greetings on any TCP port:** SSH, FTP, SMTP, IMAP, POP3, MySQL/MariaDB, and HTTP (when sent by the server).
- **Port-specific read-only probes:** HTTP `HEAD /` on configured web ports, Redis `PING` on configured Redis ports, and PostgreSQL `SSLRequest` on port 5432. These probes collect identification only.
- **TLS:** Common HTTPS and TLS-service ports collect protocol/cipher and SHA-256 of the peer certificate without bypassing TLS connection errors. Unrecognized TLS application protocols are indexed as `tls` rather than falsely labelled as HTTP.
- **Result format:** The existing worker result JSON remains unchanged; observations store `service`, `product`, `banner`, `http`, `tls` and `ssh_id` through the existing ingestion layer. No new database schema is required.

This is **not** Internet-wide active scanning, and it does not attempt every port on every host. The existing controller-side and worker-side limits and explicit active-scan target policy remain in effect. The research/indexing pipeline must separately address crawl scheduling, source permissions, opt-outs, and data coverage.

Tests: `python -m pytest -q tests/test_scanner.py tests/test_protocol_fingerprints.py`. New tests use local loopback sockets only. No production deployment is performed.
