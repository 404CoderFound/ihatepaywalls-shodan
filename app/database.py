from __future__ import annotations

import os
import ipaddress
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from .db_backend import configured_backend

DB_PATH = Path(os.getenv("DATABASE_PATH", "/data/scanlattice.db"))


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def upsert_host_identity(db: sqlite3.Connection, ip: str, source: str, observed_at: str,
                         hostname: str="", asn: str="", org: str="", country: str="") -> None:
    """Index a passive/imported host identity without creating a service or scan observation."""
    address=ipaddress.ip_address(ip);asn=(asn or "").upper();org=org or "";prefix="";best=None
    if asn.removeprefix("AS").isdigit():asn=f"AS{int(asn.removeprefix('AS'))}"
    for route in db.execute("SELECT prefix,asn,organization FROM routing_prefixes WHERE expires_at IS NULL OR expires_at>?",(int(datetime.now(timezone.utc).timestamp()),)):
        try:
            network=ipaddress.ip_network(route["prefix"],strict=False)
            if address.version==network.version and address in network and (best is None or network.prefixlen>best[0]):best=(network.prefixlen,route,network)
        except ValueError:continue
    if best:
        _,route,network=best;prefix=str(network);asn=asn or route["asn"];org=org or route["organization"]
    normalized=observed_at or utc_now()
    db.execute("""INSERT INTO hosts(ip,hostname,asn,org,country,first_seen,last_seen,last_scan_at,network_prefix,source,ip_version,ip_hex)
      VALUES(?,?,?,?,?,?,?,'',?,?,?,?) ON CONFLICT(ip) DO UPDATE SET
      hostname=CASE WHEN excluded.hostname!='' THEN excluded.hostname ELSE hosts.hostname END,
      asn=CASE WHEN excluded.asn!='' THEN excluded.asn ELSE hosts.asn END,
      org=CASE WHEN excluded.org!='' THEN excluded.org ELSE hosts.org END,
      country=CASE WHEN excluded.country!='' THEN excluded.country ELSE hosts.country END,
      first_seen=MIN(hosts.first_seen,excluded.first_seen),last_seen=MAX(hosts.last_seen,excluded.last_seen),
      network_prefix=CASE WHEN excluded.network_prefix!='' THEN excluded.network_prefix ELSE hosts.network_prefix END,
      source=excluded.source""",(ip,hostname,asn,org,country,normalized,normalized,prefix,source,address.version,f"{int(address):032x}"))
    if hostname:
        db.execute("INSERT INTO hostnames(ip,hostname,source,first_seen,last_seen) VALUES(?,?,?,?,?) ON CONFLICT(ip,hostname,source) DO UPDATE SET last_seen=MAX(hostnames.last_seen,excluded.last_seen)",(ip,hostname.lower().rstrip("."),source,normalized,normalized))


@contextmanager
def connection():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    backend = configured_backend(os.getenv("DATABASE_BACKEND", "sqlite"))
    db = backend.connect(DB_PATH)
    backend.configure(db)
    try:
        yield db
        db.commit()
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()


def _columns(db: sqlite3.Connection, table: str) -> set[str]:
    return {row[1] for row in db.execute(f"PRAGMA table_info({table})")}


def _add_columns(db: sqlite3.Connection, table: str, definitions: dict[str, str]) -> None:
    existing = _columns(db, table)
    for name, definition in definitions.items():
        if name not in existing:
            db.execute(f"ALTER TABLE {table} ADD COLUMN {name} {definition}")


def init_db(seed_demo: bool = False) -> None:
    with connection() as db:
        if os.getenv("DATABASE_BACKEND", "sqlite").lower() != "sqlite":
            raise RuntimeError("Schema migrations are SQLite-specific until a PostgreSQL migration is implemented")
        db.execute("PRAGMA journal_mode=WAL")
        db.executescript("""
        CREATE TABLE IF NOT EXISTS observations (
          id INTEGER PRIMARY KEY AUTOINCREMENT, ip TEXT NOT NULL, port INTEGER NOT NULL,
          proto TEXT NOT NULL DEFAULT 'tcp', asn TEXT NOT NULL DEFAULT '', org TEXT NOT NULL DEFAULT '',
          country TEXT NOT NULL DEFAULT '', product TEXT NOT NULL DEFAULT '', banner TEXT NOT NULL DEFAULT '',
          source TEXT NOT NULL DEFAULT 'manual', seen_at TEXT NOT NULL, is_demo INTEGER NOT NULL DEFAULT 0
        );
        CREATE INDEX IF NOT EXISTS idx_observations_ip ON observations(ip);
        CREATE INDEX IF NOT EXISTS idx_observations_port ON observations(port);
        CREATE INDEX IF NOT EXISTS idx_observations_seen ON observations(seen_at);
        CREATE TABLE IF NOT EXISTS hosts (
          ip TEXT PRIMARY KEY, hostname TEXT NOT NULL DEFAULT '', asn TEXT NOT NULL DEFAULT '',
          org TEXT NOT NULL DEFAULT '', country TEXT NOT NULL DEFAULT '', first_seen TEXT NOT NULL,
          last_seen TEXT NOT NULL, last_scan_at TEXT NOT NULL DEFAULT '', is_demo INTEGER NOT NULL DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS services (
          id INTEGER PRIMARY KEY AUTOINCREMENT, host_ip TEXT NOT NULL, port INTEGER NOT NULL,
          proto TEXT NOT NULL DEFAULT 'tcp', service TEXT NOT NULL DEFAULT '', product TEXT NOT NULL DEFAULT '',
          first_seen TEXT NOT NULL, last_seen TEXT NOT NULL, last_observation_id INTEGER,
          UNIQUE(host_ip,port,proto), FOREIGN KEY(host_ip) REFERENCES hosts(ip)
        );
        CREATE INDEX IF NOT EXISTS idx_services_host ON services(host_ip);
        CREATE TABLE IF NOT EXISTS workers (
          id TEXT PRIMARY KEY, name TEXT NOT NULL, token_hash TEXT NOT NULL UNIQUE,
          capabilities TEXT NOT NULL DEFAULT '[]', cpu_pct REAL NOT NULL DEFAULT 0,
          memory_pct REAL NOT NULL DEFAULT 0, active_jobs INTEGER NOT NULL DEFAULT 0,
          created_at TEXT NOT NULL, last_seen INTEGER NOT NULL DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS authorizations (
          id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, cidr TEXT NOT NULL UNIQUE,
          enabled INTEGER NOT NULL DEFAULT 1, created_at TEXT NOT NULL, created_by TEXT NOT NULL DEFAULT 'admin'
        );
        CREATE TABLE IF NOT EXISTS scan_profiles (
          id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL UNIQUE, ports TEXT NOT NULL,
          connect_timeout REAL NOT NULL DEFAULT 3, banner_timeout REAL NOT NULL DEFAULT 3,
          max_concurrency INTEGER NOT NULL DEFAULT 20, created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS scan_jobs (
          id TEXT PRIMARY KEY, target TEXT NOT NULL, authorization_id INTEGER NOT NULL,
          profile_id INTEGER NOT NULL, ports TEXT NOT NULL, requested_worker_id TEXT,
          assigned_worker_id TEXT, status TEXT NOT NULL, progress_done INTEGER NOT NULL DEFAULT 0,
          progress_total INTEGER NOT NULL, attempts INTEGER NOT NULL DEFAULT 0,
          max_attempts INTEGER NOT NULL DEFAULT 3, lease_token TEXT, lease_expires_at INTEGER,
          error TEXT NOT NULL DEFAULT '', created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
          started_at TEXT, completed_at TEXT, FOREIGN KEY(authorization_id) REFERENCES authorizations(id),
          FOREIGN KEY(profile_id) REFERENCES scan_profiles(id), FOREIGN KEY(assigned_worker_id) REFERENCES workers(id)
        );
        CREATE INDEX IF NOT EXISTS idx_jobs_status ON scan_jobs(status, created_at);
        CREATE TABLE IF NOT EXISTS result_uploads (
          idempotency_key TEXT PRIMARY KEY, job_id TEXT NOT NULL, worker_id TEXT NOT NULL,
          received_at TEXT NOT NULL, observation_count INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS audit_logs (
          id INTEGER PRIMARY KEY AUTOINCREMENT, action TEXT NOT NULL, actor TEXT NOT NULL,
          details TEXT NOT NULL DEFAULT '{}', created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS admin_sessions (
          token_hash TEXT PRIMARY KEY, csrf_hash TEXT NOT NULL, created_at INTEGER NOT NULL,
          expires_at INTEGER NOT NULL, last_seen INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS passive_providers (
          id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL UNIQUE,
          provider_type TEXT NOT NULL, enabled INTEGER NOT NULL DEFAULT 0,
          config_json TEXT NOT NULL DEFAULT '{}', requests_per_minute INTEGER NOT NULL DEFAULT 10,
          created_at TEXT NOT NULL, updated_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS passive_records (
          id INTEGER PRIMARY KEY AUTOINCREMENT, subject TEXT NOT NULL,
          subject_type TEXT NOT NULL, ip TEXT NOT NULL DEFAULT '', domain TEXT NOT NULL DEFAULT '',
          asn TEXT NOT NULL DEFAULT '', org TEXT NOT NULL DEFAULT '', network TEXT NOT NULL DEFAULT '',
          record_type TEXT NOT NULL, value_json TEXT NOT NULL DEFAULT '{}',
          source TEXT NOT NULL, observed_at TEXT NOT NULL, expires_at INTEGER,
          provider_id INTEGER, UNIQUE(subject,record_type,source,value_json),
          FOREIGN KEY(provider_id) REFERENCES passive_providers(id)
        );
        CREATE INDEX IF NOT EXISTS idx_passive_subject ON passive_records(subject);
        CREATE INDEX IF NOT EXISTS idx_passive_ip ON passive_records(ip);
        CREATE INDEX IF NOT EXISTS idx_passive_domain ON passive_records(domain);
        CREATE TABLE IF NOT EXISTS passive_provider_usage (
          provider_id INTEGER NOT NULL, window_start INTEGER NOT NULL, request_count INTEGER NOT NULL,
          PRIMARY KEY(provider_id,window_start), FOREIGN KEY(provider_id) REFERENCES passive_providers(id)
        );
        CREATE TABLE IF NOT EXISTS passive_negative_cache (
          provider_id INTEGER NOT NULL, subject TEXT NOT NULL, expires_at INTEGER NOT NULL,
          PRIMARY KEY(provider_id,subject), FOREIGN KEY(provider_id) REFERENCES passive_providers(id)
        );
        CREATE TABLE IF NOT EXISTS enrichment_jobs (
          id TEXT PRIMARY KEY, query_key TEXT NOT NULL UNIQUE, query_type TEXT NOT NULL,
          query_value TEXT NOT NULL, status TEXT NOT NULL, attempts INTEGER NOT NULL DEFAULT 0,
          max_attempts INTEGER NOT NULL DEFAULT 3, providers_total INTEGER NOT NULL DEFAULT 0,
          providers_completed INTEGER NOT NULL DEFAULT 0, records_added INTEGER NOT NULL DEFAULT 0,
          error TEXT NOT NULL DEFAULT '', created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
          started_at TEXT, completed_at TEXT, cache_expires_at INTEGER
        );
        CREATE INDEX IF NOT EXISTS idx_enrichment_status ON enrichment_jobs(status,updated_at);
        CREATE TABLE IF NOT EXISTS scan_campaigns (
          id TEXT PRIMARY KEY, source_query TEXT NOT NULL, profile_id INTEGER NOT NULL,
          status TEXT NOT NULL, target_count INTEGER NOT NULL, job_count INTEGER NOT NULL,
          created_at TEXT NOT NULL, FOREIGN KEY(profile_id) REFERENCES scan_profiles(id)
        );
        CREATE TABLE IF NOT EXISTS campaign_jobs (
          campaign_id TEXT NOT NULL, job_id TEXT NOT NULL UNIQUE,
          PRIMARY KEY(campaign_id,job_id), FOREIGN KEY(campaign_id) REFERENCES scan_campaigns(id),
          FOREIGN KEY(job_id) REFERENCES scan_jobs(id)
        );
        CREATE TABLE IF NOT EXISTS hostnames (
          id INTEGER PRIMARY KEY AUTOINCREMENT, ip TEXT NOT NULL, hostname TEXT NOT NULL,
          source TEXT NOT NULL, first_seen TEXT NOT NULL, last_seen TEXT NOT NULL,
          UNIQUE(ip,hostname,source), FOREIGN KEY(ip) REFERENCES hosts(ip)
        );
        CREATE INDEX IF NOT EXISTS idx_hostnames_name ON hostnames(hostname);
        CREATE INDEX IF NOT EXISTS idx_hostnames_ip ON hostnames(ip);
        CREATE TABLE IF NOT EXISTS routing_prefixes (
          id INTEGER PRIMARY KEY AUTOINCREMENT, prefix TEXT NOT NULL, asn TEXT NOT NULL,
          organization TEXT NOT NULL DEFAULT '', source TEXT NOT NULL,
          first_seen TEXT NOT NULL, last_seen TEXT NOT NULL, expires_at INTEGER,
          UNIQUE(prefix,asn,source)
        );
        CREATE INDEX IF NOT EXISTS idx_routing_asn ON routing_prefixes(asn,prefix);
        CREATE TABLE IF NOT EXISTS indexing_schedules (
          id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, query TEXT NOT NULL,
          interval_seconds INTEGER NOT NULL, enabled INTEGER NOT NULL DEFAULT 1,
          next_run_at INTEGER NOT NULL, last_run_at INTEGER, last_job_id TEXT,
          last_status TEXT NOT NULL DEFAULT 'scheduled', last_error TEXT NOT NULL DEFAULT '',
          created_at TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_indexing_due ON indexing_schedules(enabled,next_run_at);
        CREATE TABLE IF NOT EXISTS dataset_ingestions (
          dataset_id TEXT PRIMARY KEY, source TEXT NOT NULL, cursor TEXT NOT NULL DEFAULT '',
          records_processed INTEGER NOT NULL DEFAULT 0, status TEXT NOT NULL,
          error TEXT NOT NULL DEFAULT '', updated_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS api_keys (
          id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, key_hash TEXT NOT NULL UNIQUE,
          scopes TEXT NOT NULL DEFAULT '["search:read"]', created_at TEXT NOT NULL,
          last_used_at TEXT NOT NULL DEFAULT '', revoked_at TEXT NOT NULL DEFAULT ''
        );
        CREATE TABLE IF NOT EXISTS dns_observations (
          id INTEGER PRIMARY KEY AUTOINCREMENT, domain TEXT NOT NULL, record_type TEXT NOT NULL,
          value TEXT NOT NULL, source TEXT NOT NULL, method TEXT NOT NULL DEFAULT 'imported',
          observed_at TEXT NOT NULL, expires_at INTEGER
        );
        CREATE INDEX IF NOT EXISTS idx_dns_domain_time ON dns_observations(domain,observed_at DESC);
        CREATE TABLE IF NOT EXISTS vulnerabilities (
          cve TEXT PRIMARY KEY, description TEXT NOT NULL DEFAULT '', cvss REAL,
          severity TEXT NOT NULL DEFAULT '', known_exploited INTEGER NOT NULL DEFAULT 0,
          source TEXT NOT NULL, updated_at TEXT NOT NULL, cpes_json TEXT NOT NULL DEFAULT '[]'
        );
        CREATE TABLE IF NOT EXISTS host_vulnerability_matches (
          id INTEGER PRIMARY KEY AUTOINCREMENT, host_ip TEXT NOT NULL, cve TEXT NOT NULL,
          confidence TEXT NOT NULL, evidence_json TEXT NOT NULL, source TEXT NOT NULL,
          observed_at TEXT NOT NULL, UNIQUE(host_ip,cve,evidence_json),
          FOREIGN KEY(host_ip) REFERENCES hosts(ip), FOREIGN KEY(cve) REFERENCES vulnerabilities(cve)
        );
        CREATE TABLE IF NOT EXISTS host_screenshots (
          id INTEGER PRIMARY KEY AUTOINCREMENT, ip TEXT NOT NULL, filename TEXT NOT NULL,
          media_type TEXT NOT NULL, sha256 TEXT NOT NULL, image BLOB NOT NULL,
          note TEXT NOT NULL DEFAULT '', created_at TEXT NOT NULL, created_by TEXT NOT NULL DEFAULT 'admin'
        );
        CREATE INDEX IF NOT EXISTS idx_host_screenshots_ip ON host_screenshots(ip,created_at DESC);
        CREATE INDEX IF NOT EXISTS idx_host_vuln_host ON host_vulnerability_matches(host_ip,cve);
        CREATE TABLE IF NOT EXISTS intelligence_provider_state (
          provider TEXT PRIMARY KEY, last_attempt_at TEXT NOT NULL, last_success_at TEXT NOT NULL DEFAULT '',
          status TEXT NOT NULL, records_updated INTEGER NOT NULL DEFAULT 0, error TEXT NOT NULL DEFAULT ''
        );
        CREATE TABLE IF NOT EXISTS vulnerability_feed_cursors (
          provider TEXT PRIMARY KEY, window_start TEXT NOT NULL, window_end TEXT NOT NULL,
          next_index INTEGER NOT NULL DEFAULT 0, total_results INTEGER NOT NULL DEFAULT 0,
          updated_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS monitor_targets (
          id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, target TEXT NOT NULL,
          authorization_id INTEGER NOT NULL, enabled INTEGER NOT NULL DEFAULT 1,
          created_at TEXT NOT NULL, FOREIGN KEY(authorization_id) REFERENCES authorizations(id)
        );
        CREATE TABLE IF NOT EXISTS monitor_events (
          id INTEGER PRIMARY KEY AUTOINCREMENT, target_id INTEGER, ip TEXT NOT NULL DEFAULT '',
          event_type TEXT NOT NULL, details TEXT NOT NULL DEFAULT '{}', source TEXT NOT NULL,
          created_at TEXT NOT NULL, acknowledged_at TEXT NOT NULL DEFAULT '',
          FOREIGN KEY(target_id) REFERENCES monitor_targets(id)
        );
        CREATE TABLE IF NOT EXISTS monitor_destinations (
          id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, kind TEXT NOT NULL,
          endpoint TEXT NOT NULL, enabled INTEGER NOT NULL DEFAULT 1, created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS monitor_notifications (
          id INTEGER PRIMARY KEY AUTOINCREMENT, event_id INTEGER NOT NULL,
          destination_id INTEGER NOT NULL, status TEXT NOT NULL DEFAULT 'queued',
          attempts INTEGER NOT NULL DEFAULT 0, next_attempt_at INTEGER NOT NULL DEFAULT 0,
          delivered_at TEXT NOT NULL DEFAULT '', error TEXT NOT NULL DEFAULT '',
          UNIQUE(event_id,destination_id), FOREIGN KEY(event_id) REFERENCES monitor_events(id),
          FOREIGN KEY(destination_id) REFERENCES monitor_destinations(id)
        );
        CREATE INDEX IF NOT EXISTS idx_monitor_notifications_due ON monitor_notifications(status,next_attempt_at);
        CREATE TABLE IF NOT EXISTS saved_searches (
          id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, query TEXT NOT NULL,
          created_at TEXT NOT NULL, updated_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS dataset_import_runs (
          id TEXT PRIMARY KEY, source TEXT NOT NULL, format TEXT NOT NULL,
          encoding TEXT NOT NULL DEFAULT 'identity', total_bytes INTEGER NOT NULL,
          uploaded_bytes INTEGER NOT NULL DEFAULT 0, records_processed INTEGER NOT NULL DEFAULT 0,
          status TEXT NOT NULL, error TEXT NOT NULL DEFAULT '', spool_path TEXT NOT NULL,
          created_at TEXT NOT NULL, updated_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS dataset_import_records (
          import_id TEXT NOT NULL, row_number INTEGER NOT NULL, observation_count INTEGER NOT NULL,
          PRIMARY KEY(import_id,row_number),
          FOREIGN KEY(import_id) REFERENCES dataset_import_runs(id)
        );
        CREATE TABLE IF NOT EXISTS scan_generations (
          id TEXT PRIMARY KEY, refresh_request_id TEXT NOT NULL UNIQUE,
          query TEXT NOT NULL, normalized_query TEXT NOT NULL,
          query_kind TEXT NOT NULL, status TEXT NOT NULL,
          requested_by TEXT NOT NULL, target_count INTEGER NOT NULL,
          task_count INTEGER NOT NULL, completed_tasks INTEGER NOT NULL DEFAULT 0,
          failed_tasks INTEGER NOT NULL DEFAULT 0, created_at TEXT NOT NULL,
          updated_at TEXT NOT NULL, completed_at TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_scan_generations_status ON scan_generations(status,created_at DESC);
        CREATE TABLE IF NOT EXISTS scan_refresh_requests (
          id TEXT PRIMARY KEY, idempotency_key TEXT NOT NULL UNIQUE,
          request_fingerprint TEXT NOT NULL, query TEXT NOT NULL,
          normalized_query TEXT NOT NULL, profile_id INTEGER NOT NULL,
          ports_json TEXT NOT NULL, status TEXT NOT NULL,
          requested_by TEXT NOT NULL, generation_id TEXT NOT NULL UNIQUE,
          rejected_targets_json TEXT NOT NULL DEFAULT '[]',
          created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
          FOREIGN KEY(generation_id) REFERENCES scan_generations(id)
        );
        CREATE INDEX IF NOT EXISTS idx_refresh_requests_created ON scan_refresh_requests(created_at DESC);
        CREATE TABLE IF NOT EXISTS scan_tasks (
          id TEXT PRIMARY KEY, generation_id TEXT NOT NULL,
          idempotency_key TEXT NOT NULL UNIQUE, target_ip TEXT NOT NULL,
          ports_json TEXT NOT NULL, profile_id INTEGER NOT NULL,
          scan_job_id TEXT NOT NULL UNIQUE, status TEXT NOT NULL,
          attempt_count INTEGER NOT NULL DEFAULT 0, max_attempts INTEGER NOT NULL DEFAULT 3,
          lease_owner TEXT NOT NULL DEFAULT '', lease_token TEXT NOT NULL DEFAULT '',
          lease_expires_at INTEGER, available_at INTEGER NOT NULL DEFAULT 0,
          error TEXT NOT NULL DEFAULT '', created_at TEXT NOT NULL,
          updated_at TEXT NOT NULL,
          FOREIGN KEY(generation_id) REFERENCES scan_generations(id),
          FOREIGN KEY(profile_id) REFERENCES scan_profiles(id),
          FOREIGN KEY(scan_job_id) REFERENCES scan_jobs(id)
        );
        CREATE INDEX IF NOT EXISTS idx_scan_tasks_generation ON scan_tasks(generation_id,status);
        CREATE INDEX IF NOT EXISTS idx_scan_tasks_queue ON scan_tasks(status,available_at,created_at);
        """)
        _add_columns(db, "observations", {
            "hostname": "TEXT NOT NULL DEFAULT ''", "service": "TEXT NOT NULL DEFAULT ''",
            "http_json": "TEXT NOT NULL DEFAULT '{}'", "tls_json": "TEXT NOT NULL DEFAULT '{}'",
            "ssh_id": "TEXT NOT NULL DEFAULT ''", "latency_ms": "REAL",
            "scan_job_id": "TEXT", "worker_id": "TEXT"
        })
        _add_columns(db, "workers", {
            "version": "TEXT NOT NULL DEFAULT ''", "max_concurrent": "INTEGER NOT NULL DEFAULT 1",
            "completed_jobs": "INTEGER NOT NULL DEFAULT 0", "last_error": "TEXT NOT NULL DEFAULT ''"
        })
        _add_columns(db, "scan_profiles", {
            "rate_per_second": "REAL NOT NULL DEFAULT 20"
        })
        _add_columns(db, "hosts", {
            "network_prefix": "TEXT NOT NULL DEFAULT ''", "source": "TEXT NOT NULL DEFAULT ''",
            "ip_version": "INTEGER NOT NULL DEFAULT 0", "ip_hex": "TEXT NOT NULL DEFAULT ''"
        })
        _add_columns(db, "services", {
            "source": "TEXT NOT NULL DEFAULT ''", "banner": "TEXT NOT NULL DEFAULT ''",
            "http_json": "TEXT NOT NULL DEFAULT '{}'", "tls_json": "TEXT NOT NULL DEFAULT '{}'"
        })

        # v2 durable result batches are additive; legacy jobs/results remain valid.
        db.executescript("""
        CREATE TABLE IF NOT EXISTS scan_result_batches (
          job_id TEXT NOT NULL REFERENCES scan_jobs(id),
          batch_index INTEGER NOT NULL CHECK(batch_index >= 0),
          payload_hash TEXT NOT NULL,
          checks_done INTEGER NOT NULL CHECK(checks_done >= 1),
          observation_count INTEGER NOT NULL CHECK(observation_count >= 0),
          created_at TEXT NOT NULL,
          PRIMARY KEY(job_id, batch_index)
        );
        CREATE TABLE IF NOT EXISTS scan_result_finishes (
          job_id TEXT PRIMARY KEY REFERENCES scan_jobs(id),
          worker_id TEXT NOT NULL REFERENCES workers(id),
          batch_count INTEGER NOT NULL,
          completed_checks INTEGER NOT NULL,
          observation_count INTEGER NOT NULL,
          finished_at TEXT NOT NULL
        );
        """)

        _add_columns(db, "observations", {"observation_hash": "TEXT NOT NULL DEFAULT ''"})
        _add_columns(db, "observations", {"cpe": "TEXT NOT NULL DEFAULT ''", "os_name": "TEXT NOT NULL DEFAULT ''"})
        _add_columns(db, "services", {"cpe": "TEXT NOT NULL DEFAULT ''"})
        _add_columns(db, "hosts", {"os_name": "TEXT NOT NULL DEFAULT ''"})
        _add_columns(db, "vulnerabilities", {"cpes_json": "TEXT NOT NULL DEFAULT '[]'"})
        _add_columns(db, "monitor_targets", {"alert_types_json": "TEXT NOT NULL DEFAULT '[\"service_observed\",\"software_changed\",\"service_disappeared\",\"certificate_expiring\",\"certificate_changed\",\"vulnerability_new\"]'", "cooldown_seconds": "INTEGER NOT NULL DEFAULT 900"})
        db.execute("CREATE INDEX IF NOT EXISTS idx_hosts_asn_last ON hosts(asn,last_seen DESC,ip_hex)")
        db.execute("CREATE INDEX IF NOT EXISTS idx_hosts_ip_sort ON hosts(ip_version,ip_hex)")
        db.execute("CREATE INDEX IF NOT EXISTS idx_hosts_prefix ON hosts(network_prefix)")
        db.execute("CREATE INDEX IF NOT EXISTS idx_services_port_host ON services(port,host_ip)")
        db.execute("CREATE INDEX IF NOT EXISTS idx_services_name_host ON services(service,host_ip)")
        db.execute("CREATE INDEX IF NOT EXISTS idx_observations_hash ON observations(observation_hash)")
        if db.execute("SELECT COUNT(*) FROM scan_profiles").fetchone()[0] == 0:
            now = utc_now()
            db.executemany("INSERT INTO scan_profiles(name,ports,connect_timeout,banner_timeout,max_concurrency,created_at) VALUES(?,?,?,?,?,?)", [
                ("Web services", "80,443,8080,8443", 3, 3, 20, now),
                ("Common services", "21,22,25,53,80,110,143,443,587,993,995,3306,5432,6379,8080,8443", 3, 3, 20, now),
                ("Conservative", "22,80,443", 4, 3, 10, now),
            ])
        now = utc_now()
        profile_defaults = [
            ("Quick Recon", "22,80,443,8080,8443", 2, 2, 20, 30, now),
            ("Standard Recon", "21,22,25,53,80,110,143,443,587,993,995,3306,5432,6379,8080,8443", 3, 3, 20, 20, now),
            ("Deep Recon", "21,22,23,25,53,80,110,111,135,139,143,389,443,445,465,587,636,993,995,1433,1521,2049,2375,3306,3389,5432,5672,5900,6379,8080,8443,9200,27017", 4, 4, 20, 10, now),
        ]
        db.executemany("INSERT OR IGNORE INTO scan_profiles(name,ports,connect_timeout,banner_timeout,max_concurrency,rate_per_second,created_at) VALUES(?,?,?,?,?,?,?)", profile_defaults)
        provider_defaults = [
            ("RIPEstat", "ripestat", 1, "{}", 10, now, now),
            ("RDAP Bootstrap", "rdap", 1, '{"base_url":"https://rdap.org/"}', 10, now, now),
            ("crt.sh Certificate Transparency", "certificate_transparency", 0, "{}", 5, now, now),
            ("Shodan InternetDB", "shodan_internetdb", 0, "{}", 5, now, now),
        ]
        db.executemany("INSERT OR IGNORE INTO passive_providers(name,provider_type,enabled,config_json,requests_per_minute,created_at,updated_at) VALUES(?,?,?,?,?,?,?)", provider_defaults)
        if seed_demo and db.execute("SELECT COUNT(*) FROM observations WHERE is_demo=1").fetchone()[0] == 0:
            now = utc_now()
            samples = [
                ("192.0.2.10",443,"tcp","AS64500","Example Systems","US","nginx","HTTP/1.1 200 OK\nserver: nginx","example",now,1,"https"),
                ("198.51.100.22",22,"tcp","AS64501","Test Network","NL","OpenSSH","SSH-2.0-OpenSSH_9.6","example",now,1,"ssh"),
                ("203.0.113.40",80,"tcp","AS64502","Documentation ISP","DE","Apache","HTTP/1.1 200 OK\nserver: Apache/2.4","example",now,1,"http"),
            ]
            db.executemany("INSERT INTO observations(ip,port,proto,asn,org,country,product,banner,source,seen_at,is_demo,service) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)", samples)
            for row in samples:
                db.execute("INSERT OR REPLACE INTO hosts(ip,asn,org,country,first_seen,last_seen,is_demo) VALUES(?,?,?,?,?,?,1)", (row[0],row[3],row[4],row[5],now,now))
        # Backfill normalized records for databases created by v0.1. The
        # append-only observations table remains the historical source.
        db.execute("""INSERT OR IGNORE INTO hosts(ip,hostname,asn,org,country,first_seen,last_seen,is_demo)
          SELECT ip,COALESCE(MAX(hostname),''),MAX(asn),MAX(org),MAX(country),MIN(seen_at),MAX(seen_at),MAX(is_demo)
          FROM observations GROUP BY ip""")
        db.execute("""INSERT OR IGNORE INTO services(host_ip,port,proto,service,product,first_seen,last_seen,last_observation_id)
          SELECT o.ip,o.port,o.proto,COALESCE(o.service,''),o.product,MIN(o.seen_at),MAX(o.seen_at),MAX(o.id)
          FROM observations o JOIN hosts h ON h.ip=o.ip GROUP BY o.ip,o.port,o.proto""")
        for row in db.execute("SELECT ip FROM hosts WHERE ip_version=0 OR ip_hex='' ").fetchall():
            import ipaddress
            address = ipaddress.ip_address(row["ip"])
            db.execute("UPDATE hosts SET ip_version=?,ip_hex=? WHERE ip=?", (address.version, f"{int(address):032x}", row["ip"]))
        db.execute("""UPDATE services SET source=COALESCE((SELECT o.source FROM observations o WHERE o.id=services.last_observation_id),'')
          WHERE source=''""")
        db.execute("""UPDATE services SET banner=COALESCE((SELECT o.banner FROM observations o WHERE o.id=services.last_observation_id),'')
          WHERE banner=''""")
        db.execute("""INSERT OR IGNORE INTO hostnames(ip,hostname,source,first_seen,last_seen)
          SELECT ip,LOWER(hostname),source,MIN(seen_at),MAX(seen_at) FROM observations WHERE hostname!='' GROUP BY ip,LOWER(hostname),source""")
        db.execute("""INSERT OR IGNORE INTO routing_prefixes(prefix,asn,organization,source,first_seen,last_seen,expires_at)
          SELECT network,UPPER(asn),org,source,MIN(observed_at),MAX(observed_at),MAX(expires_at)
          FROM passive_records WHERE network!='' AND asn!='' GROUP BY network,UPPER(asn),source""")
        import ipaddress
        mappings=[]
        for row in db.execute("SELECT prefix,asn,organization FROM routing_prefixes").fetchall():
            try:mappings.append((ipaddress.ip_network(row["prefix"],strict=False),row))
            except ValueError:pass
        for host in db.execute("SELECT ip,network_prefix FROM hosts").fetchall():
            address=ipaddress.ip_address(host["ip"]);matches=[item for item in mappings if item[0].version==address.version and address in item[0]]
            if matches:
                network,mapping=max(matches,key=lambda item:item[0].prefixlen)
                db.execute("UPDATE hosts SET network_prefix=?,asn=CASE WHEN asn='' THEN ? ELSE asn END,org=CASE WHEN org='' THEN ? ELSE org END WHERE ip=?",(str(network),mapping["asn"],mapping["organization"],host["ip"]))
        for table in ("hosts","observations","passive_records","routing_prefixes"):
            for row in db.execute(f"SELECT rowid AS migration_rowid,asn FROM {table} WHERE asn!=''").fetchall():
                value=row["asn"].upper();number=value.removeprefix("AS")
                if number.isdigit():db.execute(f"UPDATE {table} SET asn=? WHERE rowid=?",(f"AS{int(number)}",row["migration_rowid"]))
