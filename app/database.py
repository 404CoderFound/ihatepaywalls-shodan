from __future__ import annotations

import os
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path

DB_PATH = Path(os.getenv("DATABASE_PATH", "/data/scanlattice.db"))


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


@contextmanager
def connection():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    db = sqlite3.connect(DB_PATH, timeout=20)
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA foreign_keys=ON")
    try:
        yield db
        db.commit()
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
        if db.execute("SELECT COUNT(*) FROM scan_profiles").fetchone()[0] == 0:
            now = utc_now()
            db.executemany("INSERT INTO scan_profiles(name,ports,connect_timeout,banner_timeout,max_concurrency,created_at) VALUES(?,?,?,?,?,?)", [
                ("Web services", "80,443,8080,8443", 3, 3, 20, now),
                ("Common services", "21,22,25,53,80,110,143,443,587,993,995,3306,5432,6379,8080,8443", 3, 3, 20, now),
                ("Conservative", "22,80,443", 4, 3, 10, now),
            ])
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
