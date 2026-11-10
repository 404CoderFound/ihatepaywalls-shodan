-- Initial PostgreSQL schema, mirrored from the SQLite bootstrap in app/database.py.
CREATE TABLE IF NOT EXISTS observations (
          id BIGSERIAL PRIMARY KEY, ip TEXT NOT NULL, port INTEGER NOT NULL,
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
          id BIGSERIAL PRIMARY KEY, host_ip TEXT NOT NULL, port INTEGER NOT NULL,
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
          id BIGSERIAL PRIMARY KEY, name TEXT NOT NULL, cidr TEXT NOT NULL UNIQUE,
          enabled INTEGER NOT NULL DEFAULT 1, created_at TEXT NOT NULL, created_by TEXT NOT NULL DEFAULT 'admin'
        );
        CREATE TABLE IF NOT EXISTS scan_profiles (
          id BIGSERIAL PRIMARY KEY, name TEXT NOT NULL UNIQUE, ports TEXT NOT NULL,
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
          id BIGSERIAL PRIMARY KEY, action TEXT NOT NULL, actor TEXT NOT NULL,
          details TEXT NOT NULL DEFAULT '{}', created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS admin_sessions (
          token_hash TEXT PRIMARY KEY, csrf_hash TEXT NOT NULL, created_at INTEGER NOT NULL,
          expires_at INTEGER NOT NULL, last_seen INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS passive_providers (
          id BIGSERIAL PRIMARY KEY, name TEXT NOT NULL UNIQUE,
          provider_type TEXT NOT NULL, enabled INTEGER NOT NULL DEFAULT 0,
          config_json TEXT NOT NULL DEFAULT '{}', requests_per_minute INTEGER NOT NULL DEFAULT 10,
          created_at TEXT NOT NULL, updated_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS passive_records (
          id BIGSERIAL PRIMARY KEY, subject TEXT NOT NULL,
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
          id BIGSERIAL PRIMARY KEY, ip TEXT NOT NULL, hostname TEXT NOT NULL,
          source TEXT NOT NULL, first_seen TEXT NOT NULL, last_seen TEXT NOT NULL,
          UNIQUE(ip,hostname,source), FOREIGN KEY(ip) REFERENCES hosts(ip)
        );
        CREATE INDEX IF NOT EXISTS idx_hostnames_name ON hostnames(hostname);
        CREATE INDEX IF NOT EXISTS idx_hostnames_ip ON hostnames(ip);
        CREATE TABLE IF NOT EXISTS routing_prefixes (
          id BIGSERIAL PRIMARY KEY, prefix TEXT NOT NULL, asn TEXT NOT NULL,
          organization TEXT NOT NULL DEFAULT '', source TEXT NOT NULL,
          first_seen TEXT NOT NULL, last_seen TEXT NOT NULL, expires_at INTEGER,
          UNIQUE(prefix,asn,source)
        );
        CREATE INDEX IF NOT EXISTS idx_routing_asn ON routing_prefixes(asn,prefix);
        CREATE TABLE IF NOT EXISTS indexing_schedules (
          id BIGSERIAL PRIMARY KEY, name TEXT NOT NULL, query TEXT NOT NULL,
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
          id BIGSERIAL PRIMARY KEY, name TEXT NOT NULL, key_hash TEXT NOT NULL UNIQUE,
          scopes TEXT NOT NULL DEFAULT '["search:read"]', created_at TEXT NOT NULL,
          last_used_at TEXT NOT NULL DEFAULT '', revoked_at TEXT NOT NULL DEFAULT ''
        );
        CREATE TABLE IF NOT EXISTS dns_observations (
          id BIGSERIAL PRIMARY KEY, domain TEXT NOT NULL, record_type TEXT NOT NULL,
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
          id BIGSERIAL PRIMARY KEY, host_ip TEXT NOT NULL, cve TEXT NOT NULL,
          confidence TEXT NOT NULL, evidence_json TEXT NOT NULL, source TEXT NOT NULL,
          observed_at TEXT NOT NULL, UNIQUE(host_ip,cve,evidence_json),
          FOREIGN KEY(host_ip) REFERENCES hosts(ip), FOREIGN KEY(cve) REFERENCES vulnerabilities(cve)
        );
        CREATE TABLE IF NOT EXISTS host_screenshots (
          id BIGSERIAL PRIMARY KEY, ip TEXT NOT NULL, filename TEXT NOT NULL,
          media_type TEXT NOT NULL, sha256 TEXT NOT NULL, image BYTEA NOT NULL,
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
          id BIGSERIAL PRIMARY KEY, name TEXT NOT NULL, target TEXT NOT NULL,
          authorization_id INTEGER NOT NULL, enabled INTEGER NOT NULL DEFAULT 1,
          created_at TEXT NOT NULL, FOREIGN KEY(authorization_id) REFERENCES authorizations(id)
        );
        CREATE TABLE IF NOT EXISTS monitor_events (
          id BIGSERIAL PRIMARY KEY, target_id INTEGER, ip TEXT NOT NULL DEFAULT '',
          event_type TEXT NOT NULL, details TEXT NOT NULL DEFAULT '{}', source TEXT NOT NULL,
          created_at TEXT NOT NULL, acknowledged_at TEXT NOT NULL DEFAULT '',
          FOREIGN KEY(target_id) REFERENCES monitor_targets(id)
        );
        CREATE TABLE IF NOT EXISTS monitor_destinations (
          id BIGSERIAL PRIMARY KEY, name TEXT NOT NULL, kind TEXT NOT NULL,
          endpoint TEXT NOT NULL, enabled INTEGER NOT NULL DEFAULT 1, created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS monitor_notifications (
          id BIGSERIAL PRIMARY KEY, event_id INTEGER NOT NULL,
          destination_id INTEGER NOT NULL, status TEXT NOT NULL DEFAULT 'queued',
          attempts INTEGER NOT NULL DEFAULT 0, next_attempt_at INTEGER NOT NULL DEFAULT 0,
          delivered_at TEXT NOT NULL DEFAULT '', error TEXT NOT NULL DEFAULT '',
          UNIQUE(event_id,destination_id), FOREIGN KEY(event_id) REFERENCES monitor_events(id),
          FOREIGN KEY(destination_id) REFERENCES monitor_destinations(id)
        );
        CREATE INDEX IF NOT EXISTS idx_monitor_notifications_due ON monitor_notifications(status,next_attempt_at);
        CREATE TABLE IF NOT EXISTS saved_searches (
          id BIGSERIAL PRIMARY KEY, name TEXT NOT NULL, query TEXT NOT NULL,
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
