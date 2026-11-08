-- Frozen representative v0.4 database snapshot generated with commit 7741806.
BEGIN TRANSACTION;
CREATE TABLE admin_sessions (
          token_hash TEXT PRIMARY KEY, csrf_hash TEXT NOT NULL, created_at INTEGER NOT NULL,
          expires_at INTEGER NOT NULL, last_seen INTEGER NOT NULL
        );
CREATE TABLE audit_logs (
          id INTEGER PRIMARY KEY AUTOINCREMENT, action TEXT NOT NULL, actor TEXT NOT NULL,
          details TEXT NOT NULL DEFAULT '{}', created_at TEXT NOT NULL
        );
CREATE TABLE authorizations (
          id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, cidr TEXT NOT NULL UNIQUE,
          enabled INTEGER NOT NULL DEFAULT 1, created_at TEXT NOT NULL, created_by TEXT NOT NULL DEFAULT 'admin'
        );
INSERT INTO "authorizations" VALUES(1,'V04 fixture authorization','198.51.100.0/24',1,'2025-03-04T05:06:07+00:00','admin');
CREATE TABLE campaign_jobs (
          campaign_id TEXT NOT NULL, job_id TEXT NOT NULL UNIQUE,
          PRIMARY KEY(campaign_id,job_id), FOREIGN KEY(campaign_id) REFERENCES scan_campaigns(id),
          FOREIGN KEY(job_id) REFERENCES scan_jobs(id)
        );
INSERT INTO "campaign_jobs" VALUES('v04-campaign-01','v04-job-01');
CREATE TABLE dataset_ingestions (
          dataset_id TEXT PRIMARY KEY, source TEXT NOT NULL, cursor TEXT NOT NULL DEFAULT '',
          records_processed INTEGER NOT NULL DEFAULT 0, status TEXT NOT NULL,
          error TEXT NOT NULL DEFAULT '', updated_at TEXT NOT NULL
        );
INSERT INTO "dataset_ingestions" VALUES('v04-dataset-01','v04-fixture','done',1,'completed','','2025-03-04T05:06:07+00:00');
CREATE TABLE enrichment_jobs (
          id TEXT PRIMARY KEY, query_key TEXT NOT NULL UNIQUE, query_type TEXT NOT NULL,
          query_value TEXT NOT NULL, status TEXT NOT NULL, attempts INTEGER NOT NULL DEFAULT 0,
          max_attempts INTEGER NOT NULL DEFAULT 3, providers_total INTEGER NOT NULL DEFAULT 0,
          providers_completed INTEGER NOT NULL DEFAULT 0, records_added INTEGER NOT NULL DEFAULT 0,
          error TEXT NOT NULL DEFAULT '', created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
          started_at TEXT, completed_at TEXT, cache_expires_at INTEGER
        );
INSERT INTO "enrichment_jobs" VALUES('v04-enrichment-01','ip:198.51.100.10','ip','198.51.100.10','completed',0,3,0,0,0,'','2025-03-04T05:06:07+00:00','2025-03-04T05:06:07+00:00',NULL,NULL,NULL);
CREATE TABLE hostnames (
          id INTEGER PRIMARY KEY AUTOINCREMENT, ip TEXT NOT NULL, hostname TEXT NOT NULL,
          source TEXT NOT NULL, first_seen TEXT NOT NULL, last_seen TEXT NOT NULL,
          UNIQUE(ip,hostname,source), FOREIGN KEY(ip) REFERENCES hosts(ip)
        );
INSERT INTO "hostnames" VALUES(1,'198.51.100.10','edge.v04.example.test','v04-release-fixture','2025-03-04T05:06:07+00:00','2025-03-04T05:06:07+00:00');
CREATE TABLE hosts (
          ip TEXT PRIMARY KEY, hostname TEXT NOT NULL DEFAULT '', asn TEXT NOT NULL DEFAULT '',
          org TEXT NOT NULL DEFAULT '', country TEXT NOT NULL DEFAULT '', first_seen TEXT NOT NULL,
          last_seen TEXT NOT NULL, last_scan_at TEXT NOT NULL DEFAULT '', is_demo INTEGER NOT NULL DEFAULT 0
        , network_prefix TEXT NOT NULL DEFAULT '', source TEXT NOT NULL DEFAULT '', ip_version INTEGER NOT NULL DEFAULT 0, ip_hex TEXT NOT NULL DEFAULT '');
INSERT INTO "hosts" VALUES('198.51.100.10','edge.v04.example.test','AS64496','V04 Fixture Networks','NL','2025-03-04T05:06:07+00:00','2025-03-04T05:06:07+00:00','2025-03-04T05:06:07+00:00',0,'','',0,'');
CREATE TABLE indexing_schedules (
          id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, query TEXT NOT NULL,
          interval_seconds INTEGER NOT NULL, enabled INTEGER NOT NULL DEFAULT 1,
          next_run_at INTEGER NOT NULL, last_run_at INTEGER, last_job_id TEXT,
          last_status TEXT NOT NULL DEFAULT 'scheduled', last_error TEXT NOT NULL DEFAULT '',
          created_at TEXT NOT NULL
        );
INSERT INTO "indexing_schedules" VALUES(1,'V04 fixture schedule','asn:AS64496',300,1,1741065000,NULL,NULL,'completed','','2025-03-04T05:06:07+00:00');
CREATE TABLE observations (
          id INTEGER PRIMARY KEY AUTOINCREMENT, ip TEXT NOT NULL, port INTEGER NOT NULL,
          proto TEXT NOT NULL DEFAULT 'tcp', asn TEXT NOT NULL DEFAULT '', org TEXT NOT NULL DEFAULT '',
          country TEXT NOT NULL DEFAULT '', product TEXT NOT NULL DEFAULT '', banner TEXT NOT NULL DEFAULT '',
          source TEXT NOT NULL DEFAULT 'manual', seen_at TEXT NOT NULL, is_demo INTEGER NOT NULL DEFAULT 0
        , hostname TEXT NOT NULL DEFAULT '', service TEXT NOT NULL DEFAULT '', http_json TEXT NOT NULL DEFAULT '{}', tls_json TEXT NOT NULL DEFAULT '{}', ssh_id TEXT NOT NULL DEFAULT '', latency_ms REAL, scan_job_id TEXT, worker_id TEXT, observation_hash TEXT NOT NULL DEFAULT '');
INSERT INTO "observations" VALUES(1,'198.51.100.10',443,'tcp','AS64496','V04 Fixture Networks','NL','nginx','fixture banner from v0.4','v04-release-fixture','2025-03-04T05:06:07+00:00',0,'edge.v04.example.test','https','{}','{}','',NULL,NULL,NULL,'');
CREATE TABLE passive_negative_cache (
          provider_id INTEGER NOT NULL, subject TEXT NOT NULL, expires_at INTEGER NOT NULL,
          PRIMARY KEY(provider_id,subject), FOREIGN KEY(provider_id) REFERENCES passive_providers(id)
        );
CREATE TABLE passive_provider_usage (
          provider_id INTEGER NOT NULL, window_start INTEGER NOT NULL, request_count INTEGER NOT NULL,
          PRIMARY KEY(provider_id,window_start), FOREIGN KEY(provider_id) REFERENCES passive_providers(id)
        );
CREATE TABLE passive_providers (
          id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL UNIQUE,
          provider_type TEXT NOT NULL, enabled INTEGER NOT NULL DEFAULT 0,
          config_json TEXT NOT NULL DEFAULT '{}', requests_per_minute INTEGER NOT NULL DEFAULT 10,
          created_at TEXT NOT NULL, updated_at TEXT NOT NULL
        );
INSERT INTO "passive_providers" VALUES(1,'RIPEstat','ripestat',1,'{}',10,'2026-11-08T18:44:48+00:00','2026-11-08T18:44:48+00:00');
INSERT INTO "passive_providers" VALUES(2,'RDAP Bootstrap','rdap',1,'{"base_url":"https://rdap.org/"}',10,'2026-11-08T18:44:48+00:00','2026-11-08T18:44:48+00:00');
INSERT INTO "passive_providers" VALUES(3,'crt.sh Certificate Transparency','certificate_transparency',0,'{}',5,'2026-11-08T18:44:48+00:00','2026-11-08T18:44:48+00:00');
CREATE TABLE passive_records (
          id INTEGER PRIMARY KEY AUTOINCREMENT, subject TEXT NOT NULL,
          subject_type TEXT NOT NULL, ip TEXT NOT NULL DEFAULT '', domain TEXT NOT NULL DEFAULT '',
          asn TEXT NOT NULL DEFAULT '', org TEXT NOT NULL DEFAULT '', network TEXT NOT NULL DEFAULT '',
          record_type TEXT NOT NULL, value_json TEXT NOT NULL DEFAULT '{}',
          source TEXT NOT NULL, observed_at TEXT NOT NULL, expires_at INTEGER,
          provider_id INTEGER, UNIQUE(subject,record_type,source,value_json),
          FOREIGN KEY(provider_id) REFERENCES passive_providers(id)
        );
INSERT INTO "passive_records" VALUES(1,'198.51.100.10','ip','198.51.100.10','','AS64496','V04 Registry','198.51.100.0/24','rdap','{"handle":"V04-NET"}','v04-rdap-fixture','2025-03-04T05:06:07+00:00',NULL,NULL);
CREATE TABLE result_uploads (
          idempotency_key TEXT PRIMARY KEY, job_id TEXT NOT NULL, worker_id TEXT NOT NULL,
          received_at TEXT NOT NULL, observation_count INTEGER NOT NULL
        );
INSERT INTO "result_uploads" VALUES('v04-result-key','v04-job-01','v04-worker-01','2025-03-04T05:06:07+00:00',1);
CREATE TABLE routing_prefixes (
          id INTEGER PRIMARY KEY AUTOINCREMENT, prefix TEXT NOT NULL, asn TEXT NOT NULL,
          organization TEXT NOT NULL DEFAULT '', source TEXT NOT NULL,
          first_seen TEXT NOT NULL, last_seen TEXT NOT NULL, expires_at INTEGER,
          UNIQUE(prefix,asn,source)
        );
INSERT INTO "routing_prefixes" VALUES(1,'198.51.100.0/24','AS64496','V04 Registry','v04-rdap-fixture','2025-03-04T05:06:07+00:00','2025-03-04T05:06:07+00:00',NULL);
CREATE TABLE scan_campaigns (
          id TEXT PRIMARY KEY, source_query TEXT NOT NULL, profile_id INTEGER NOT NULL,
          status TEXT NOT NULL, target_count INTEGER NOT NULL, job_count INTEGER NOT NULL,
          created_at TEXT NOT NULL, FOREIGN KEY(profile_id) REFERENCES scan_profiles(id)
        );
INSERT INTO "scan_campaigns" VALUES('v04-campaign-01','ip:198.51.100.10',4,'completed',1,1,'2025-03-04T05:06:07+00:00');
CREATE TABLE scan_jobs (
          id TEXT PRIMARY KEY, target TEXT NOT NULL, authorization_id INTEGER NOT NULL,
          profile_id INTEGER NOT NULL, ports TEXT NOT NULL, requested_worker_id TEXT,
          assigned_worker_id TEXT, status TEXT NOT NULL, progress_done INTEGER NOT NULL DEFAULT 0,
          progress_total INTEGER NOT NULL, attempts INTEGER NOT NULL DEFAULT 0,
          max_attempts INTEGER NOT NULL DEFAULT 3, lease_token TEXT, lease_expires_at INTEGER,
          error TEXT NOT NULL DEFAULT '', created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
          started_at TEXT, completed_at TEXT, FOREIGN KEY(authorization_id) REFERENCES authorizations(id),
          FOREIGN KEY(profile_id) REFERENCES scan_profiles(id), FOREIGN KEY(assigned_worker_id) REFERENCES workers(id)
        );
INSERT INTO "scan_jobs" VALUES('v04-job-01','198.51.100.10/32',1,4,'[443]','v04-worker-01','v04-worker-01','completed',1,1,1,3,NULL,NULL,'','2025-03-04T05:06:07+00:00','2025-03-04T05:06:07+00:00','2025-03-04T05:06:07+00:00','2025-03-04T05:06:07+00:00');
CREATE TABLE scan_profiles (
          id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL UNIQUE, ports TEXT NOT NULL,
          connect_timeout REAL NOT NULL DEFAULT 3, banner_timeout REAL NOT NULL DEFAULT 3,
          max_concurrency INTEGER NOT NULL DEFAULT 20, created_at TEXT NOT NULL
        , rate_per_second REAL NOT NULL DEFAULT 20);
INSERT INTO "scan_profiles" VALUES(1,'Web services','80,443,8080,8443',3.0,3.0,20,'2026-11-08T18:44:48+00:00',20.0);
INSERT INTO "scan_profiles" VALUES(2,'Common services','21,22,25,53,80,110,143,443,587,993,995,3306,5432,6379,8080,8443',3.0,3.0,20,'2026-11-08T18:44:48+00:00',20.0);
INSERT INTO "scan_profiles" VALUES(3,'Conservative','22,80,443',4.0,3.0,10,'2026-11-08T18:44:48+00:00',20.0);
INSERT INTO "scan_profiles" VALUES(4,'Quick Recon','22,80,443,8080,8443',2.0,2.0,20,'2026-11-08T18:44:48+00:00',30.0);
INSERT INTO "scan_profiles" VALUES(5,'Standard Recon','21,22,25,53,80,110,143,443,587,993,995,3306,5432,6379,8080,8443',3.0,3.0,20,'2026-11-08T18:44:48+00:00',20.0);
INSERT INTO "scan_profiles" VALUES(6,'Deep Recon','21,22,23,25,53,80,110,111,135,139,143,389,443,445,465,587,636,993,995,1433,1521,2049,2375,3306,3389,5432,5672,5900,6379,8080,8443,9200,27017',4.0,4.0,20,'2026-11-08T18:44:48+00:00',10.0);
CREATE TABLE services (
          id INTEGER PRIMARY KEY AUTOINCREMENT, host_ip TEXT NOT NULL, port INTEGER NOT NULL,
          proto TEXT NOT NULL DEFAULT 'tcp', service TEXT NOT NULL DEFAULT '', product TEXT NOT NULL DEFAULT '',
          first_seen TEXT NOT NULL, last_seen TEXT NOT NULL, last_observation_id INTEGER, source TEXT NOT NULL DEFAULT '', banner TEXT NOT NULL DEFAULT '', http_json TEXT NOT NULL DEFAULT '{}', tls_json TEXT NOT NULL DEFAULT '{}',
          UNIQUE(host_ip,port,proto), FOREIGN KEY(host_ip) REFERENCES hosts(ip)
        );
INSERT INTO "services" VALUES(1,'198.51.100.10',443,'tcp','https','nginx','2025-03-04T05:06:07+00:00','2025-03-04T05:06:07+00:00',1,'v04-release-fixture','fixture banner from v0.4','{}','{}');
CREATE TABLE workers (
          id TEXT PRIMARY KEY, name TEXT NOT NULL, token_hash TEXT NOT NULL UNIQUE,
          capabilities TEXT NOT NULL DEFAULT '[]', cpu_pct REAL NOT NULL DEFAULT 0,
          memory_pct REAL NOT NULL DEFAULT 0, active_jobs INTEGER NOT NULL DEFAULT 0,
          created_at TEXT NOT NULL, last_seen INTEGER NOT NULL DEFAULT 0
        , version TEXT NOT NULL DEFAULT '', max_concurrent INTEGER NOT NULL DEFAULT 1, completed_jobs INTEGER NOT NULL DEFAULT 0, last_error TEXT NOT NULL DEFAULT '');
INSERT INTO "workers" VALUES('v04-worker-01','V04 fixture worker','aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa','["tcp-connect"]',0.0,0.0,0,'2025-03-04T05:06:07+00:00',1741064767,'0.4.0',1,0,'');
CREATE INDEX idx_observations_ip ON observations(ip);
CREATE INDEX idx_observations_port ON observations(port);
CREATE INDEX idx_observations_seen ON observations(seen_at);
CREATE INDEX idx_services_host ON services(host_ip);
CREATE INDEX idx_jobs_status ON scan_jobs(status, created_at);
CREATE INDEX idx_passive_subject ON passive_records(subject);
CREATE INDEX idx_passive_ip ON passive_records(ip);
CREATE INDEX idx_passive_domain ON passive_records(domain);
CREATE INDEX idx_enrichment_status ON enrichment_jobs(status,updated_at);
CREATE INDEX idx_hostnames_name ON hostnames(hostname);
CREATE INDEX idx_hostnames_ip ON hostnames(ip);
CREATE INDEX idx_routing_asn ON routing_prefixes(asn,prefix);
CREATE INDEX idx_indexing_due ON indexing_schedules(enabled,next_run_at);
CREATE INDEX idx_hosts_asn_last ON hosts(asn,last_seen DESC,ip_hex);
CREATE INDEX idx_hosts_ip_sort ON hosts(ip_version,ip_hex);
CREATE INDEX idx_hosts_prefix ON hosts(network_prefix);
CREATE INDEX idx_services_port_host ON services(port,host_ip);
CREATE INDEX idx_services_name_host ON services(service,host_ip);
CREATE INDEX idx_observations_hash ON observations(observation_hash);
DELETE FROM "sqlite_sequence";
INSERT INTO "sqlite_sequence" VALUES('scan_profiles',6);
INSERT INTO "sqlite_sequence" VALUES('passive_providers',3);
INSERT INTO "sqlite_sequence" VALUES('services',1);
INSERT INTO "sqlite_sequence" VALUES('hostnames',1);
INSERT INTO "sqlite_sequence" VALUES('routing_prefixes',1);
INSERT INTO "sqlite_sequence" VALUES('observations',1);
INSERT INTO "sqlite_sequence" VALUES('authorizations',1);
INSERT INTO "sqlite_sequence" VALUES('passive_records',1);
INSERT INTO "sqlite_sequence" VALUES('indexing_schedules',1);
COMMIT;
