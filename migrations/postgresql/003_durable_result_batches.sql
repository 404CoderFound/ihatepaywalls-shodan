-- Durable result batch receipts, applied after initial schema and SQLite-import ledger.
-- All writes run inside the controlplane transaction. Batch index uniqueness
-- provides exactly-once ingestion under reconnect/retry.
CREATE TABLE IF NOT EXISTS scan_result_batches (
  job_id TEXT NOT NULL REFERENCES scan_jobs(id),
  batch_index INTEGER NOT NULL CHECK(batch_index >= 0),
  payload_hash TEXT NOT NULL,
  checks_done INTEGER NOT NULL CHECK(checks_done >= 1),
  observation_count INTEGER NOT NULL CHECK(observation_count >= 0),
  created_at TEXT NOT NULL,
  PRIMARY KEY(job_id,batch_index)
);
CREATE TABLE IF NOT EXISTS scan_result_finishes (
  job_id TEXT PRIMARY KEY REFERENCES scan_jobs(id),
  worker_id TEXT NOT NULL REFERENCES workers(id),
  batch_count INTEGER NOT NULL,
  completed_checks INTEGER NOT NULL,
  observation_count INTEGER NOT NULL,
  finished_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_scan_result_batches_job_checks
ON scan_result_batches(job_id,checks_done);
