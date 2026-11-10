CREATE TABLE IF NOT EXISTS sqlite_migration_runs (
  import_id TEXT PRIMARY KEY,
  source_fingerprint TEXT NOT NULL,
  status TEXT NOT NULL,
  started_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  completed_at TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS sqlite_migration_cursors (
  import_id TEXT NOT NULL,
  table_name TEXT NOT NULL,
  last_source_rowid BIGINT NOT NULL DEFAULT 0,
  rows_imported BIGINT NOT NULL DEFAULT 0,
  updated_at TEXT NOT NULL,
  PRIMARY KEY(import_id,table_name),
  FOREIGN KEY(import_id) REFERENCES sqlite_migration_runs(import_id)
);
