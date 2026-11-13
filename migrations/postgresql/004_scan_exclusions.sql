CREATE TABLE IF NOT EXISTS scan_exclusions (
    id BIGSERIAL PRIMARY KEY,
    name TEXT NOT NULL,
    cidr TEXT NOT NULL UNIQUE,
    reason TEXT NOT NULL DEFAULT '',
    enabled INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL,
    created_by TEXT NOT NULL DEFAULT 'admin'
);
CREATE INDEX IF NOT EXISTS idx_scan_exclusions_enabled
    ON scan_exclusions(enabled, cidr);
