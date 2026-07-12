-- region 0001_INIT [DOMAIN(8): Storage; CONCEPT(8): SchemaBootstrap; TECH(9): SQLite]
-- @purpose Establish the four logical schemas (config/metrics/incidents/audit) and the
--          authoritative migration tracking table. Plane A tables avoid credential deps.
-- @invariants
--   - schema_versions is the single source of truth for migration state.
--   - audit_log forms a tamper-evident prev_hash chain (Plane A service events only).

-- Authoritative migration ledger.
CREATE TABLE IF NOT EXISTS schema_versions (
    version    INTEGER PRIMARY KEY,
    applied_at TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    label      TEXT    NOT NULL
);

-- ── schema: audit (Plane A service events + Plane B admin actions) ──────────────────
CREATE TABLE IF NOT EXISTS audit_log (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    ts          TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    user_id     INTEGER,                       -- NULL for system/Plane A events
    action      TEXT    NOT NULL,
    target_type TEXT,
    target_id   TEXT,
    ip_address  TEXT,
    user_agent  TEXT,
    detail      TEXT    NOT NULL DEFAULT '{}',  -- JSON
    success     INTEGER NOT NULL DEFAULT 1,     -- 0/1
    prev_hash   TEXT    NOT NULL,               -- sha256(prev_hash || canonical_json(record))
    hash        TEXT    NOT NULL,
    plane       TEXT    NOT NULL DEFAULT 'A'    -- 'A' always-on | 'B' gated
);
CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_log(ts);

-- ── schema: config (VMs, users, rules, ...) — stub for this slice ───────────────────
CREATE TABLE IF NOT EXISTS config_meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

-- ── schema: metrics (Plane A writes) — stub for this slice ──────────────────────────
CREATE TABLE IF NOT EXISTS metric_samples (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    vm_id       INTEGER,
    ts          TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    metric_name TEXT    NOT NULL,
    value       REAL    NOT NULL,
    labels      TEXT    NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS idx_metrics_vm_ts ON metric_samples(vm_id, ts DESC);

-- ── schema: incidents — stub for this slice ─────────────────────────────────────────
CREATE TABLE IF NOT EXISTS incidents (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    vm_id      INTEGER,
    started_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    resolved_at TEXT,
    severity   TEXT NOT NULL DEFAULT 'warning',
    summary    TEXT NOT NULL
);

INSERT OR IGNORE INTO schema_versions (version, label) VALUES (1, 'init_skeleton');
-- endregion 0001_INIT
