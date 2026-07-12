-- region 0002_VMS_CHECKS_DOMAINS [DOMAIN(8): Storage; CONCEPT(7): ConfigSchema; TECH(9): SQLite]
-- @purpose Create the configuration tables: VMs (soft-delete), domains (unique name),
--          checks (FK to vms/domains). This is the data the monitoring engine, UI and AI
--          tools operate on (foundation-v2 §4, adapted).
-- @invariants
--   - vms.archived_at implements soft-delete; List excludes archived by default.
--   - checks.vm_id / domain_id are nullable (a check targets exactly one of them).
--   - domains.name is UNIQUE.
--   - FKs use ON DELETE SET NULL so deleting a VM does not erase its check history config.

-- ── vms ────────────────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS vms (
    id                 INTEGER PRIMARY KEY AUTOINCREMENT,
    name               TEXT    NOT NULL,
    hostname           TEXT    NOT NULL,
    ip                 TEXT,
    port_ssh           INTEGER NOT NULL DEFAULT 22,
    ssh_user           TEXT,
    auth_type          TEXT,                      -- key | password | agent
    provider           TEXT,
    location_country   TEXT,
    location_city      TEXT,
    tags               TEXT    NOT NULL DEFAULT '[]',  -- JSON array of strings
    group_id           INTEGER,
    notes              TEXT,
    cost_monthly       REAL,
    currency           TEXT,
    owner_user_id      INTEGER,
    agent_enabled      INTEGER NOT NULL DEFAULT 0,
    agent_port         INTEGER,
    prometheus_url     TEXT,
    record_ssh_sessions INTEGER NOT NULL DEFAULT 0,
    created_at         TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    updated_at         TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    archived_at        TEXT
);
CREATE INDEX IF NOT EXISTS idx_vms_archived ON vms(archived_at);

-- ── domains (before checks: checks references domains) ──────────────────────────────
CREATE TABLE IF NOT EXISTS domains (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    name            TEXT    NOT NULL UNIQUE,
    registrar       TEXT,
    auto_discovered INTEGER NOT NULL DEFAULT 0,
    vm_id           INTEGER,
    monitor_dns     INTEGER NOT NULL DEFAULT 0,
    monitor_whois   INTEGER NOT NULL DEFAULT 0,
    monitor_tls     INTEGER NOT NULL DEFAULT 0,
    created_at      TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    FOREIGN KEY (vm_id) REFERENCES vms(id) ON DELETE SET NULL
);

-- ── checks ──────────────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS checks (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    vm_id        INTEGER,
    domain_id    INTEGER,
    target_type  TEXT    NOT NULL,               -- vm | domain
    check_type   TEXT    NOT NULL,               -- ping|tcp|http|whois|tls|agent|prom
    params       TEXT    NOT NULL DEFAULT '{}',   -- JSON
    interval_sec INTEGER NOT NULL DEFAULT 60,
    enabled      INTEGER NOT NULL DEFAULT 1,
    thresholds   TEXT    NOT NULL DEFAULT '{}',   -- JSON
    created_at   TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    FOREIGN KEY (vm_id) REFERENCES vms(id) ON DELETE SET NULL,
    FOREIGN KEY (domain_id) REFERENCES domains(id) ON DELETE SET NULL,
    CHECK (target_type IN ('vm','domain'))
);
CREATE INDEX IF NOT EXISTS idx_checks_vm ON checks(vm_id);
CREATE INDEX IF NOT EXISTS idx_checks_enabled ON checks(enabled);

INSERT OR IGNORE INTO schema_versions (version, label) VALUES (2, 'vms_checks_domains');
-- endregion 0002_VMS_CHECKS_DOMAINS
