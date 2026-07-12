-- region 0004_ALERTS [DOMAIN(8): Storage; CONCEPT(8): Alerting; TECH(9): SQLite]
-- @purpose Alerting schema: rules, delivery channels, rule<->channel links, fired alerts.
-- @invariants
--   - alert_rule_channels PK(rule_id, channel_id) + CASCADE delete on both sides.
--   - alerts idx (rule_id, check_id, triggered_at DESC) backs the cooldown query.
--   - channels.config is JSON; secrets stored PLAINTEXT for now (TODO(encrypt) in vault slice).
-- endregion 0004_ALERTS

CREATE TABLE IF NOT EXISTS alert_rules (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    name           TEXT    NOT NULL,
    check_type     TEXT,                          -- nullable = apply to all check types
    trigger_status TEXT    NOT NULL,              -- warn | critical | unknown
    severity       TEXT    NOT NULL,              -- warning | critical
    cooldown_sec   INTEGER NOT NULL DEFAULT 300,
    enabled        INTEGER NOT NULL DEFAULT 1,
    created_at     TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    CHECK (trigger_status IN ('warn','critical','unknown')),
    CHECK (severity       IN ('warning','critical'))
);

CREATE TABLE IF NOT EXISTS channels (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    type       TEXT    NOT NULL,                  -- telegram | log | email | webhook
    name       TEXT    NOT NULL,
    config     TEXT    NOT NULL DEFAULT '{}',     -- JSON; TODO(encrypt) secrets when vault lands
    enabled    INTEGER NOT NULL DEFAULT 1,
    created_at TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);

CREATE TABLE IF NOT EXISTS alert_rule_channels (
    rule_id    INTEGER NOT NULL,
    channel_id INTEGER NOT NULL,
    PRIMARY KEY (rule_id, channel_id),
    FOREIGN KEY (rule_id)    REFERENCES alert_rules(id) ON DELETE CASCADE,
    FOREIGN KEY (channel_id) REFERENCES channels(id)    ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS alerts (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    rule_id        INTEGER NOT NULL,
    check_id       INTEGER NOT NULL,
    vm_id          INTEGER,
    severity       TEXT    NOT NULL,
    message        TEXT    NOT NULL,
    triggered_at   TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    acknowledged_at TEXT,
    delivery_log   TEXT    NOT NULL DEFAULT '{}',  -- JSON {channel_id: {ok, err}}
    FOREIGN KEY (rule_id) REFERENCES alert_rules(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_alerts_triggered    ON alerts(triggered_at);
CREATE INDEX IF NOT EXISTS idx_alerts_rule_check   ON alerts(rule_id, check_id, triggered_at DESC);

INSERT OR IGNORE INTO schema_versions (version, label) VALUES (4, 'alerts');
-- endregion 0004_ALERTS
