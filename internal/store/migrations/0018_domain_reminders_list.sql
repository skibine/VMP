-- region 0018_DOMAIN_REMINDERS_LIST [DOMAIN(8): Alerting; CONCEPT(8]: DomainReminders; TECH(9]: SQLite]
-- @purpose Per-event LIST of reminders (a domain can have several cert reminders at different
--          thresholds/channels), each with an optional repeat (re-notify every N days while the
--          reminder stays triggered; 0 = fire once when it enters the window). Supersedes the
--          single-threshold columns added in 0016/0017 (left in place, now unused).
-- @invariants
--   - kind IN ('cert','owner','dns'); days is the threshold (0 for dns, which is change-based).
--   - channel_id = 0 means in-app only; >0 references channels(id).
--   - repeat_days = 0 fires once per entry into the window; >0 re-fires every repeat_days while in it.
--   - last_notified_at dedups delivery per reminder.
-- endregion 0018_DOMAIN_REMINDERS_LIST

CREATE TABLE IF NOT EXISTS domain_reminders (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    domain_id       INTEGER NOT NULL,
    kind            TEXT    NOT NULL,                 -- cert | owner | dns
    days            INTEGER NOT NULL DEFAULT 0,       -- threshold days (0 for dns)
    channel_id      INTEGER NOT NULL DEFAULT 0,       -- 0 = in-app only
    repeat_days     INTEGER NOT NULL DEFAULT 0,       -- re-notify interval while triggered (0 = once)
    last_notified_at TEXT,
    created_at      TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    FOREIGN KEY (domain_id) REFERENCES domains(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_domain_reminders_domain ON domain_reminders(domain_id);
CREATE INDEX IF NOT EXISTS idx_domain_reminders_kind ON domain_reminders(kind);

INSERT OR IGNORE INTO schema_versions (version, label) VALUES (18, 'domain_reminders_list');
