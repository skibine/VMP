-- region 0017_DOMAIN_REMINDER_CHANNELS [DOMAIN(8): Alerting; CONCEPT(8]: DomainReminders; TECH(9]: SQLite]
-- @purpose (1) attach a delivery channel to each domain reminder (cert / owner / dns), (2) track
--          DNS-record changes for the dns-change reminder (last signature + dedup timestamp),
--          (3) add an in-app notification center so reminders surface inside VMPulse itself.
-- @invariants
--   - *_channel_id = 0 means in-app only; >0 references channels(id) (telegram/webhook).
--   - dns_last_signature NULL on first probe = baseline (no alert); subsequent changes alert.
-- endregion 0017_DOMAIN_REMINDER_CHANNELS

ALTER TABLE domains ADD COLUMN cert_notify_channel_id  INTEGER NOT NULL DEFAULT 0;
ALTER TABLE domains ADD COLUMN owner_notify_channel_id INTEGER NOT NULL DEFAULT 0;
ALTER TABLE domains ADD COLUMN dns_notify_enabled      INTEGER NOT NULL DEFAULT 0;
ALTER TABLE domains ADD COLUMN dns_notify_channel_id   INTEGER NOT NULL DEFAULT 0;
ALTER TABLE domains ADD COLUMN dns_last_signature      TEXT;
ALTER TABLE domains ADD COLUMN dns_last_notified_at    TEXT;

CREATE TABLE IF NOT EXISTS notifications (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    title       TEXT    NOT NULL,
    body        TEXT    NOT NULL,
    kind        TEXT    NOT NULL DEFAULT 'reminder',  -- reminder | system
    ref_id      INTEGER,                               -- domain id (for reminders)
    created_at  TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    read_at     TEXT
);
CREATE INDEX IF NOT EXISTS idx_notifications_unread ON notifications(read_at) WHERE read_at IS NULL;

INSERT OR IGNORE INTO schema_versions (version, label) VALUES (17, 'domain_reminder_channels');
