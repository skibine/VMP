-- region 0016_DOMAIN_REMINDERS [DOMAIN(8): Alerting; CONCEPT(7]: DomainExpiry; TECH(9]: SQLite]
-- @purpose Per-domain expiry reminders: notify N days before the TLS certificate expires and/or
--          before the domain registration (ownership) expires. last_*_notified_at dedups delivery
--          (the evaluator re-notifies at most once per renotify window while in the warning zone).
-- @invariants
--   - Both thresholds default to 0 (off); existing rows keep working with no reminders.
--   - last_*_notified_at is NULL until the first notification fires.
-- endregion 0016_DOMAIN_REMINDERS

ALTER TABLE domains ADD COLUMN cert_notify_days INTEGER NOT NULL DEFAULT 0;
ALTER TABLE domains ADD COLUMN owner_notify_days INTEGER NOT NULL DEFAULT 0;
ALTER TABLE domains ADD COLUMN cert_last_notified_at TEXT;
ALTER TABLE domains ADD COLUMN owner_last_notified_at TEXT;
INSERT OR IGNORE INTO schema_versions (version, label) VALUES (16, 'domain_reminders');
