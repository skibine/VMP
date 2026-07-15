-- region 0014_CHECK_SYSTEM [DOMAIN(8): Monitoring; CONCEPT(8]: Liveness; TECH(9]: SQLite]
-- @purpose Mark "system" checks — the always-on composite liveness probe VM Pulse auto-creates per
--          VM. System checks drive the fleet status dot INDEPENDENTLY of alert configuration, are
--          not user-deletable, and are hidden from the user-facing "alert rules" view.
-- @invariants
--   - Every VM always has exactly one system liveness check (auto-provisioned, re-created if gone).
-- endregion 0014_CHECK_SYSTEM

ALTER TABLE checks ADD COLUMN system INTEGER NOT NULL DEFAULT 0;
INSERT OR IGNORE INTO schema_versions (version, label) VALUES (14, 'check_system');
