-- region 0031_TOTP_REPLAY [DOMAIN(9): Security; CONCEPT(8): TOTP,ReplayProtection; TECH(8): SQLite]
-- @purpose Store the last successfully used TOTP counter step per user so a captured code cannot
--          be replayed within its ~60-90s validity window (audit 2.5).
-- @invariants
--   - totp_last_step is 0 for users that never logged in with 2FA (or pre-migration).
--   - A login only succeeds with a step STRICTLY GREATER than the stored one; the winning step
--     is persisted on success. Clock skew is absorbed by the +/-1 step search, not by this value.
-- endregion 0031_TOTP_REPLAY

ALTER TABLE users ADD COLUMN totp_last_step INTEGER NOT NULL DEFAULT 0;
INSERT OR IGNORE INTO schema_versions (version, label) VALUES (31, 'totp_replay');
