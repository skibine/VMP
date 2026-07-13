-- region 0012_USER_TOTP [DOMAIN(9): Security; CONCEPT(8): 2FA,TOTP; TECH(9): SQLite]
-- @purpose Per-user TOTP two-factor authentication. The TOTP seed is vault-encrypted at rest.
--          2FA is opt-in but cannot be disabled while any VM stores SSH credentials (cred-gate):
--          privileged access requires a hardened login.
-- @invariants
--   - totp_secret is vault-encrypted; empty when 2FA is off.
--   - backup_codes stores an argon2id-hashed JSON array of one-time recovery codes.
-- endregion 0012_USER_TOTP

ALTER TABLE users ADD COLUMN totp_secret TEXT NOT NULL DEFAULT '';
ALTER TABLE users ADD COLUMN totp_enabled INTEGER NOT NULL DEFAULT 0;
ALTER TABLE users ADD COLUMN backup_codes TEXT NOT NULL DEFAULT '';

INSERT OR IGNORE INTO schema_versions (version, label) VALUES (12, 'user_totp');
