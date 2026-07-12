-- region 0009_KEY_PASSPHRASE [DOMAIN(9): Security; CONCEPT(7]: SSHKeyPassphrase; TECH(9]: SQLite,vault]
-- @purpose Support passphrase-protected SSH private keys. The passphrase is vault-encrypted at rest
--          alongside the key secret; used by the dialer (ssh.ParsePrivateKeyWithPassphrase).
-- @invariants
--   - key_passphrase is vault-encrypted (enc:v1: marker); empty when the key has no passphrase.
-- endregion 0009_KEY_PASSPHRASE

ALTER TABLE vm_credentials ADD COLUMN key_passphrase TEXT NOT NULL DEFAULT '';

INSERT OR IGNORE INTO schema_versions (version, label) VALUES (9, 'key_passphrase');
-- endregion 0009_KEY_PASSPHRASE
