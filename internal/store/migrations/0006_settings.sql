-- region 0006_SETTINGS [DOMAIN(9): Security; CONCEPT(7]: InAppSettings; TECH(9]: SQLite,vault]
-- @purpose In-app settings (AI provider config, etc.) and per-VM SSH credentials. Secret values
--          are encrypted at rest by the vault (enc:v1 marker); the app never returns them via GET.
-- @invariants
--   - settings.is_secret marks rows whose value is vault-encrypted.
--   - vm_credentials has at most one row per VM (PK vm_id); secret is vault-encrypted.
-- endregion 0006_SETTINGS

CREATE TABLE IF NOT EXISTS settings (
    key        TEXT PRIMARY KEY,
    value      TEXT NOT NULL,
    is_secret  INTEGER NOT NULL DEFAULT 0,
    updated_at TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);

CREATE TABLE IF NOT EXISTS vm_credentials (
    vm_id     INTEGER PRIMARY KEY,
    ssh_user  TEXT    NOT NULL DEFAULT '',
    auth_type TEXT    NOT NULL DEFAULT 'password',  -- password | key | agent
    secret    TEXT    NOT NULL DEFAULT '',           -- vault-encrypted (password OR private key)
    updated_at TEXT   NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    FOREIGN KEY (vm_id) REFERENCES vms(id) ON DELETE CASCADE,
    CHECK (auth_type IN ('password','key','agent'))
);

INSERT OR IGNORE INTO schema_versions (version, label) VALUES (6, 'settings');
-- endregion 0006_SETTINGS
