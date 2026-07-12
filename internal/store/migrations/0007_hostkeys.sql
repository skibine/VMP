-- region 0007_HOSTKEYS [DOMAIN(9): Security; CONCEPT(8): HostKeyTOFU; TECH(9): SQLite]
-- @purpose TOFU host-key store for SSH connections (Plane B). On first successful SSH dial the
--          server's public-key fingerprint is recorded; subsequent dials must match or the
--          connection is rejected (MITM / reinstall guard). Resettable via DELETE.
-- @invariants
--   - At most one host key row per VM (PK vm_id).
--   - Cascade-deleted with the VM.
--   - fingerprint is the ssh public-key fingerprint (sha256 base64) for fast compare.
-- endregion 0007_HOSTKEYS

CREATE TABLE IF NOT EXISTS vm_hostkeys (
    vm_id       INTEGER PRIMARY KEY,
    fingerprint TEXT    NOT NULL,
    algo        TEXT    NOT NULL DEFAULT '',
    first_seen  TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    FOREIGN KEY (vm_id) REFERENCES vms(id) ON DELETE CASCADE
);

INSERT OR IGNORE INTO schema_versions (version, label) VALUES (7, 'hostkeys');
-- endregion 0007_HOSTKEYS
