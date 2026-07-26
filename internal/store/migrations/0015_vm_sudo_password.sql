-- region 0015_VM_SUDO_PASSWORD [DOMAIN(9): Security; CONCEPT(8]: Sudo; TECH(9]: SQLite]
-- @purpose Add an OPTIONAL sudo password to per-VM SSH credentials so the AI executor (RunCommand,
--          non-interactive) can run privileged commands (install/restart/systemctl) via `sudo -S`.
--          Stored vault-encrypted at rest exactly like the SSH secret; empty = no sudo password
--          (RunCommand falls back to passwordless `sudo -n`).
-- @invariants
--   - Column is optional (default ''); existing rows keep working without a sudo password.
-- endregion 0015_VM_SUDO_PASSWORD

ALTER TABLE vm_credentials ADD COLUMN sudo_password TEXT NOT NULL DEFAULT '';
INSERT OR IGNORE INTO schema_versions (version, label) VALUES (15, 'vm_sudo_password');
