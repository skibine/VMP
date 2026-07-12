-- region 0010_AI_ACCESS_AND_INVENTORY [DOMAIN(8): Security,Storage; CONCEPT(7): AIAccess,Inventory; TECH(9): SQLite]
-- @purpose (1) Per-VM opt-in AI access (ai_enabled): the assistant only sees VMs the operator
--          explicitly grants. (2) Persist the SSH inventory profile so the "system // profile"
--          block survives VM navigation (was ephemeral, returned only on cred-save).
-- @invariants
--   - ai_enabled defaults to 0 (off): access is opt-in, never assumed.
--   - inventory is the last successful SSH inventory JSON (plain text, non-secret facts only).
-- endregion 0010_AI_ACCESS_AND_INVENTORY

ALTER TABLE vms ADD COLUMN ai_enabled INTEGER NOT NULL DEFAULT 0;
ALTER TABLE vm_credentials ADD COLUMN inventory TEXT NOT NULL DEFAULT '';

INSERT OR IGNORE INTO schema_versions (version, label) VALUES (10, 'ai_access_and_inventory');
