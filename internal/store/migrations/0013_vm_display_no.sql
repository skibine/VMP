-- region 0013_VM_DISPLAY_NO [DOMAIN(8): Config; CONCEPT(6): Ordinal; TECH(9): SQLite]
-- @purpose A stable, human-friendly ordinal per VM (so an operator with several similar boxes, e.g.
--          "4 in USA", can tell them apart by #N besides the name).
-- @invariants
--   - display_no is assigned once at creation (max+1) and NEVER renumbered: deleting VM #3 leaves
--     #4 and #5 as-is (a gap at 3). Predictable — you never lose track of "VM #4".
-- endregion 0013_VM_DISPLAY_NO

ALTER TABLE vms ADD COLUMN display_no INTEGER NOT NULL DEFAULT 0;
-- Backfill existing rows in id order so they get 1,2,3,...
UPDATE vms SET display_no = (SELECT COUNT(*) FROM vms v2 WHERE v2.id <= vms.id);

INSERT OR IGNORE INTO schema_versions (version, label) VALUES (13, 'vm_display_no');
