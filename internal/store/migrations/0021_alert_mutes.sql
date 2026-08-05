-- Per-VM alert mute: excludes a VM from fleet-wide (vm_id=NULL) liveness rules.
--
-- Enables the "all except one" flow: turn the fleet-wide alert ON, then open one server and turn
-- its bell OFF -> it is muted (no liveness-down alert for it) while every other server stays alerted.
-- Scoped rules (vm_id = that VM) are explicit overrides and always fire regardless of mute.
CREATE TABLE IF NOT EXISTS alert_mutes (
    vm_id INTEGER PRIMARY KEY
);

INSERT OR IGNORE INTO schema_versions (version, label) VALUES (21, 'alert_mutes');
