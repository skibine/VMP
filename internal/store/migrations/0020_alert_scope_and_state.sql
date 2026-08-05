-- Alert rule scope + edge-triggered state.
--
-- vm_id on alert_rules: when set, the rule matches ONLY that VM's checks (per-VM alerts). NULL = the
-- rule applies to all VMs (the legacy/global behavior, and the fleet-wide "any VM down" rule).
ALTER TABLE alert_rules ADD COLUMN vm_id INTEGER;

-- alert_state tracks the last seen status per (rule, check) so the evaluator can fire on TRANSITIONS
-- (down when entering critical, recovered when returning to ok) instead of re-firing every cycle.
CREATE TABLE IF NOT EXISTS alert_state (
    rule_id     INTEGER NOT NULL,
    check_id    INTEGER NOT NULL,
    last_status TEXT    NOT NULL,
    PRIMARY KEY (rule_id, check_id)
);

INSERT OR IGNORE INTO schema_versions (version, label) VALUES (20, 'alert_scope_and_state');
