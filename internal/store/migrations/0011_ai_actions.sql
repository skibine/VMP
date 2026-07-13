-- region 0011_AI_ACTIONS [DOMAIN(9): AI,Security; CONCEPT(8): MutatingActions,Approval; TECH(9): SQLite]
-- @purpose Persist AI-proposed VM commands (Plane B mutating actions) so they can be approved/
--          rejected out-of-band and audited. Default flow: the model proposes, the operator approves.
-- @invariants
--   - A pending action is never executed until an operator (or auto-approve) flips it to approved.
--   - Every execution is recorded (status done/error + output) for the tamper-evident audit trail.
-- endregion 0011_AI_ACTIONS

CREATE TABLE IF NOT EXISTS ai_actions (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    vm_id        INTEGER NOT NULL,
    command      TEXT    NOT NULL,
    reason       TEXT    NOT NULL DEFAULT '',
    status       TEXT    NOT NULL DEFAULT 'pending', -- pending | approved | rejected | done | error
    output       TEXT    NOT NULL DEFAULT '',
    requested_by TEXT    NOT NULL DEFAULT 'ai',       -- ai | <username>
    created_at   TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    executed_at  TEXT,
    FOREIGN KEY (vm_id) REFERENCES vms(id) ON DELETE CASCADE
);

INSERT OR IGNORE INTO schema_versions (version, label) VALUES (11, 'ai_actions');
