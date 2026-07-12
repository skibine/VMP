-- region 0003_CHECK_RESULTS [DOMAIN(8): Storage; CONCEPT(8): Metrics; TECH(9): SQLite]
-- @purpose Store the outcome of every executed check (Plane A writes). Indexed for the
--          "latest N results for a check" access pattern. Retention (delete old) runs in app.
-- @invariants
--   - status domain: ok | warn | critical | unknown.
--   - idx(check_id, ts DESC) serves the hot "recent results" query.
-- endregion 0003_CHECK_RESULTS

CREATE TABLE IF NOT EXISTS check_results (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    check_id    INTEGER NOT NULL,
    ts          TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    status      TEXT    NOT NULL,             -- ok | warn | critical | unknown
    latency_ms  REAL    NOT NULL DEFAULT 0,
    message     TEXT    NOT NULL DEFAULT '',
    detail      TEXT    NOT NULL DEFAULT '{}'  -- JSON
);
CREATE INDEX IF NOT EXISTS idx_results_check_ts ON check_results(check_id, ts DESC);

INSERT OR IGNORE INTO schema_versions (version, label) VALUES (3, 'check_results');
-- endregion 0003_CHECK_RESULTS
