-- region 0008_METRICS [DOMAIN(8): Observability; CONCEPT(8): MetricsCollection,Downsampling; TECH(9): SQLite]
-- @purpose Enable per-VM metrics collection (pull-over-SSH poller) and add a resolution column to
--          metric_samples so the downsampler (§5.2: 7d per-minute -> 1/hour) can coexist raw+1h rows.
-- @invariants
--   - vms.metrics_enabled gates the pull-poller (distinct from agent_enabled = future push-agent).
--   - metric_samples.resolution defaults to 'raw'; the downsampler writes '1h' rows and deletes raw.
-- endregion 0008_METRICS

ALTER TABLE vms ADD COLUMN metrics_enabled INTEGER NOT NULL DEFAULT 0;

ALTER TABLE metric_samples ADD COLUMN resolution TEXT NOT NULL DEFAULT 'raw';
CREATE INDEX IF NOT EXISTS idx_metrics_vm_name_ts ON metric_samples(vm_id, metric_name, ts DESC);

INSERT OR IGNORE INTO schema_versions (version, label) VALUES (8, 'metrics');
-- endregion 0008_METRICS
