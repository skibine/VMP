-- Cache the domain "ip // info" (geo/ASN/PTR per resolved IP) and "port // scan" results, so the
-- operator doesn't re-probe (30-40s for some domains) every time they open the domain detail. One
-- row per domain; columns hold the JSON blob + an ISO timestamp of when it was fetched. The UI shows
-- the timestamp ("updated X ago") with a manual refresh button — no automatic expiry.

CREATE TABLE IF NOT EXISTS domain_intel (
  domain_id   INTEGER PRIMARY KEY,
  ipinfo      TEXT NOT NULL DEFAULT '',
  ipinfo_at   TEXT NOT NULL DEFAULT '',
  portscan    TEXT NOT NULL DEFAULT '',
  portscan_at TEXT NOT NULL DEFAULT ''
);

INSERT OR IGNORE INTO schema_versions (version, label) VALUES (25, 'domain_intel_cache');
