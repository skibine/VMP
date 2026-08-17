-- 0030: collapse the equipment kinds (network/iot/web) into a single 'equipment' bucket —
-- the operator found the granular split unnecessary (a router exposes web+ssh+telnet alike, so
-- pigeonholing by interface is artificial). Set: server | equipment.
UPDATE vms SET kind='equipment' WHERE kind IN ('network','iot','web');
INSERT OR IGNORE INTO schema_versions (version, label) VALUES (30, 'kind_collapse');
