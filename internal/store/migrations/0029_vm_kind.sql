-- 0029: VM kind — semantic split between servers and NETWORK EQUIPMENT (routers, cameras,
-- external web panels). Equipment is functionally a VM (tcp-liveness/http/exposures checks,
-- SSH optional) but must be visually and semantically distinct from servers.
-- Closed set: server (default, all pre-existing rows) | network | iot | web.
ALTER TABLE vms ADD COLUMN kind TEXT NOT NULL DEFAULT 'server';
INSERT OR IGNORE INTO schema_versions (version, label) VALUES (29, 'vm_kind');
