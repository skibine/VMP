-- Per-server alert channels: which delivery channels a server's liveness alerts go to.
--
-- Routes "WHERE an alert is delivered" to the server (not the rule). A server with its own channels
-- alerts only there (e.g. you + that server's owner); a server with none gets a "add channels" hint.
-- The fleet/mute layer (which servers are alerted) is unchanged; this only changes the destination.
CREATE TABLE IF NOT EXISTS vm_alert_channels (
    vm_id      INTEGER NOT NULL,
    channel_id INTEGER NOT NULL,
    PRIMARY KEY (vm_id, channel_id)
);

INSERT OR IGNORE INTO schema_versions (version, label) VALUES (22, 'vm_alert_channels');
