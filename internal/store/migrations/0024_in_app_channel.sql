-- Seed a built-in "in-app" delivery channel.
--
-- in-app delivery = the alert creates a notification shown in the VM Pulse bell dropdown (no external
-- service). It is OPTIONAL: the operator attaches it to a server in the bell picker exactly like a
-- telegram/webhook channel. It is seeded here so it always appears in the channel list; deleting it
-- merely removes the option (a later start re-seeds via INSERT OR IGNORE).

INSERT OR IGNORE INTO channels (type, name, config, enabled)
VALUES ('in-app', 'in-app (bell)', '{}', 1);

INSERT OR IGNORE INTO schema_versions (version, label) VALUES (24, 'in_app_channel');
