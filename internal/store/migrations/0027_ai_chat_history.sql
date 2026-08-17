-- 0027: server-side AI chat history — ONE conversation shared by the web chat and the Telegram
-- bridge, so a thread started in the web UI continues in Telegram (and vice versa).
-- Rows are appended user+assistant per completed turn; trimmed to the newest 200 by the store.
CREATE TABLE IF NOT EXISTS ai_chat_messages (
    id      INTEGER PRIMARY KEY AUTOINCREMENT,
    role    TEXT NOT NULL,            -- user | assistant
    content TEXT NOT NULL,
    ts      TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);
CREATE INDEX IF NOT EXISTS idx_ai_chat_messages_id ON ai_chat_messages(id);
