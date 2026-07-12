-- region 0005_AUTH [DOMAIN(9): Security; CONCEPT(8): AccessControl; TECH(9): SQLite]
-- @purpose Users (owner/guest) and server-side sessions for Plane B access control.
-- @invariants
--   - username is UNIQUE.
--   - password_hash stores an argon2id encoded string (never a plaintext password).
--   - sessions carry an absolute expires_at; the app treats expired rows as invalid.
-- endregion 0005_AUTH

CREATE TABLE IF NOT EXISTS users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    username      TEXT    NOT NULL UNIQUE,
    password_hash TEXT    NOT NULL,
    password_algo TEXT    NOT NULL DEFAULT 'argon2id',
    role          TEXT    NOT NULL DEFAULT 'owner',   -- owner | guest (RBAC matrix later)
    is_active     INTEGER NOT NULL DEFAULT 1,
    created_at    TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    last_login_at TEXT,
    CHECK (role IN ('owner','guest'))
);
CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);

CREATE TABLE IF NOT EXISTS sessions (
    token      TEXT    PRIMARY KEY,
    user_id    INTEGER NOT NULL,
    created_at TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    expires_at TEXT    NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);

INSERT OR IGNORE INTO schema_versions (version, label) VALUES (5, 'auth');
-- endregion 0005_AUTH
