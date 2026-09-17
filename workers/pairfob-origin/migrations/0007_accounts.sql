CREATE TABLE users (
  user_id TEXT PRIMARY KEY,
  username TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  role TEXT NOT NULL,
  created_at INTEGER NOT NULL
);

CREATE TABLE user_sessions (
  token_hash TEXT PRIMARY KEY,
  user_id TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL
);

CREATE INDEX user_sessions_user ON user_sessions (user_id);
CREATE INDEX user_sessions_expiry ON user_sessions (expires_at);

-- Single row. The code is shown to whoever may rotate it, so it is stored as
-- typed rather than hashed; its low entropy is covered by the lockout ledger.
CREATE TABLE invite_codes (
  id INTEGER PRIMARY KEY CHECK (id = 1),
  code TEXT NOT NULL,
  updated_by TEXT,
  updated_at INTEGER NOT NULL
);

CREATE TABLE auth_failures (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  subject TEXT NOT NULL,
  at INTEGER NOT NULL
);

CREATE INDEX auth_failures_subject ON auth_failures (subject, at);

CREATE TABLE device_owners (
  daemon_id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL,
  label TEXT,
  bound_at INTEGER NOT NULL
);

CREATE INDEX device_owners_user ON device_owners (user_id, bound_at);
