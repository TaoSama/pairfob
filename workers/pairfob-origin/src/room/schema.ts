export const ROOM_DDL = [
  `CREATE TABLE IF NOT EXISTS _sql_schema_migrations (
    id INTEGER PRIMARY KEY,
    applied_at INTEGER NOT NULL
  )`,
  `CREATE TABLE IF NOT EXISTS meta (
    daemon_id TEXT PRIMARY KEY,
    reconnect_hash TEXT NOT NULL,
    grant_id TEXT,
    created_at INTEGER NOT NULL
  )`,
  `CREATE TABLE IF NOT EXISTS pair_slot (
    pair_ref TEXT PRIMARY KEY,
    pair_loc TEXT NOT NULL UNIQUE,
    deadline INTEGER NOT NULL
  )`,
  `CREATE TABLE IF NOT EXISTS pair_tickets (
    ticket TEXT PRIMARY KEY,
    pair_ref TEXT NOT NULL,
    deadline INTEGER NOT NULL
  )`,
  `CREATE TABLE IF NOT EXISTS alarms (
    id INTEGER PRIMARY KEY,
    at INTEGER NOT NULL,
    kind TEXT NOT NULL,
    ref TEXT
  )`,
  `CREATE TABLE IF NOT EXISTS binds (
    route_id TEXT PRIMARY KEY,
    kind TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    pair_ref TEXT
  )`,
  `INSERT OR IGNORE INTO _sql_schema_migrations (id, applied_at) VALUES (1, 0)`,
  // Gate attempt ledger. Timestamp and outcome only: the relay never sees the
  // passphrase, so nothing that could identify a guess or a guesser is stored.
  `CREATE TABLE IF NOT EXISTS gate_attempts (
    id INTEGER PRIMARY KEY,
    at INTEGER NOT NULL,
    ok INTEGER NOT NULL
  )`,
  `CREATE INDEX IF NOT EXISTS idx_gate_attempts_at ON gate_attempts (at)`,
  `INSERT OR IGNORE INTO _sql_schema_migrations (id, applied_at) VALUES (2, 0)`,
] as const;
