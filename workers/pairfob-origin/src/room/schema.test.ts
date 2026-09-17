import { Database } from "bun:sqlite";
import { describe, expect, test } from "bun:test";
import { ROOM_DDL } from "./schema.ts";

/** Statements a Durable Object that only ever ran migration id=1 would have applied. */
function legacyDdl(): string[] {
  const end = ROOM_DDL.findIndex((s) => s.includes("VALUES (1, 0)"));
  expect(end).toBeGreaterThanOrEqual(0);
  return ROOM_DDL.slice(0, end + 1) as unknown as string[];
}

function applyDdl(db: Database, stmts: readonly string[]): void {
  for (const s of stmts) db.exec(s);
}

function tableExists(db: Database, name: string): boolean {
  return db.query("SELECT name FROM sqlite_master WHERE type='table' AND name=?").all(name).length === 1;
}

function migrationIds(db: Database): number[] {
  return db
    .query<{ id: number }, []>("SELECT id FROM _sql_schema_migrations ORDER BY id")
    .all()
    .map((r) => r.id);
}

describe("Room SQLite schema", () => {
  test("uses an append-only migration table instead of unsupported PRAGMA state", () => {
    const sql = ROOM_DDL.join("\n");
    expect(sql).not.toContain("PRAGMA user_version");
    expect(sql).toContain("CREATE TABLE IF NOT EXISTS _sql_schema_migrations");
    expect(ROOM_DDL.at(-1)).toContain("INSERT OR IGNORE INTO _sql_schema_migrations");
  });

  test("migration id=2 creates gate_attempts and its index", () => {
    const db = new Database(":memory:");
    applyDdl(db, ROOM_DDL);

    expect(tableExists(db, "gate_attempts")).toBe(true);
    expect(migrationIds(db)).toEqual([1, 2]);

    const cols = db.query<{ name: string; notnull: number }, []>("PRAGMA table_info(gate_attempts)").all();
    expect(cols.map((c) => c.name)).toEqual(["id", "at", "ok"]);

    const idx = db.query("SELECT name FROM sqlite_master WHERE type='index' AND name='idx_gate_attempts_at'").all();
    expect(idx.length).toBe(1);
    db.close();
  });

  test("gate_attempts stores no passphrase, hash, IP or other identifier", () => {
    const db = new Database(":memory:");
    applyDdl(db, ROOM_DDL);
    const cols = db
      .query<{ name: string }, []>("PRAGMA table_info(gate_attempts)")
      .all()
      .map((c) => c.name);
    // The relay must stay blind: only a timestamp and a boolean outcome.
    for (const forbidden of ["ip", "hash", "pass", "token", "device", "ref", "id_hash"]) {
      expect(cols.filter((c) => c.includes(forbidden))).toEqual([]);
    }
    expect(cols).toEqual(["id", "at", "ok"]);
    db.close();
  });

  test("full DDL is idempotent across repeated cold starts", () => {
    const db = new Database(":memory:");
    applyDdl(db, ROOM_DDL);
    db.exec("INSERT INTO gate_attempts (at, ok) VALUES (10, 0)");

    // ensureSchema() replays every statement on each cold start.
    applyDdl(db, ROOM_DDL);
    applyDdl(db, ROOM_DDL);

    expect(migrationIds(db)).toEqual([1, 2]);
    expect(db.query("SELECT at, ok FROM gate_attempts").all()).toEqual([{ at: 10, ok: 0 }]);
    db.close();
  });

  test("an existing DO at id=1 upgrades incrementally without losing data", () => {
    const db = new Database(":memory:");
    applyDdl(db, legacyDdl());
    expect(tableExists(db, "gate_attempts")).toBe(false);
    expect(migrationIds(db)).toEqual([1]);

    // Populate the pre-existing room state a live DO would hold.
    db.exec("INSERT INTO meta (daemon_id, reconnect_hash, grant_id, created_at) VALUES ('d_1', 'h1', 'g_1', 7)");
    db.exec("INSERT INTO pair_slot (pair_ref, pair_loc, deadline) VALUES ('r1', 'loc1', 99)");
    db.exec("INSERT INTO binds (route_id, kind, created_at, pair_ref) VALUES ('rt1', 'established', 5, 'r1')");

    applyDdl(db, ROOM_DDL);

    expect(tableExists(db, "gate_attempts")).toBe(true);
    expect(migrationIds(db)).toEqual([1, 2]);
    expect(db.query("SELECT daemon_id, reconnect_hash, grant_id, created_at FROM meta").all()).toEqual([
      { daemon_id: "d_1", reconnect_hash: "h1", grant_id: "g_1", created_at: 7 },
    ]);
    expect(db.query("SELECT pair_ref, pair_loc, deadline FROM pair_slot").all()).toEqual([
      { pair_ref: "r1", pair_loc: "loc1", deadline: 99 },
    ]);
    expect(db.query("SELECT route_id, kind, created_at, pair_ref FROM binds").all()).toEqual([
      { route_id: "rt1", kind: "established", created_at: 5, pair_ref: "r1" },
    ]);
    db.close();
  });

  test("applied_at of migration 1 is not rewritten by a later upgrade", () => {
    const db = new Database(":memory:");
    applyDdl(db, legacyDdl());
    db.exec("UPDATE _sql_schema_migrations SET applied_at = 12345 WHERE id = 1");

    applyDdl(db, ROOM_DDL);

    const rows = db.query<{ id: number; applied_at: number }, []>(
      "SELECT id, applied_at FROM _sql_schema_migrations ORDER BY id",
    ).all();
    expect(rows).toEqual([{ id: 1, applied_at: 12345 }, { id: 2, applied_at: 0 }]);
    db.close();
  });
});
