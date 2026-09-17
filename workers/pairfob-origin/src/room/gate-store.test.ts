import { Database } from "bun:sqlite";
import { describe, expect, test } from "bun:test";
import { CfStore } from "./cf-store.ts";
import { MemoryStore } from "./memory-store.ts";
import { GATE_COOLDOWN_BASE_MS, GATE_FREE_ATTEMPTS, GateThrottle, asGateStore } from "./gate-throttle.ts";
import type { RoomStore } from "./types.ts";

// The throttle's backoff is driven by whatever the store reports, so CfStore
// and MemoryStore must agree exactly. A divergence would only surface in
// production, where CfStore is the one that runs.

/** Minimal DurableObjectStorage shim so CfStore's real SQL hits real SQLite. */
function sqliteStore(): { store: CfStore; db: Database } {
  const db = new Database(":memory:");
  const storage = {
    sql: {
      exec(query: string, ...binds: unknown[]) {
        const rows = db.query(query).all(...(binds as never[]));
        return { toArray: () => rows, rowsWritten: 0 };
      },
    },
  };
  return { store: new CfStore(storage as unknown as DurableObjectStorage), db };
}

function implementations(): Array<{ name: string; store: RoomStore }> {
  return [
    { name: "MemoryStore", store: new MemoryStore() },
    { name: "CfStore", store: sqliteStore().store as unknown as RoomStore },
  ];
}

describe("gate ledger conformance", () => {
  for (const { name, store } of implementations()) {
    describe(name, () => {
      test("satisfies the throttle's storage port", () => {
        expect(asGateStore(store)).not.toBeNull();
      });

      test("reports lastAt 0 when no failures are recorded", () => {
        // SQL MAX() yields NULL on an empty set; both sides must normalise to 0
        // or the backoff arithmetic diverges.
        expect(store.gateFailuresSince(0)).toEqual({ count: 0, lastAt: 0 });
      });

      test("counts only failures inside the window", () => {
        store.recordGateAttempt(100, false);
        store.recordGateAttempt(200, true);
        store.recordGateAttempt(300, false);

        expect(store.gateFailuresSince(0)).toEqual({ count: 2, lastAt: 300 });
        expect(store.gateFailuresSince(250)).toEqual({ count: 1, lastAt: 300 });
        // A successful attempt is never counted as a failure.
        expect(store.gateFailuresSince(150)).toEqual({ count: 1, lastAt: 300 });
        expect(store.gateFailuresSince(400)).toEqual({ count: 0, lastAt: 0 });
      });

      test("prunes strictly older than the cutoff", () => {
        store.pruneGateAttempts(300);
        expect(store.gateFailuresSince(0)).toEqual({ count: 1, lastAt: 300 });
      });

      test("drives the throttle identically", () => {
        const fresh = name === "MemoryStore"
          ? (new MemoryStore() as unknown as RoomStore)
          : (sqliteStore().store as unknown as RoomStore);
        const port = asGateStore(fresh);
        expect(port).not.toBeNull();
        const t = new GateThrottle(port!);

        for (let i = 0; i < GATE_FREE_ATTEMPTS; i++) {
          expect(t.check(1000).allowed).toBe(true);
          t.record(1000, false);
        }
        expect(t.check(1000).allowed).toBe(true);

        t.record(1000, false);
        expect(t.check(1000)).toEqual({ allowed: false, retryAfterMs: GATE_COOLDOWN_BASE_MS });
        expect(t.check(1000 + GATE_COOLDOWN_BASE_MS).allowed).toBe(true);
      });
    });
  }

  test("CfStore persists attempts as timestamp and outcome only", () => {
    const { store, db } = sqliteStore();
    store.recordGateAttempt(1000, false);
    store.recordGateAttempt(2000, true);

    const cols = db
      .query<{ name: string }, []>("PRAGMA table_info(gate_attempts)")
      .all()
      .map((c) => c.name);
    expect(cols).toEqual(["id", "at", "ok"]);
    expect(db.query("SELECT at, ok FROM gate_attempts ORDER BY at").all()).toEqual([
      { at: 1000, ok: 0 },
      { at: 2000, ok: 1 },
    ]);
    db.close();
  });
});
