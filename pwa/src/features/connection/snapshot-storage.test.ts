/**
 * IndexedDB snapshot persistence against a real in-memory IndexedDB.
 *
 * The bounds and validation are proven in `snapshot-cache.test.ts` on pure
 * values; what this file proves is that the storage layer round-trips through
 * an actual object store, evicts rows, refuses to go backwards, deletes what it
 * cannot read, and treats every failure as a cache miss rather than an error
 * that could fail a reconnect.
 */
import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import {
  SNAPSHOT_CACHE_MAX_DAEMONS,
  type SessionSnapshotRecord,
} from "./snapshot-cache";
import {
  clearSessionSnapshots,
  deleteSessionSnapshot,
  loadSessionSnapshot,
  saveSessionSnapshot,
} from "./snapshot-storage";

/**
 * A minimal IndexedDB over plain Maps. happy-dom ships none, and the real
 * contract this module depends on is narrow: keyPath stores, get/getAll/put/
 * delete, transaction completion and abort, and deleteDatabase. Callbacks fire
 * on the microtask queue and a transaction commits only once the requests it
 * issued have all finished, which is what makes the abort-before-complete
 * ordering in the stale-write test observable.
 */
function installIndexedDB() {
  const databases = new Map<string, Map<string, Map<string, unknown>>>();
  let failOpen = false;
  let abortDelete = false;

  const soon = (run: () => void) => queueMicrotask(run);

  function makeRequest<T>(produce: () => T, finished?: () => void) {
    const request: Record<string, unknown> = { result: undefined, error: null, onsuccess: null, onerror: null };
    soon(() => {
      try {
        request.result = produce();
        (request.onsuccess as (() => void) | null)?.();
      } catch (error) {
        request.error = error;
        (request.onerror as (() => void) | null)?.();
      }
      // Reported after the handler, so a request the handler itself issued is
      // already counted and cannot be missed by the commit check.
      finished?.();
    });
    return request;
  }

  function makeTransaction(stores: Map<string, Map<string, unknown>>, names: string[]) {
    let aborted = false;
    let settled = false;
    let outstanding = 0;
    const pending: Array<() => void> = [];
    const tx: Record<string, unknown> = { error: null, oncomplete: null, onerror: null, onabort: null };
    const complete = () => {
      if (aborted || settled) return;
      settled = true;
      for (const apply of pending) apply();
      (tx.oncomplete as (() => void) | null)?.();
    };
    // A transaction lives while any request it issued is unfinished and commits
    // once none are left, so a handler that chains another request — or calls
    // abort() — is always observed before completion. Counting the outstanding
    // requests reproduces that rule; settling after a fixed number of
    // microtasks would only coincide with it for the exact request chain the
    // storage module issues today, and would report a false failure the moment
    // that chain grew by one.
    const track = () => {
      outstanding += 1;
      return () => {
        outstanding -= 1;
        if (outstanding === 0) soon(() => { if (outstanding === 0) complete(); });
      };
    };
    tx.abort = () => {
      if (settled) return;
      aborted = true;
      settled = true;
      soon(() => (tx.onabort as (() => void) | null)?.());
    };
    tx.objectStore = (name: string) => {
      const store = stores.get(name);
      if (!store) throw new Error(`no store ${name}`);
      return {
        get: (key: string) => makeRequest(() => store.get(key), track()),
        getAll: () => makeRequest(() => [...store.values()], track()),
        put: (value: Record<string, unknown>) => {
          pending.push(() => store.set(String(value.daemonId), value));
          return makeRequest(() => undefined, track());
        },
        delete: (key: string) => {
          if (abortDelete) (tx.abort as () => void)();
          pending.push(() => store.delete(key));
          return makeRequest(() => undefined, track());
        },
      };
    };
    // A transaction the caller never issues a request on still commits.
    soon(() => { if (outstanding === 0) complete(); });
    void names;
    return tx;
  }

  const shim = {
    open(name: string, _version: number) {
      const request: Record<string, unknown> = {
        result: undefined, error: null, onsuccess: null, onerror: null, onupgradeneeded: null, onblocked: null,
      };
      soon(() => {
        if (failOpen) {
          request.error = new Error("open denied");
          (request.onerror as (() => void) | null)?.();
          return;
        }
        const fresh = !databases.has(name);
        const stores = databases.get(name) ?? new Map<string, Map<string, unknown>>();
        databases.set(name, stores);
        const db = {
          objectStoreNames: { contains: (store: string) => stores.has(store) },
          createObjectStore: (store: string) => {
            stores.set(store, new Map());
            return {};
          },
          transaction: (store: string | string[]) =>
            makeTransaction(stores, Array.isArray(store) ? store : [store]),
          close: () => undefined,
        };
        request.result = db;
        if (fresh) (request.onupgradeneeded as (() => void) | null)?.();
        (request.onsuccess as (() => void) | null)?.();
      });
      return request;
    },
    deleteDatabase(name: string) {
      const request: Record<string, unknown> = { onsuccess: null, onerror: null, onblocked: null };
      soon(() => {
        databases.delete(name);
        (request.onsuccess as (() => void) | null)?.();
      });
      return request;
    },
  };

  const globals = globalThis as Record<string, unknown>;
  const original = Object.getOwnPropertyDescriptor(globalThis, "indexedDB");
  globals.indexedDB = shim;
  return {
    databases,
    failOpen(value: boolean) {
      failOpen = value;
    },
    abortDelete(value: boolean) {
      abortDelete = value;
    },
    restore() {
      if (original) Object.defineProperty(globalThis, "indexedDB", original);
      else delete globals.indexedDB;
    },
  };
}

let idb: ReturnType<typeof installIndexedDB>;

function record(daemonId: string, seq: number, savedAt: number, text = "screen"): SessionSnapshotRecord {
  return {
    daemonId,
    seq,
    savedAt,
    wire: { panes: [{ pane_id: "p1", workspace_id: "w" }] },
    panes: [{ paneId: "p1", text, hash: "h", updatedAt: savedAt }],
  };
}

beforeEach(() => {
  idb = installIndexedDB();
});

afterEach(() => {
  idb.restore();
});

describe("snapshot storage round trip", () => {
  test("a saved record is read back whole", async () => {
    await saveSessionSnapshot(record("d1", 1, 10));
    expect(await loadSessionSnapshot("d1")).toEqual(record("d1", 1, 10));
  });

  test("a computer that was never cached is a miss, not an error", async () => {
    expect(await loadSessionSnapshot("unknown")).toBeNull();
    expect(await loadSessionSnapshot("")).toBeNull();
  });

  test("a later save supersedes the earlier picture", async () => {
    await saveSessionSnapshot(record("d1", 1, 10, "old"));
    await saveSessionSnapshot(record("d1", 2, 20, "new"));
    expect((await loadSessionSnapshot("d1"))!.panes[0]!.text).toBe("new");
  });

  test("a stale save landing late cannot bury the newer picture", async () => {
    // A queued snapshot finishing after the one that superseded it: ordinal
    // decides, not arrival, or the reader's reconnect shows the older screen.
    await saveSessionSnapshot(record("d1", 5, 50, "newer"));
    await saveSessionSnapshot(record("d1", 2, 20, "older"));
    const loaded = (await loadSessionSnapshot("d1"))!;
    expect(loaded.panes[0]!.text).toBe("newer");
    expect(loaded.seq).toBe(5);
  });
});

describe("snapshot storage bounds and cleanup", () => {
  test("rows past the computer bound are evicted oldest-first", async () => {
    for (let index = 0; index < SNAPSHOT_CACHE_MAX_DAEMONS + 3; index += 1) {
      await saveSessionSnapshot(record(`d${index}`, 1, index + 1));
    }
    const rows = idb.databases.get("pairfob-session-cache")!.get("snapshots")!;
    expect(rows.size).toBe(SNAPSHOT_CACHE_MAX_DAEMONS);
    expect(await loadSessionSnapshot("d0")).toBeNull();
    expect(await loadSessionSnapshot(`d${SNAPSHOT_CACHE_MAX_DAEMONS + 2}`)).not.toBeNull();
  });

  test("a corrupt row is deleted rather than left occupying the device's quota", async () => {
    await saveSessionSnapshot(record("d1", 1, 10));
    const rows = idb.databases.get("pairfob-session-cache")!.get("snapshots")!;
    rows.set("d1", { daemonId: "d1", wire: "not a wire" });
    expect(await loadSessionSnapshot("d1")).toBeNull();
    await Promise.resolve();
    await new Promise((resolve) => setTimeout(resolve, 5));
    expect(rows.has("d1")).toBe(false);
  });

  test("a row filed under the wrong key is refused", async () => {
    const rows = new Map<string, unknown>([["d1", record("other", 1, 10)]]);
    idb.databases.set("pairfob-session-cache", new Map([["snapshots", rows]]));
    expect(await loadSessionSnapshot("d1")).toBeNull();
  });

  test("forgetting one computer leaves the others cached", async () => {
    await saveSessionSnapshot(record("d1", 1, 10));
    await saveSessionSnapshot(record("d2", 1, 11));
    await deleteSessionSnapshot("d1");
    expect(await loadSessionSnapshot("d1")).toBeNull();
    expect(await loadSessionSnapshot("d2")).not.toBeNull();
  });

  test("an aborted privacy deletion rejects and preserves the row", async () => {
    await saveSessionSnapshot(record("d1", 1, 10));
    idb.abortDelete(true);
    await expect(deleteSessionSnapshot("d1")).rejects.toThrow("snapshot cache delete aborted");
    expect(await loadSessionSnapshot("d1")).not.toBeNull();
  });

  test("clearing drops the whole database, not just its rows", async () => {
    await saveSessionSnapshot(record("d1", 1, 10));
    await saveSessionSnapshot(record("d2", 1, 11));
    await clearSessionSnapshots();
    // Terminal output is as sensitive as what the terminal shows: an emptied
    // store can still hold the pages of what it used to contain.
    expect(idb.databases.has("pairfob-session-cache")).toBe(false);
    expect(await loadSessionSnapshot("d1")).toBeNull();
  });
});

describe("snapshot storage never fails a reconnect", () => {
  test("a database that refuses to open reads as a miss and writes silently", async () => {
    idb.failOpen(true);
    expect(await loadSessionSnapshot("d1")).toBeNull();
    await saveSessionSnapshot(record("d1", 1, 10));
    await expect(deleteSessionSnapshot("d1")).rejects.toThrow("open denied");
  });

  test("a platform with no IndexedDB at all is a miss, not a throw", async () => {
    idb.restore();
    delete (globalThis as Record<string, unknown>).indexedDB;
    expect(await loadSessionSnapshot("d1")).toBeNull();
    await saveSessionSnapshot(record("d1", 1, 10));
    await clearSessionSnapshots();
  });

  test("a record that cannot be validated is never written", async () => {
    await saveSessionSnapshot({ ...record("d1", 1, 10), daemonId: "" });
    expect(idb.databases.has("pairfob-session-cache")).toBe(false);
  });
});
