/**
 * IndexedDB persistence for session snapshots.
 *
 * Follows the credential store's shape: open per operation, run one
 * transaction, close in a `finally`. A snapshot is a cache, so every read
 * resolves to null rather than rejecting — a reconnect must not fail because
 * storage is blocked, evicted, or holding a row this build cannot parse.
 *
 * Its own database, not the credential one. Adding a store to `pairfob` means
 * bumping that database's version, and two modules owning independent version
 * numbers of one database race on upgrade: whichever opens first decides the
 * schema and the other blocks. Cache and key material also have different
 * lifetimes — dropping the whole cache must never risk a credential row.
 */
import {
  parseSessionSnapshot,
  SNAPSHOT_CACHE_MAX_DAEMONS,
  trimSessionSnapshot,
  type SessionSnapshotRecord,
} from "./snapshot-cache";

const DB_NAME = "pairfob-session-cache";
const DB_VERSION = 1;
const STORE = "snapshots";

function storageAvailable(): boolean {
  return typeof indexedDB !== "undefined" && indexedDB !== null;
}

function openDatabase(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(DB_NAME, DB_VERSION);
    request.onupgradeneeded = () => {
      const db = request.result;
      if (!db.objectStoreNames.contains(STORE)) db.createObjectStore(STORE, { keyPath: "daemonId" });
    };
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error || new Error("snapshot cache open failed"));
    request.onblocked = () => reject(new Error("snapshot cache upgrade blocked"));
  });
}

function readAll(db: IDBDatabase): Promise<unknown[]> {
  return new Promise((resolve, reject) => {
    const request = db.transaction(STORE, "readonly").objectStore(STORE).getAll();
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error || new Error("snapshot cache read failed"));
  });
}

/**
 * The cached screen for one computer, or null.
 *
 * A row that fails validation is not merely skipped: it is deleted, so a shape
 * this build can never read stops occupying the device's quota forever.
 */
export async function loadSessionSnapshot(daemonId: string): Promise<SessionSnapshotRecord | null> {
  if (!daemonId || !storageAvailable()) return null;
  try {
    const db = await openDatabase();
    try {
      const value = await new Promise<unknown>((resolve, reject) => {
        const request = db.transaction(STORE, "readonly").objectStore(STORE).get(daemonId);
        request.onsuccess = () => resolve(request.result);
        request.onerror = () => reject(request.error || new Error("snapshot cache read failed"));
      });
      if (value === undefined) return null;
      const record = parseSessionSnapshot(value);
      if (!record || record.daemonId !== daemonId) {
        void deleteSessionSnapshot(daemonId).catch(() => undefined);
        return null;
      }
      return record;
    } finally {
      db.close();
    }
  } catch {
    return null;
  }
}

/**
 * Persist one computer's screen, evicting the oldest rows past the row bound.
 *
 * The record is trimmed and re-parsed before the write, so what lands on the
 * device is exactly what a later read will accept — a row can never be stored
 * in a shape its own reader would reject and delete.
 */
export async function saveSessionSnapshot(record: SessionSnapshotRecord): Promise<void> {
  if (!record.daemonId || !storageAvailable()) return;
  const trimmed = parseSessionSnapshot(trimSessionSnapshot(record));
  if (!trimmed) return;
  try {
    const db = await openDatabase();
    try {
      const existing = await readAll(db);
      // Oldest first, so the slice taken for eviction is the stale end.
      const stale = existing
        .map(parseSessionSnapshot)
        .filter((item): item is SessionSnapshotRecord => item !== null && item.daemonId !== trimmed.daemonId)
        .sort((left, right) => left.savedAt - right.savedAt);
      const evict = stale.slice(0, Math.max(0, stale.length + 1 - SNAPSHOT_CACHE_MAX_DAEMONS));
      await new Promise<void>((resolve, reject) => {
        const tx = db.transaction(STORE, "readwrite");
        const store = tx.objectStore(STORE);
        // Ordinal, not arrival: a queued snapshot finishing after the save that
        // superseded it must not bury the newer picture.
        const request = store.get(trimmed.daemonId);
        request.onsuccess = () => {
          const previous = parseSessionSnapshot(request.result);
          if (previous && previous.seq > trimmed.seq) {
            tx.abort();
            return;
          }
          for (const item of evict) store.delete(item.daemonId);
          store.put(trimmed);
        };
        request.onerror = () => reject(request.error || new Error("snapshot cache read failed"));
        tx.oncomplete = () => resolve();
        // A deliberate abort (a newer record already stored) is a success for
        // the caller: the device holds the picture it should.
        tx.onabort = () => resolve();
        tx.onerror = () => reject(tx.error || new Error("snapshot cache write failed"));
      });
    } finally {
      db.close();
    }
  } catch {
    // Quota, private mode, a blocked upgrade: the cache is an optimisation.
  }
}

/** Drop one computer's cached screen. Called when its credential is forgotten. */
export async function deleteSessionSnapshot(daemonId: string): Promise<void> {
  if (!daemonId || !storageAvailable()) return;
  const db = await openDatabase();
  try {
    await new Promise<void>((resolve, reject) => {
      const tx = db.transaction(STORE, "readwrite");
      tx.objectStore(STORE).delete(daemonId);
      tx.oncomplete = () => resolve();
      tx.onabort = () => reject(tx.error || new Error("snapshot cache delete aborted"));
      tx.onerror = () => reject(tx.error || new Error("snapshot cache delete failed"));
    });
  } finally {
    db.close();
  }
}

/**
 * Drop every cached screen.
 *
 * Cached terminal text is the same class of secret as what the terminal shows,
 * so signing out of every computer must leave none of it behind. The whole
 * database is deleted rather than its rows cleared: an emptied object store
 * can still hold the evicted pages of what it used to contain.
 */
export async function clearSessionSnapshots(): Promise<void> {
  if (!storageAvailable()) return;
  await new Promise<void>((resolve) => {
    const request = indexedDB.deleteDatabase(DB_NAME);
    request.onsuccess = () => resolve();
    request.onerror = () => resolve();
    request.onblocked = () => resolve();
  });
}
