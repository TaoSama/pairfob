/**
 * Session snapshot cache model: the pure part.
 *
 * A reconnect retires every live domain before the replacement session can
 * answer a Snapshot RPC, so the herd list and the open pane are empty for a
 * whole round trip — the blank screen the reader sees after the phone wakes up.
 * The cure is to keep the last painted picture on the device and repaint it
 * immediately, then let the live answer supersede it.
 *
 * This module owns the data: what a cached record may contain, how a record
 * that came back off storage is validated, and how it is kept inside its
 * bounds. It performs no IO and touches no domain; the IndexedDB side is
 * `snapshot-storage.ts` and the observation side is `snapshot.ts`.
 *
 * What is deliberately absent is any alignment against live terminal output.
 * A cached record is a placeholder to look at, never a base to diff against:
 * the daemon destroys the terminal on disconnect and `TerminalOpen` mints a
 * fresh `terminal_id` whose frame sequence restarts at 1
 * (internal/daemon/rpc_terminal.go:78,403, internal/runtime/fake_terminal.go:44),
 * so a sequence number kept across a reconnect describes a different stream.
 * Comparing them would discard the whole-screen first frame and produce the
 * very blank screen this cache exists to prevent. The first `full:true` frame
 * replaces the placeholder outright.
 *
 * That first frame being whole-screen is the one daemon behaviour this cache
 * leans on, and it is asserted on both terminal implementations
 * (internal/runtime/fake_test.go:44, internal/runtime/herdr_terminal_test.go:63),
 * so it cannot be dropped quietly — changing it means editing those assertions.
 */
import type { SnapshotWire } from "../../lib/dashboard";

/** Rows kept in the store: one per paired computer, oldest evicted first. */
export const SNAPSHOT_CACHE_MAX_DAEMONS = 8;
/** Panes whose terminal text is cached inside one record. */
export const SNAPSHOT_CACHE_MAX_PANES = 12;
/** Terminal characters kept for one pane; the newest tail survives a trim. */
export const SNAPSHOT_CACHE_MAX_PANE_TEXT_CHARS = 64 * 1024;
/** Total characters one record may occupy before panes are evicted. */
export const SNAPSHOT_CACHE_MAX_RECORD_CHARS = 512 * 1024;
/** Panes carried in the cached dashboard wire; a larger herd is truncated. */
export const SNAPSHOT_CACHE_MAX_WIRE_PANES = 200;

/**
 * A pane's last painted terminal text.
 *
 * Deliberately carries no sequence or generation marker. The text is shown
 * while the live terminal reopens and is replaced wholesale by its first
 * whole-screen frame, so there is nothing to align and no watermark that could
 * survive into a stream where it means something else.
 */
export type PaneSnapshot = {
  paneId: string;
  text: string;
  hash: string;
  updatedAt: number;
};

/**
 * What one computer's last painted screen looked like.
 *
 * `seq` versions the record itself: two saves racing (a queued snapshot
 * finishing after the one that superseded it) resolve by ordinal, never by
 * arrival, so a stale write cannot bury a newer picture.
 */
export type SessionSnapshotRecord = {
  daemonId: string;
  seq: number;
  savedAt: number;
  wire: SnapshotWire;
  panes: PaneSnapshot[];
};

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function safeText(value: unknown): string {
  return typeof value === "string" ? value : "";
}

function safeOrdinal(value: unknown): number {
  return typeof value === "number" && Number.isSafeInteger(value) && value >= 0 ? value : 0;
}

/** Keep the newest characters: a truncated head reads as scrollback already gone. */
function tail(text: string, limit: number): string {
  return text.length <= limit ? text : text.slice(text.length - limit);
}

/**
 * Structural sanitize of a cached dashboard wire.
 *
 * The record is same-origin data this module wrote, but a partial write, a
 * storage-level corruption or an older build's shape must not reach
 * `applySnapshot`, which projects the layout as well as the cards. Only the
 * known keys survive, arrays stay arrays, and a pane without an identity is
 * dropped rather than folded as a nameless card.
 */
export function sanitizeSnapshotWire(value: unknown): SnapshotWire | null {
  if (!isPlainObject(value)) return null;
  const wire: SnapshotWire = {};
  if (isPlainObject(value.focused)) {
    const focused: NonNullable<SnapshotWire["focused"]> = {};
    if (typeof value.focused.pane_id === "string") focused.pane_id = value.focused.pane_id;
    if (typeof value.focused.tab_id === "string") focused.tab_id = value.focused.tab_id;
    if (typeof value.focused.workspace_id === "string") focused.workspace_id = value.focused.workspace_id;
    wire.focused = focused;
  }
  if (value.layouts !== undefined) wire.layouts = value.layouts;
  if (Array.isArray(value.workspaces)) {
    wire.workspaces = value.workspaces
      .filter((item): item is Record<string, unknown> => isPlainObject(item) && typeof item.workspace_id === "string")
      .map((item) => item as unknown as NonNullable<SnapshotWire["workspaces"]>[number]);
  }
  if (Array.isArray(value.tabs)) {
    wire.tabs = value.tabs
      .filter((item): item is Record<string, unknown> =>
        isPlainObject(item) && typeof item.tab_id === "string" && typeof item.workspace_id === "string")
      .map((item) => item as unknown as NonNullable<SnapshotWire["tabs"]>[number]);
  }
  if (Array.isArray(value.panes)) {
    wire.panes = value.panes
      .filter((item): item is Record<string, unknown> =>
        isPlainObject(item) && typeof item.pane_id === "string" && item.pane_id !== ""
        && typeof item.workspace_id === "string")
      .slice(0, SNAPSHOT_CACHE_MAX_WIRE_PANES)
      .map((item) => item as unknown as NonNullable<SnapshotWire["panes"]>[number]);
  }
  return wire;
}

function sanitizePane(value: unknown): PaneSnapshot | null {
  if (!isPlainObject(value)) return null;
  if (typeof value.paneId !== "string" || value.paneId === "") return null;
  return {
    paneId: value.paneId,
    text: tail(safeText(value.text), SNAPSHOT_CACHE_MAX_PANE_TEXT_CHARS),
    hash: safeText(value.hash),
    updatedAt: safeOrdinal(value.updatedAt),
  };
}

/** Characters a record occupies, counting only what a trim can actually shed. */
export function snapshotRecordChars(record: SessionSnapshotRecord): number {
  let chars = 0;
  for (const pane of record.panes) chars += pane.text.length;
  try {
    chars += JSON.stringify(record.wire).length;
  } catch {
    // A wire carrying a cycle cannot be stored at all; report it as oversized
    // so the trim path sheds panes and the write is rejected on serialize.
    chars += SNAPSHOT_CACHE_MAX_RECORD_CHARS;
  }
  return chars;
}

/**
 * Bring a record inside every declared bound.
 *
 * Panes are evicted oldest-first, because the pane the reader last looked at
 * is the one whose blank screen they would notice. The per-pane cap is applied
 * before the record cap so one runaway pane cannot evict eleven healthy ones.
 */
export function trimSessionSnapshot(record: SessionSnapshotRecord): SessionSnapshotRecord {
  const panes = record.panes
    .map((pane) => ({ ...pane, text: tail(pane.text, SNAPSHOT_CACHE_MAX_PANE_TEXT_CHARS) }))
    .sort((left, right) => right.updatedAt - left.updatedAt)
    .slice(0, SNAPSHOT_CACHE_MAX_PANES);
  const trimmed: SessionSnapshotRecord = { ...record, panes };
  while (trimmed.panes.length > 0 && snapshotRecordChars(trimmed) > SNAPSHOT_CACHE_MAX_RECORD_CHARS) {
    trimmed.panes = trimmed.panes.slice(0, -1);
  }
  return trimmed;
}

/**
 * Validate a value read back from storage.
 *
 * Returns null rather than throwing: a corrupt row is a cache miss, and a
 * reconnect must never fail because of one. Everything that survives is also
 * trimmed, so a record written by a build with looser bounds cannot be
 * rehydrated past this build's limits.
 */
export function parseSessionSnapshot(value: unknown): SessionSnapshotRecord | null {
  if (!isPlainObject(value)) return null;
  if (typeof value.daemonId !== "string" || value.daemonId === "") return null;
  const wire = sanitizeSnapshotWire(value.wire);
  if (!wire) return null;
  const panes = Array.isArray(value.panes)
    ? value.panes.map(sanitizePane).filter((pane): pane is PaneSnapshot => pane !== null)
    : [];
  return trimSessionSnapshot({
    daemonId: value.daemonId,
    seq: safeOrdinal(value.seq),
    savedAt: safeOrdinal(value.savedAt),
    wire,
    panes,
  });
}

/** The cached pane, or null when this record never held one. */
export function paneSnapshot(record: SessionSnapshotRecord | null, paneId: string): PaneSnapshot | null {
  if (!record || !paneId) return null;
  return record.panes.find((pane) => pane.paneId === paneId) ?? null;
}

/** Replace (or add) one pane inside a record, keeping the record trimmed. */
export function withPaneSnapshot(record: SessionSnapshotRecord, pane: PaneSnapshot): SessionSnapshotRecord {
  const panes = record.panes.filter((item) => item.paneId !== pane.paneId);
  panes.push({ ...pane, text: tail(pane.text, SNAPSHOT_CACHE_MAX_PANE_TEXT_CHARS) });
  return trimSessionSnapshot({ ...record, panes });
}
