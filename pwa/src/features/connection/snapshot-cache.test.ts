/**
 * Snapshot cache model: bounds and corruption tolerance.
 *
 * The bounds are the point of the module: a cache that grows without a ceiling
 * fills the reader's phone, and a row that came back malformed must read as a
 * miss rather than take the reconnect down with it.
 */
import { describe, expect, test } from "bun:test";
import {
  parseSessionSnapshot,
  paneSnapshot,
  sanitizeSnapshotWire,
  snapshotRecordChars,
  trimSessionSnapshot,
  withPaneSnapshot,
  SNAPSHOT_CACHE_MAX_PANES,
  SNAPSHOT_CACHE_MAX_PANE_TEXT_CHARS,
  SNAPSHOT_CACHE_MAX_RECORD_CHARS,
  SNAPSHOT_CACHE_MAX_WIRE_PANES,
  type SessionSnapshotRecord,
} from "./snapshot-cache";

const wire = (paneId: string) => ({
  panes: [{ pane_id: paneId, workspace_id: "w", tab_id: "t", agent: "codex", agent_status: "idle" }],
});

function record(panes: SessionSnapshotRecord["panes"] = []): SessionSnapshotRecord {
  return { daemonId: "d1", seq: 1, savedAt: 100, wire: wire("p1"), panes };
}

function pane(paneId: string, text: string, updatedAt = 1) {
  return { paneId, text, hash: `h-${paneId}`, updatedAt };
}

describe("snapshot cache round trip", () => {
  test("a stored record survives parse with every field intact", () => {
    const original = record([pane("p1", "hello", 42)]);
    const parsed = parseSessionSnapshot(JSON.parse(JSON.stringify(original)));
    expect(parsed).toEqual(original);
  });

  test("withPaneSnapshot replaces a pane by id instead of appending a duplicate", () => {
    const first = withPaneSnapshot(record(), pane("p1", "one", 10));
    const second = withPaneSnapshot(first, pane("p1", "two", 11));
    expect(second.panes).toHaveLength(1);
    expect(paneSnapshot(second, "p1")?.text).toBe("two");
    expect(paneSnapshot(second, "absent")).toBeNull();
    expect(paneSnapshot(null, "p1")).toBeNull();
  });
});

describe("snapshot cache bounds", () => {
  test("a pane's text is capped to the newest characters, not the oldest", () => {
    const long = "A".repeat(SNAPSHOT_CACHE_MAX_PANE_TEXT_CHARS) + "TAIL";
    const trimmed = withPaneSnapshot(record(), pane("p1", long));
    const text = paneSnapshot(trimmed, "p1")!.text;
    expect(text).toHaveLength(SNAPSHOT_CACHE_MAX_PANE_TEXT_CHARS);
    // Scrollback that fell off the top reads as history already gone; a lost
    // tail would silently hide the newest output the reader came back for.
    expect(text.endsWith("TAIL")).toBe(true);
  });

  test("panes past the count bound are evicted oldest-first", () => {
    const panes = Array.from({ length: SNAPSHOT_CACHE_MAX_PANES + 4 }, (_, index) =>
      pane(`p${index}`, "x", index));
    const trimmed = trimSessionSnapshot(record(panes));
    expect(trimmed.panes).toHaveLength(SNAPSHOT_CACHE_MAX_PANES);
    const kept = trimmed.panes.map((item) => item.paneId);
    expect(kept).not.toContain("p0");
    expect(kept).toContain(`p${SNAPSHOT_CACHE_MAX_PANES + 3}`);
  });

  test("a record over the total character bound sheds panes until it fits", () => {
    const big = "B".repeat(SNAPSHOT_CACHE_MAX_PANE_TEXT_CHARS);
    const panes = Array.from({ length: SNAPSHOT_CACHE_MAX_PANES }, (_, index) =>
      pane(`p${index}`, big, index));
    const trimmed = trimSessionSnapshot(record(panes));
    expect(snapshotRecordChars(trimmed)).toBeLessThanOrEqual(SNAPSHOT_CACHE_MAX_RECORD_CHARS);
    expect(trimmed.panes.length).toBeLessThan(SNAPSHOT_CACHE_MAX_PANES);
    expect(trimmed.panes.length).toBeGreaterThan(0);
  });

  test("a herd larger than the wire bound is truncated rather than stored whole", () => {
    const panes = Array.from({ length: SNAPSHOT_CACHE_MAX_WIRE_PANES + 30 }, (_, index) =>
      ({ pane_id: `p${index}`, workspace_id: "w" }));
    expect(sanitizeSnapshotWire({ panes })!.panes).toHaveLength(SNAPSHOT_CACHE_MAX_WIRE_PANES);
  });
});

describe("snapshot cache corruption tolerance", () => {
  test("a value that is not a record is a miss, never a throw", () => {
    for (const value of [null, undefined, 0, "", "{}", [], true, { daemonId: "" }, { daemonId: 5 }]) {
      expect(parseSessionSnapshot(value)).toBeNull();
    }
  });

  test("a record whose wire is unusable is a miss", () => {
    expect(parseSessionSnapshot({ daemonId: "d1", wire: null, panes: [] })).toBeNull();
    expect(parseSessionSnapshot({ daemonId: "d1", wire: "panes", panes: [] })).toBeNull();
    expect(parseSessionSnapshot({ daemonId: "d1", wire: [], panes: [] })).toBeNull();
  });

  test("wrong-typed fields inside a usable record are replaced, not propagated", () => {
    const parsed = parseSessionSnapshot({
      daemonId: "d1",
      seq: "nope",
      savedAt: -4,
      wire: { panes: [{ pane_id: "p1", workspace_id: "w" }, { workspace_id: "w" }, null, 7] },
      panes: [
        { paneId: "p1", text: 42, hash: null, updatedAt: 1.5 },
        { paneId: "", text: "orphan" },
        "not a pane",
      ],
    })!;
    expect(parsed.seq).toBe(0);
    expect(parsed.savedAt).toBe(0);
    // A pane with no identity cannot be matched to anything; keeping it would
    // put a nameless card on the herd screen.
    expect(parsed.wire.panes).toHaveLength(1);
    expect(parsed.panes).toHaveLength(1);
    expect(parsed.panes[0]).toEqual({ paneId: "p1", text: "", hash: "", updatedAt: 0 });
  });

  test("a record written past this build's bounds is brought inside them on read", () => {
    const parsed = parseSessionSnapshot({
      daemonId: "d1",
      seq: 1,
      savedAt: 1,
      wire: wire("p1"),
      panes: Array.from({ length: SNAPSHOT_CACHE_MAX_PANES + 6 }, (_, index) => pane(`p${index}`, "x", index)),
    })!;
    expect(parsed.panes).toHaveLength(SNAPSHOT_CACHE_MAX_PANES);
  });

  test("unknown wire keys are dropped so a foreign shape cannot reach the projection", () => {
    const sanitized = sanitizeSnapshotWire({
      panes: [{ pane_id: "p1", workspace_id: "w" }],
      focused: { pane_id: "p1", tab_id: 9 },
      injected: { toString: "no" },
    })!;
    expect(Object.keys(sanitized).sort()).toEqual(["focused", "panes"]);
    expect(sanitized.focused).toEqual({ pane_id: "p1" });
  });
});
