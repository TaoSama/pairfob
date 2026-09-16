/**
 * Reconnect behaviour of the snapshot cache, at the observation level.
 *
 * The blank screen after a reconnect is what this exists to cure, so the cases
 * are about the seam: what the cached picture is allowed to overwrite, what the
 * live answer persists, how a replayed history window that overlaps the cached
 * tail is folded, and what a computer switch mid-read must not be able to do.
 */
import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import "../../../test-support/boot-dom";
import type { LiveSession } from "../../lib/protocol/session-types";
import type { PairResult } from "../../lib/protocol/client";
import { attachLiveSession, liveSession, setCredential } from "../computers/catalog-store";
import { setScreen } from "../../app/navigation-store";
import { noteRelayRtt, setSessionTransport } from "./connection-store";
import { applySnapshot, dashboardStore, resetDashboard } from "../dashboard/catalog-store";
import { batch } from "../../shared/model/domain-store";
import {
  applyPaneRead,
  livePaneText,
  resetObservationLifecycle,
  selectPane,
} from "../session/session-store";
import type { SessionSnapshotRecord } from "./snapshot-cache";
import {
  refreshSnapshot,
  restoreCachedSnapshot,
  type SnapshotCachePorts,
  type SnapshotPorts,
} from "./snapshot";

const pair: PairResult = { daemonId: "A", deviceId: "dev", fp: "f" } as unknown as PairResult;

const wire = (...paneIds: string[]) => ({
  panes: paneIds.map((id) => ({ pane_id: id, workspace_id: "w", tab_id: "t", agent: "codex", agent_status: "idle" })),
});

let calls: string[] = [];
let session: LiveSession;
let stored: Map<string, SessionSnapshotRecord>;
let daemon: string;
let clock: number;

const snapshotPorts: SnapshotPorts = {
  currentLive: liveSession,
  networkOnline: () => true,
  documentVisible: () => true,
  isDesk: () => false,
  openPendingNotification: async () => false,
  openPane: async () => undefined,
  abandonOpenPane: () => calls.push("abandon"),
  syncFullTerminalChrome: () => calls.push("full"),
  patchAgentChat: () => true,
  patchChromeTitle: () => calls.push("chrome"),
  showError: () => calls.push("error"),
  messageOf: String,
  commitView: () => calls.push("commitView"),
  now: () => 12345,
};

/** The real domain writers, with storage replaced by a Map the test inspects. */
function cachePorts(overrides: Partial<SnapshotCachePorts> = {}): SnapshotCachePorts {
  return {
    daemonId: () => daemon,
    load: async (id) => stored.get(id) ?? null,
    save: async (record) => {
      calls.push(`save:${record.daemonId}`);
      const previous = stored.get(record.daemonId);
      if (previous && previous.seq > record.seq) return;
      stored.set(record.daemonId, record);
    },
    applyWire: (value) => {
      calls.push("applyWire");
      applySnapshot(value);
    },
    applyPaneText: (text, hash) => {
      calls.push("applyPaneText");
      applyPaneRead(text, hash);
    },
    paneText: livePaneText,
    paneHash: () => "h",
    now: () => (clock += 1),
    ...overrides,
  };
}

function cached(daemonId: string, record: Partial<SessionSnapshotRecord> = {}): SessionSnapshotRecord {
  return {
    daemonId,
    seq: 1,
    savedAt: 10,
    wire: wire("cached-pane"),
    panes: [],
    ...record,
  };
}

beforeEach(() => {
  calls = [];
  stored = new Map();
  daemon = "A";
  clock = 1000;
  resetDashboard();
  resetObservationLifecycle();
  selectPane("");
  applyPaneRead("", "");
  setScreen("home");
  session = {
    isConnected: () => true,
    snapshot: async () => wire("live-pane"),
    onEvent: () => () => undefined,
    close() {},
  } as unknown as LiveSession;
  batch(() => {
    setCredential(pair);
    noteRelayRtt(null);
    setSessionTransport("relay");
  });
  attachLiveSession(session);
});

afterEach(() => {
  attachLiveSession(null);
  resetDashboard();
  resetObservationLifecycle();
  selectPane("");
  applyPaneRead("", "");
});

describe("restoring the cached screen on reconnect", () => {
  test("an empty herd is painted from the device before any RPC lands", async () => {
    stored.set("A", cached("A"));
    expect(dashboardStore.get().agents).toHaveLength(0);
    await restoreCachedSnapshot(cachePorts());
    expect(dashboardStore.get().agents.map((agent) => agent.paneId)).toEqual(["cached-pane"]);
  });

  test("a herd the live answer already filled is never dragged back to the cached one", async () => {
    applySnapshot(wire("live-pane"));
    stored.set("A", cached("A"));
    await restoreCachedSnapshot(cachePorts());
    expect(dashboardStore.get().agents.map((agent) => agent.paneId)).toEqual(["live-pane"]);
    expect(calls).not.toContain("applyWire");
  });

  test("the open pane's cached text is restored only when the screen is blank", async () => {
    selectPane("p1");
    stored.set("A", cached("A", {
      panes: [{ paneId: "p1", text: "cached output", hash: "h1", updatedAt: 5 }],
    }));
    await restoreCachedSnapshot(cachePorts());
    expect(livePaneText()).toBe("cached output");

    applyPaneRead("live output", "h2");
    calls = [];
    await restoreCachedSnapshot(cachePorts());
    expect(livePaneText()).toBe("live output");
    expect(calls).not.toContain("applyPaneText");
  });

  test("nothing cached for this computer paints nothing", async () => {
    expect(await restoreCachedSnapshot(cachePorts())).toBeNull();
    expect(dashboardStore.get().agents).toHaveLength(0);
    daemon = "";
    expect(await restoreCachedSnapshot(cachePorts())).toBeNull();
  });

  test("a computer switch during the storage read cannot paint the wrong screen", async () => {
    stored.set("A", cached("A"));
    const ports = cachePorts({
      load: async (id) => {
        const record = stored.get(id) ?? null;
        // The reader switched computers while the row was being read.
        daemon = "B";
        return record;
      },
    });
    expect(await restoreCachedSnapshot(ports)).toBeNull();
    expect(dashboardStore.get().agents).toHaveLength(0);
  });

  test("a cache that cannot be read is a blank screen, not a rejection", async () => {
    // The caller fires this without awaiting, so a rejection here would be an
    // unhandled failure of a reconnect that otherwise succeeded.
    const ports = cachePorts({
      load: async () => {
        throw new Error("storage unavailable");
      },
    });
    expect(await restoreCachedSnapshot(ports)).toBeNull();
    expect(dashboardStore.get().agents).toHaveLength(0);
  });
});

describe("persisting the painted screen", () => {
  test("a live snapshot is written to the device for the next reconnect", async () => {
    await refreshSnapshot(snapshotPorts, cachePorts());
    await Promise.resolve();
    const record = stored.get("A")!;
    expect(record.wire.panes?.map((p) => p.pane_id)).toEqual(["live-pane"]);
    expect(record.seq).toBe(1);
  });

  test("the open pane's text rides along with the herd", async () => {
    selectPane("p1");
    applyPaneRead("terminal text", "h");
    await refreshSnapshot(snapshotPorts, cachePorts());
    await Promise.resolve();
    const record = stored.get("A")!;
    expect(record.panes.map((p) => p.paneId)).toEqual(["p1"]);
    expect(record.panes[0]!.text).toBe("terminal text");
  });

  test("a save keeps the panes the herd snapshot says nothing about", async () => {
    // A Snapshot carries the herd, not each pane's terminal text; dropping the
    // cached text on every Snapshot would blank the pane the reader reopens.
    stored.set("A", cached("A", {
      panes: [{ paneId: "other", text: "kept", hash: "h", updatedAt: 5 }],
    }));
    await refreshSnapshot(snapshotPorts, cachePorts());
    await Promise.resolve();
    expect(stored.get("A")!.panes.map((p) => p.paneId)).toEqual(["other"]);
  });

  test("a storage failure never surfaces as a snapshot error", async () => {
    const ports = cachePorts({
      save: async () => {
        throw new Error("quota exceeded");
      },
    });
    await refreshSnapshot(snapshotPorts, ports);
    await Promise.resolve();
    expect(calls).not.toContain("error");
    expect(dashboardStore.get().agents.map((agent) => agent.paneId)).toEqual(["live-pane"]);
  });
});
