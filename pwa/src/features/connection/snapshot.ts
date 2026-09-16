/**
 * Snapshot observation: one in-flight Snapshot, one queued follow-up.
 *
 * Applies the daemon snapshot through the dashboard and preferences owners
 * (`applySnapshot`, `applyHerdTouches`). Chrome patches and `#app` classes stay
 * ports until core's declarative shell owns them.
 */
import { boardStore } from "../board/layout-store";
import { applySnapshot, dashboardStore, setRefreshBusy } from "../dashboard/catalog-store";
import { currentScreen, setScreen } from "../../app/navigation-store";
import { applyHerdTouches } from "../settings/preferences-store";
import {
  applyPaneRead,
  isAgentChat,
  isFullTerminal,
  noteSnapshotAt,
  openPaneId,
  queueSnapshot,
  selectPane,
  takeQueuedSnapshot,
} from "../session/session-store";
import { t } from "../../lib/i18n";
import { choosePane, type SnapshotWire } from "../../lib/dashboard";
import { ProtocolError, type LiveSession } from "../../lib/protocol/client";
import { liveView, liveViewIsCurrent } from "./generations";
import { currentDaemonId } from "../computers/catalog-store";
import { livePaneHash, livePaneText } from "../session/session-store";
import {
  paneSnapshot,
  withPaneSnapshot,
  type SessionSnapshotRecord,
} from "./snapshot-cache";
import { loadSessionSnapshot, saveSessionSnapshot } from "./snapshot-storage";

export type SnapshotPorts = {
  currentLive(): LiveSession | null;
  networkOnline(): boolean;
  documentVisible(): boolean;
  isDesk(): boolean;
  openPendingNotification(open: (paneId: string) => Promise<void>): Promise<boolean>;
  openPane(paneId: string): Promise<void>;
  abandonOpenPane(message: string): void;
  syncFullTerminalChrome(): void;
  patchAgentChat(): boolean;
  patchChromeTitle(): void;
  showError(text: string, persist?: boolean): void;
  messageOf(error: unknown): string;
  commitView(): void;
  now(): number;
};

/**
 * Cache side of the observation, kept out of `SnapshotPorts` so the ports a
 * caller must supply stay the live-session surface. The defaults are the real
 * IndexedDB store and the real domain writers; a test substitutes them without
 * standing up storage.
 */
export type SnapshotCachePorts = {
  daemonId(): string;
  load(daemonId: string): Promise<SessionSnapshotRecord | null>;
  save(record: SessionSnapshotRecord): Promise<void>;
  applyWire(wire: SnapshotWire): void;
  applyPaneText(text: string, hash: string): void;
  paneText(): string;
  paneHash(): string;
  now(): number;
};

export const defaultSnapshotCachePorts: SnapshotCachePorts = {
  daemonId: () => currentDaemonId() ?? "",
  load: loadSessionSnapshot,
  save: saveSessionSnapshot,
  applyWire: (wire) => {
    applySnapshot(wire);
  },
  applyPaneText: applyPaneRead,
  paneText: livePaneText,
  paneHash: livePaneHash,
  now: Date.now,
};

/**
 * The record a save starts from, so a save only ever adds to the picture.
 *
 * Reading the stored row first keeps panes the live answer says nothing about:
 * a Snapshot carries the herd, not each pane's terminal text, and dropping the
 * cached text on every Snapshot would blank the pane the reader reopens.
 */
async function baseRecord(daemonId: string, ports: SnapshotCachePorts): Promise<SessionSnapshotRecord> {
  const stored = await ports.load(daemonId);
  if (stored) return stored;
  return { daemonId, seq: 0, savedAt: 0, wire: {}, panes: [] };
}

/**
 * Repaint the last picture this computer showed, before the live session can
 * answer anything.
 *
 * Only ever paints onto an empty screen. A reconnect that found the herd
 * already populated (a session that never fully retired, or a live Snapshot
 * that won the race) must not be dragged backwards to a stale one; this is a
 * cure for the blank screen, not a source of truth. The restored pane text is
 * likewise a placeholder: the reopened terminal's first whole-screen frame
 * replaces it outright, and nothing here is ever diffed against live output.
 *
 * A failed restore resolves null rather than rejecting: the caller fires it
 * without awaiting, and a cache that cannot be read is exactly the blank screen
 * the reader would have had anyway.
 */
export async function restoreCachedSnapshot(
  ports: SnapshotCachePorts = defaultSnapshotCachePorts,
): Promise<SessionSnapshotRecord | null> {
  try {
    const daemonId = ports.daemonId();
    if (!daemonId) return null;
    const record = await ports.load(daemonId);
    // Re-read the identity after the await: a computer switch during the storage
    // read would otherwise paint one computer's screen under another's session.
    if (!record || ports.daemonId() !== daemonId) return null;
    if (dashboardStore.get().agents.length === 0 && (record.wire.panes?.length ?? 0) > 0) {
      ports.applyWire(record.wire);
    }
    const pane = paneSnapshot(record, openPaneId());
    if (pane && pane.text && !ports.paneText()) ports.applyPaneText(pane.text, pane.hash);
    return record;
  } catch {
    return null;
  }
}

/**
 * Persist the painted screen: the herd wire, plus the open pane's terminal text
 * when one is showing.
 *
 * The pane identity and its text are captured synchronously, before the storage
 * read: the caller fires this alongside a continuation that can still change
 * the open pane, and a pane read after the await would file one pane's text
 * under another's name.
 *
 * The write is not awaited by the observation — a full device or a blocked
 * database slows nothing down and costs only the next reconnect's head start —
 * so it also cannot be allowed to reject: an unhandled rejection from a cache
 * would be reported as a failure of the paint that succeeded. Every failure
 * ends here.
 */
async function cacheSnapshot(
  wire: SnapshotWire,
  ports: SnapshotCachePorts,
): Promise<void> {
  try {
    const daemonId = ports.daemonId();
    if (!daemonId) return;
    const paneId = openPaneId();
    const text = ports.paneText();
    const hash = ports.paneHash();
    const record = await baseRecord(daemonId, ports);
    if (ports.daemonId() !== daemonId) return;
    let next: SessionSnapshotRecord = { ...record, wire };
    if (paneId && text) {
      next = withPaneSnapshot(next, { paneId, text, hash, updatedAt: ports.now() });
    }
    await ports.save({ ...next, seq: record.seq + 1, savedAt: ports.now() });
  } catch {
    /* the cached head start is optional; the painted screen is not affected */
  }
}

function viewIsCurrent(session: LiveSession, viewVersion: number, ports: SnapshotPorts): boolean {
  return liveViewIsCurrent(session, viewVersion, ports.currentLive());
}

function dropGonePane(): void {
  selectPane("");
  applyPaneRead("", "");
}

export async function refreshSnapshot(
  ports: SnapshotPorts,
  cache: SnapshotCachePorts = defaultSnapshotCachePorts,
): Promise<void> {
  const session = ports.currentLive();
  const viewVersion = liveView();
  if (!session || !session.isConnected() || !ports.networkOnline() || !ports.documentVisible()) return;
  if (dashboardStore.get().refreshBusy) {
    queueSnapshot();
    return;
  }
  setRefreshBusy(true);
  // The busy publication can reenter: a subscriber retiring the owner there
  // must prevent the old owner's RPC from firing at all.
  if (!viewIsCurrent(session, viewVersion, ports)) return;
  try {
    const snapshot = (await session.snapshot()) as SnapshotWire;
    if (!viewIsCurrent(session, viewVersion, ports)) return;
    noteSnapshotAt(ports.now());
    // The timestamp publication can reenter and install a replacement owner;
    // the old response must not apply onto it.
    if (!viewIsCurrent(session, viewVersion, ports)) return;
    const previousLayoutSig = boardStore.get().lastLayoutSig;
    const { previous, unchanged } = applySnapshot(snapshot);
    // applySnapshot publishes the dashboard: a subscriber retiring this owner
    // there (a newer computer/session/view) must not let the old status touch
    // persist under the replacement daemon's key. Revalidate before the second
    // owned domain write; checking only after both publications is too late.
    if (!viewIsCurrent(session, viewVersion, ports)) return;
    applyHerdTouches(previous, dashboardStore.get().agents);
    // The dashboard/preferences publications can reenter too.
    if (!viewIsCurrent(session, viewVersion, ports)) return;
    // The picture just painted is what the next reconnect
    // shows before its first RPC lands. Fire-and-forget: a slow or full device
    // must not hold up the paint that follows.
    void cacheSnapshot(snapshot, cache);
    const layoutUnchanged = previousLayoutSig === boardStore.get().lastLayoutSig;
    if (await ports.openPendingNotification(ports.openPane)) return;
    if (!viewIsCurrent(session, viewVersion, ports)) return;
    const screen = currentScreen();
    const agents = dashboardStore.get().agents;
    if (screen === "pane") {
      selectPane(choosePane(openPaneId(), agents));
      if (!viewIsCurrent(session, viewVersion, ports)) return;
      if (!openPaneId()) {
        ports.abandonOpenPane(t("err.paneGone"));
        return;
      }
      if (isFullTerminal()) ports.syncFullTerminalChrome();
      if (isAgentChat()) {
        if (!ports.patchAgentChat()) ports.commitView();
        return;
      }
      ports.patchChromeTitle();
      if (ports.isDesk()) ports.commitView();
      return;
    }
    if (screen === "workspace" && openPaneId() && !agents.some((agent) => agent.paneId === openPaneId())) {
      setScreen("home");
      dropGonePane();
      ports.showError(t("err.paneGone"), true);
      ports.commitView();
      return;
    }
    if (openPaneId() && !agents.some((agent) => agent.paneId === openPaneId())) dropGonePane();
    if (screen === "board") {
      if (unchanged && layoutUnchanged) return;
      ports.commitView();
      return;
    }
    if ((screen === "home" || screen === "workspace" || screen === "settings" || screen === "computers") && unchanged) return;
    ports.commitView();
  } catch (error) {
    if (!viewIsCurrent(session, viewVersion, ports)) return;
    if (!(error instanceof ProtocolError && ["reconnecting", "disconnected"].includes(error.code))) {
      ports.showError(ports.messageOf(error));
    }
    if (!viewIsCurrent(session, viewVersion, ports)) return;
    ports.commitView();
  } finally {
    if (viewIsCurrent(session, viewVersion, ports)) {
      setRefreshBusy(false);
      if (takeQueuedSnapshot()) void refreshSnapshot(ports);
    }
  }
}
