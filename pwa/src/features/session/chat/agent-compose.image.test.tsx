import { happy, resetChatDOM } from "../../../../test-support/chat-dom";
import { beforeEach, afterEach, expect, test } from "bun:test";
import { act, createElement } from "react";
import { appRoot } from "../../../app/dom-root";
import { setLang } from "../../../lib/i18n";
import { NO_OPERATION_CAPABILITIES } from "../../../lib/operations";
import type { LiveSession } from "../../../lib/protocol/client";
import { resetComposeDrafts } from "../drafts/compose-drafts";
import { clearAgentTraceCache } from "../../../lib/agent-trace-cache";
import { setPhase } from "../../connection/connection-store";
import { setScreen } from "../../../app/navigation-store";
import { selectPane, setAgentChat, setFullTerminal } from "../session-store";
import { applyCapabilities, setOperationBusy } from "../../operations/capabilities-store";
import { applyTrace, setTraceBusy, setTraceLoadState, setTraceNote } from "./trace-store";
import { composeDraft, setComposeDraft, setComposeIME } from "../compose-store";
import { clearNotice } from "../../../app/notices-store";
import { replaceAgentsFromSnapshot } from "../../dashboard/catalog-store";
import { attachLiveSession } from "../../computers/catalog-store";
import { AgentChatPane } from "./agent-chat";
import { renderReact, unmountReact, unmountTestApp } from "../../../../test-support/react-harness";
import * as controller from "./agent-chat-controller";

const created: string[] = [];
const revoked: string[] = [];
const originalCreate = URL.createObjectURL;
const originalRevoke = URL.revokeObjectURL;

/** Deterministic object-URL stubs so the strip and cleanup are observable. */
function stubObjectURLs(): void {
  URL.createObjectURL = ((): string => {
    const url = `blob:img/${created.length}`;
    created.push(url);
    return url;
  }) as typeof URL.createObjectURL;
  URL.revokeObjectURL = ((url: string): void => { revoked.push(url); }) as typeof URL.revokeObjectURL;
}

function imageFile(name: string): File {
  return new File([new Uint8Array([1, 2, 3])], name, { type: "image/png" });
}

/** happy-dom's file input accepts an assigned FileList-like via defineProperty. */
function setFiles(picker: HTMLInputElement, files: File[]): void {
  Object.defineProperty(picker, "files", {
    configurable: true,
    value: { length: files.length, item: (i: number) => files[i] ?? null, ...files },
  });
}

function picker(): HTMLInputElement {
  return appRoot().querySelector<HTMLInputElement>(".dock-form input[type=file]")!;
}
function textarea(): HTMLTextAreaElement {
  return appRoot().querySelector<HTMLTextAreaElement>(".agent-dock textarea")!;
}
function thumbs(): NodeListOf<Element> {
  return appRoot().querySelectorAll(".agent-image-thumb");
}

function mount(): void {
  renderReact(createElement(AgentChatPane, {
    includeBack: true,
    handlers: { onBack() {}, onWorkspace() {}, onMenu() {}, onSwitch() {} },
  }));
}

beforeEach(async () => {
  created.length = 0;
  revoked.length = 0;
  stubObjectURLs();
  await resetChatDOM();
  setLang("zh");
  resetComposeDrafts();
  clearAgentTraceCache();
  setPhase("live");
  setScreen("pane");
  selectPane("p1");
  setFullTerminal(false);
  setAgentChat(true);
  setComposeDraft("");
  setComposeIME(false);
  setOperationBusy(false);
  clearNotice();
  setTraceLoadState("ready");
  setTraceBusy(false);
  setTraceNote("");
  applyTrace({
    agentTraceItems: [{ type: "user", text: "Review this" }, { type: "assistant", text: "Ready" }],
    agentTracePending: "",
    agentTracePendingBase: [],
  });
  applyCapabilities({ ...NO_OPERATION_CAPABILITIES, history: true, prompt_agent: true }, []);
  replaceAgentsFromSnapshot({
    focused: { workspace_id: "w1", tab_id: "w1:t1", pane_id: "p1" },
    workspaces: [{ workspace_id: "w1", label: "demo" }],
    tabs: [{ tab_id: "w1:t1", workspace_id: "w1", label: "main" }],
    panes: [
      { pane_id: "p1", workspace_id: "w1", tab_id: "w1:t1", cwd: "/tmp/demo", agent: "codex", agent_status: "idle", history_available: true },
    ],
  });
  attachLiveSession({ isConnected: () => true } as unknown as LiveSession);
});

afterEach(async () => await act(async () => {
  unmountReact();
  controller.leaveAgentChat({ paint: false });
  attachLiveSession(null);
  selectPane("");
  setScreen("home");
  setAgentChat(false);
  resetComposeDrafts();
  clearAgentTraceCache();
  unmountTestApp();
  appRoot().replaceChildren();
  URL.createObjectURL = originalCreate;
  URL.revokeObjectURL = originalRevoke;
}));

test("+ inserts an [Image #N] marker at the caret and shows a thumbnail", () => {
  act(() => mount());
  const field = textarea();
  field.value = "before after";
  field.dispatchEvent(new happy.window.Event("input", { bubbles: true }));
  field.setSelectionRange(6, 6); // between "before" and " after"
  act(() => { setFiles(picker(), [imageFile("cat.png")]); picker().dispatchEvent(new happy.window.Event("change", { bubbles: true })); });
  expect(composeDraft()).toBe("before[Image #1]  after");
  expect(thumbs().length).toBe(1);
  expect(created.length).toBe(1);
});

test("multiple images across positions get increasing numbers", () => {
  act(() => mount());
  const field = textarea();
  field.value = "start end";
  field.dispatchEvent(new happy.window.Event("input", { bubbles: true }));
  field.setSelectionRange(6, 6); // before "end"
  act(() => { setFiles(picker(), [imageFile("a.png"), imageFile("b.png")]); picker().dispatchEvent(new happy.window.Event("change", { bubbles: true })); });
  expect(composeDraft()).toBe("start [Image #1] [Image #2] end");
  expect(thumbs().length).toBe(2);
});

test("removing a thumbnail deletes its marker and revokes the URL", () => {
  act(() => mount());
  const field = textarea();
  field.setSelectionRange(0, 0);
  act(() => { setFiles(picker(), [imageFile("a.png"), imageFile("b.png")]); picker().dispatchEvent(new happy.window.Event("change", { bubbles: true })); });
  expect(composeDraft()).toBe("[Image #1] [Image #2] ");
  const removeFirst = appRoot().querySelector<HTMLButtonElement>(".agent-image-thumb .agent-image-remove")!;
  act(() => removeFirst.click());
  expect(composeDraft()).toBe("[Image #2] ");
  expect(thumbs().length).toBe(1);
  expect(revoked).toContain("blob:img/0");
});

test("emptying the draft clears the strip and revokes remaining URLs", () => {
  act(() => mount());
  textarea().setSelectionRange(0, 0);
  act(() => { setFiles(picker(), [imageFile("a.png")]); picker().dispatchEvent(new happy.window.Event("change", { bubbles: true })); });
  expect(thumbs().length).toBe(1);
  // A successful send empties the draft; the strip follows.
  act(() => setComposeDraft(""));
  expect(thumbs().length).toBe(0);
  expect(revoked).toContain("blob:img/0");
});
