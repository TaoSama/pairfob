import { resetTestDOM } from "../../../test-support/boot-dom";
import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { createElement } from "react";
import { act } from "react";
import { createRoot, type Root } from "react-dom/client";
import { setLang, t } from "../../lib/i18n";
import {
  adoptAccountIdentity,
  clearAccountSession,
  setAccountBusy,
  setAccountSyncOutcome,
} from "../../features/account/account-store";
import { AccountSummary } from "./account-summary";

/**
 * The account card as the person actually sees it.
 *
 * The controller tests prove which outcome is published; these prove the card
 * paints it. That seam is where the original defect lived: every sync outcome
 * was published into a field no component read, so the screen was identical
 * whether the press had worked, failed, or done nothing at all.
 *
 * A private root rather than the mounted app: this is a component contract, and
 * the surrounding screen is the settings page's business.
 */

let root: Root | null = null;
let host: HTMLElement | null = null;

function render(): HTMLElement {
  host = document.createElement("div");
  document.body.append(host);
  root = createRoot(host);
  act(() => root!.render(createElement(AccountSummary)));
  return host;
}

beforeEach(async () => {
  await resetTestDOM();
  Object.defineProperty(document, "visibilityState", { value: "hidden", configurable: true });
  setLang("zh");
  clearAccountSession();
  adoptAccountIdentity({ userId: "u_0123456789abcdef", username: "admin", role: "admin" });
});

afterEach(async () => {
  if (root) {
    act(() => root!.unmount());
    root = null;
  }
  host?.remove();
  host = null;
  clearAccountSession();
});

describe("the account card", () => {
  test("an untouched card offers the sync and says nothing about it", () => {
    const card = render();
    expect(card.querySelector(".account-sync")?.textContent).toBe(t("settings.accountSync"));
    expect(card.querySelector(".notice")).toBeNull();
  });

  test("a successful sync is visible on the card, not only in the domain", () => {
    const card = render();
    act(() => { setAccountSyncOutcome("ok"); });
    const notice = card.querySelector(".notice");
    expect(notice?.textContent).toBe(t("settings.accountSynced"));
    // A success is a status, not an alarm.
    expect(notice?.className).toContain("notice-status");
  });

  test("a sealed vault is painted as its own problem, not as a retry", () => {
    const card = render();
    act(() => { setAccountSyncOutcome("sealed"); });
    const notice = card.querySelector(".notice");
    expect(notice?.textContent).toBe(t("settings.accountSyncSealed"));
    expect(notice?.textContent).not.toBe(t("settings.accountSyncFailed"));
    expect(notice?.className).toContain("notice-error");
  });

  test("the same outcome twice repaints rather than going stale", () => {
    const card = render();
    act(() => { setAccountSyncOutcome("failed", "conflict"); });
    expect(card.querySelector(".notice")?.textContent).toBe(t("settings.accountSyncConflict"));
    // Two presses that fail the same way are two answers. The text is identical,
    // so what must not happen is the second one being dropped as a no-op update.
    act(() => { setAccountSyncOutcome("failed", "conflict"); });
    expect(card.querySelector(".notice")?.textContent).toBe(t("settings.accountSyncConflict"));
    // A later success must replace it rather than sit alongside it.
    act(() => { setAccountSyncOutcome("ok"); });
    expect(card.querySelectorAll(".notice").length).toBe(1);
    expect(card.querySelector(".notice")?.textContent).toBe(t("settings.accountSynced"));
  });

  test("a failure carries the cause the code named", () => {
    const card = render();
    act(() => { setAccountSyncOutcome("failed", "conflict"); });
    expect(card.querySelector(".notice")?.textContent).toBe(t("settings.accountSyncConflict"));

    act(() => { setAccountSyncOutcome("failed", "something_unmapped"); });
    expect(card.querySelector(".notice")?.textContent).toBe(t("settings.accountSyncFailed"));
  });

  test("an in-flight sync changes the label, since a disabled attribute is not visible on a phone", () => {
    const card = render();
    const button = () => card.querySelector<HTMLButtonElement>(".account-sync");
    expect(button()?.textContent).toBe(t("settings.accountSync"));

    act(() => { setAccountBusy(true); });
    expect(button()?.textContent).toBe(t("settings.accountSyncing"));
    expect(button()?.disabled).toBe(true);
    expect(button()?.getAttribute("aria-busy")).toBe("true");

    act(() => { setAccountBusy(false); });
    expect(button()?.textContent).toBe(t("settings.accountSync"));
    expect(button()?.disabled).toBe(false);
  });

  test("a signed-out card offers sign-in instead of a sync it cannot perform", () => {
    act(() => { clearAccountSession(); });
    const card = render();
    expect(card.querySelector(".account-sync")).toBeNull();
    expect(card.querySelector(".account-sign-in")).toBeTruthy();
  });
});
