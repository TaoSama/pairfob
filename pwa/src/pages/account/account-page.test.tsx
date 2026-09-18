import { happy, resetBoardTestDOM } from "../../../test-support/dom";
import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { act } from "react";
import { batch } from "../../shared/model/domain-store";
import { mountApp, unmountApp } from "../../app/mount";
import { commitView } from "../../app/host";
import { appRoot } from "../../app/dom-root";
import { registerSessionOwnerPreparer } from "../../app/frame";
import { registerPairedDeviceClaimer, notifyDevicePaired } from "../../app/device-claim";
import { setPhase } from "../../features/connection/connection-store";
import { setAddingComputer, setComputers, setCredential, attachLiveSession, computersStore, liveSession } from "../../features/computers/catalog-store";
import { establish, closeComputerSession } from "../../features/connection/controller";
import type { LiveSession, PairResult, SessionEvent } from "../../lib/protocol/client";
import { fingerprint16 } from "../../lib/protocol/hello";
import { saveCredential, loadCatalog, rememberWrapKey, readWrapKey } from "../../lib/credentials";
import { setScreen } from "../../app/navigation-store";
import { clearNotice } from "../../app/notices-store";
import { resetTransitionState } from "../../app/transition";
import {
  accountStore,
  adoptAccountIdentity,
  clearAccountSession,
  setAccountDevices,
  setAccountGate,
  setAccountInitialized,
} from "../../features/account/account-store";
import { setLang, setLangPref, t } from "../../lib/i18n";
import { resumeAccountAtBoot, signOutOfAccount, switchAccount, syncAccountVault } from "./account-controller";

/**
 * The account surface against the actual mounted App.
 *
 * These are the cases a model test cannot make: that `layout.mode` really routes
 * to this page, that the fields the model describes exist as focusable inputs on
 * the phone-sized document, and that the buttons are wired to the controller
 * rather than to nothing. A pure projection can be right about all of it while
 * the page renders no form at all.
 *
 * The passphrase cost is production Argon2id, so exactly one case signs in for
 * real; every other case seeds the identity through the domain. That is not a
 * shortcut around the crypto — actions.test.ts owns the derivation — it is what
 * keeps this suite about the surface.
 */

const ADMIN = { user_id: "u_0123456789abcdef", username: "admin", role: "admin" };
const DAEMON_A = "d_aaaaaaaaaaaaaaaaaaaa";
const DAEMON_B = "d_bbbbbbbbbbbbbbbbbbbb";
let deleteFailureStore: string | null = null;
let snapshotOpenFailure = false;
const storageDeletes: Array<[string, string]> = [];

function credential(daemonId: string): PairResult {
  const daemonPk = new Uint8Array(32);
  return {
    daemonId, deviceId: "dev_aaaaaaaaaaaaaaaa", psk: new Uint8Array(32), daemonPk,
    relayOrigin: location.origin, fp: fingerprint16(daemonPk), label: "test", createdAt: 1,
  };
}

function poolSession() {
  const listeners = new Set<(event: SessionEvent) => void>();
  const session = {
    closed: 0,
    close: () => { session.closed += 1; },
    isConnected: () => session.closed === 0,
    setNetworkAvailable: () => undefined,
    reconnectNow: () => undefined,
    onEvent: (listener: (event: SessionEvent) => void) => {
      listeners.add(listener);
      return () => listeners.delete(listener);
    },
    getConfig: async () => ({}),
    snapshot: async () => ({ panes: [] }),
  };
  return session as unknown as LiveSession & { closed: number };
}

type Route = (body: unknown) => { status?: number; json: unknown };

const originalFetch = globalThis.fetch;
let originalIndexedDB: PropertyDescriptor | undefined;
let seen: { path: string; method: string; body: unknown }[] = [];

/** A scripted origin. Anything unscripted answers 500 and shows up in `seen`. */
function serve(table: Record<string, Route>): void {
  seen = [];
  globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = new URL(String(input), location.origin);
    const method = init?.method ?? "GET";
    const body = typeof init?.body === "string" ? JSON.parse(init.body) : null;
    seen.push({ path: url.pathname, method, body });
    const route = table[`${method} ${url.pathname}`];
    if (!route) return new Response(JSON.stringify({ ok: false, error: { code: "internal" } }), { status: 500 });
    const { status = 200, json } = route(body);
    return new Response(JSON.stringify(json), { status });
  }) as typeof fetch;
}

/** The empty-vault origin most cases want: a session, no devices, no vault yet. */
function serveSignedIn(extra: Record<string, Route> = {}): void {
  serve({
    "GET /v2/account/state": () => ({ json: { ok: true, initialized: true, user: ADMIN } }),
    "GET /v2/account/devices": () => ({ json: { ok: true, devices: [] } }),
    "GET /v2/account/vault": () => ({ status: 404, json: { ok: false, error: { code: "unbound" } } }),
    ...extra,
  });
}

/**
 * Enough IndexedDB for the credential database to settle empty.
 *
 * The account controller reads the local catalogue before it syncs, and
 * happy-dom ships no IndexedDB, so without this the page would render against a
 * rejected read rather than against the empty catalogue a fresh phone has.
 */
function installIndexedDBShim(): void {
  const stores = new Map<string, Map<string, unknown>>([["credentials", new Map()], ["settings", new Map()]]);
  const db = {
    objectStoreNames: { contains: (name: string) => stores.has(name) },
    transaction(name: string) {
      const store = stores.get(name) ?? new Map();
      let deletion = false;
      const tx = {
        error: new Error("delete denied"),
        objectStore: () => ({
          getAll: () => idbRequest(() => Array.from(store.values())),
          get: (key: string) => idbRequest(() => store.get(String(key))),
          put: (value: unknown, key?: string) => idbRequest(() => {
            const id = key ?? (value as { daemon_id?: string })?.daemon_id;
            if (id !== undefined) store.set(String(id), value);
          }),
          delete: (key: string) => {
            deletion = true;
            storageDeletes.push([name, key]);
            return idbRequest(() => { if (deleteFailureStore !== name) store.delete(String(key)); });
          },
        }),
        set oncomplete(run: (() => void) | null) {
          if (run) queueMicrotask(() => { if (!deletion || deleteFailureStore !== name) run(); });
        },
        set onerror(run: (() => void) | null) {
          if (run) queueMicrotask(() => { if (deletion && deleteFailureStore === name) run(); });
        },
        set onabort(_run: (() => void) | null) { /* abort is covered by storage tests */ },
      };
      return tx;
    },
    close: () => {},
  };
  (globalThis as Record<string, unknown>).indexedDB = { open: (name: string) => {
    if (snapshotOpenFailure && name === "pairfob-session-cache") {
      const request = { onerror: null as (() => void) | null, error: new Error("snapshot open denied") };
      queueMicrotask(() => request.onerror?.());
      return request;
    }
    return idbRequest(() => db);
  } };
}

function idbRequest<T>(run: () => T) {
  const request = {
    result: undefined as T | undefined,
    error: null as unknown,
    onsuccess: null as (() => void) | null,
    onerror: null as (() => void) | null,
    onupgradeneeded: null as (() => void) | null,
  };
  queueMicrotask(() => {
    request.result = run();
    request.onsuccess?.();
  });
  return request;
}

/** Let the controller's await chain and React's queued commit both settle. */
async function settle(): Promise<void> {
  await act(async () => {
    for (let i = 0; i < 40; i += 1) await Promise.resolve();
    await new Promise<void>((resolve) => setTimeout(resolve, 0));
  });
}

/**
 * Wait for a condition instead of for a fixed number of turns.
 *
 * Signing in runs real Argon2id, which takes far longer than any microtask
 * drain: a fixed wait passes or fails depending on how busy the machine is,
 * which is the definition of a flaky test. This yields until the thing actually
 * happened, and fails loudly with the reason if it never does.
 */
async function until(what: string, ready: () => boolean, tries = 200): Promise<void> {
  for (let i = 0; i < tries; i += 1) {
    if (ready()) return;
    await act(async () => { await new Promise<void>((resolve) => setTimeout(resolve, 10)); });
  }
  throw new Error(`timed out waiting for ${what}`);
}

async function mountAccount(gate: "entry" = "entry"): Promise<HTMLElement> {
  act(() => {
    batch(() => {
      setPhase("connect");
      setAccountGate(gate);
    });
    mountApp();
    commitView();
  });
  await settle();
  return appRoot();
}

function field(app: HTMLElement, name: string): HTMLInputElement {
  const input = app.querySelector<HTMLInputElement>(`input[name="${name}"]`);
  if (!input) throw new Error(`no ${name} field on the account form`);
  return input;
}

/**
 * Type as a person does.
 *
 * The value goes in through the prototype setter rather than by assignment:
 * React tracks the last value it rendered on the node itself, and a direct
 * assignment updates the DOM behind that tracker, so the change event that
 * follows is discarded as a no-op and the controlled field never moves.
 */
function type(input: HTMLInputElement, value: string): void {
  const setter = Object.getOwnPropertyDescriptor(happy.HTMLInputElement.prototype, "value")?.set;
  if (!setter) throw new Error("no value setter on HTMLInputElement");
  act(() => {
    setter.call(input, value);
    input.dispatchEvent(new happy.Event("input", { bubbles: true }) as unknown as Event);
  });
}

function submit(app: HTMLElement): void {
  const form = app.querySelector<HTMLFormElement>("form.account-form")!;
  act(() => { form.dispatchEvent(new happy.Event("submit", { bubbles: true, cancelable: true }) as unknown as Event); });
}

function click(app: HTMLElement, selector: string): void {
  const button = app.querySelector<HTMLButtonElement>(selector);
  if (!button) throw new Error(`no ${selector} on the account page`);
  act(() => { button.click(); });
}

beforeEach(async () => {
  await resetBoardTestDOM();
  Object.defineProperty(document, "visibilityState", { value: "hidden", configurable: true });
  originalIndexedDB = Object.getOwnPropertyDescriptor(globalThis, "indexedDB");
  deleteFailureStore = null;
  snapshotOpenFailure = false;
  storageDeletes.length = 0;
  installIndexedDBShim();
  registerSessionOwnerPreparer(null);
  registerPairedDeviceClaimer(null);
  resetTransitionState();
  localStorage.removeItem("pairfob_lang");
  setLangPref("auto");
  setLang("zh");
  act(() => {
    batch(() => {
      clearAccountSession();
      setAccountGate("off");
      setPhase("connect");
      setScreen("home");
      setComputers([]);
      setAddingComputer(false);
      clearNotice();
    });
  });
});

afterEach(async () => {
  await act(async () => {
    closeComputerSession(DAEMON_A);
    closeComputerSession(DAEMON_B);
    unmountApp();
    registerSessionOwnerPreparer(null);
    registerPairedDeviceClaimer(null);
    resetTransitionState();
    batch(() => {
      clearAccountSession();
      setAccountGate("off");
      setComputers([]);
      setCredential(null);
      setAddingComputer(false);
      attachLiveSession(null);
      setPhase("boot");
      setScreen("home");
      clearNotice();
    });
    clearNotice();
  });
  globalThis.fetch = originalFetch;
  if (originalIndexedDB) Object.defineProperty(globalThis, "indexedDB", originalIndexedDB);
  else delete (globalThis as Record<string, unknown>).indexedDB;
  localStorage.removeItem("pairfob_lang");
  setLangPref("auto");
  setLang("zh");
});

describe("the account gate reaches the page", () => {
  test("a deployment with no account renders the bootstrap form, not sign-in", async () => {
    serve({ "GET /v2/account/state": () => ({ json: { ok: true, initialized: false, user: null } }) });
    act(() => { setAccountInitialized(false); });
    const app = await mountAccount();

    expect(app.querySelector(".prelude-title")?.textContent).toBe(t("account.title.bootstrap"));
    // The first account's name is not the person's to choose, so it is stated.
    expect(app.querySelector(".account-username")?.textContent).toBe("admin");
    expect(app.querySelector('input[name="username"]')).toBeNull();
    expect(field(app, "serviceToken").type).toBe("password");
    expect(field(app, "confirm")).toBeTruthy();
    // Bootstrap has no account to sign in to, so there is nothing to switch to.
    expect(app.querySelector(".account-switch-form")).toBeNull();
  });

  test("a deployment that already has an admin renders sign-in with a way to register", async () => {
    serve({ "GET /v2/account/state": () => ({ json: { ok: true, initialized: true, user: null } }) });
    act(() => { setAccountInitialized(true); });
    const app = await mountAccount();

    expect(app.querySelector(".prelude-title")?.textContent).toBe(t("account.title.login"));
    expect(field(app, "username")).toBeTruthy();
    expect(app.querySelector('input[name="serviceToken"]')).toBeNull();
    expect(app.querySelector('input[name="inviteCode"]')).toBeNull();

    click(app, ".account-switch-form");
    await settle();
    expect(app.querySelector(".prelude-title")?.textContent).toBe(t("account.title.register"));
    const invite = field(app, "inviteCode");
    expect(invite.maxLength).toBe(4);
    expect(invite.getAttribute("autocapitalize")).toBe("characters");
  });

  test("gate off leaves the application composing as it did before", async () => {
    serve({});
    const app = await mountAccount();
    expect(app.querySelector(".account-page")).toBeTruthy();

    act(() => { setAccountGate("off"); commitView(); });
    await settle();
    expect(appRoot().querySelector(".account-page")).toBeNull();
  });
});

describe("submitting the form", () => {
  test("the submit button stays refused until every field is valid", async () => {
    serve({ "GET /v2/account/state": () => ({ json: { ok: true, initialized: true, user: null } }) });
    act(() => { setAccountInitialized(true); });
    const app = await mountAccount();
    const button = app.querySelector<HTMLButtonElement>(".account-submit")!;
    expect(button.disabled).toBeTrue();

    type(field(app, "username"), "admin");
    type(field(app, "password"), "short");
    expect(button.disabled).toBeTrue();

    type(field(app, "password"), "correct horse battery");
    expect(button.disabled).toBeFalse();
  });

  test("a leaving field explains itself without complaining mid-typing", async () => {
    serve({ "GET /v2/account/state": () => ({ json: { ok: true, initialized: true, user: null } }) });
    act(() => { setAccountInitialized(true); });
    const app = await mountAccount();
    const username = field(app, "username");

    type(username, "A");
    expect(app.querySelector("#account-username-problem")).toBeNull();

    // React delegates onBlur from the root, and a native blur does not bubble
    // there, so leaving a field is dispatched as the focusout it really is.
    act(() => { username.dispatchEvent(new happy.Event("focusout", { bubbles: true }) as unknown as Event); });
    const problem = app.querySelector("#account-username-problem");
    expect(problem?.textContent).toBe(t("account.problem.username"));
    expect(username.getAttribute("aria-invalid")).toBe("true");
  });

  test("a real sign-in leaves the gate and never sends the passphrase", async () => {
    serveSignedIn({ "POST /v2/account/login": () => ({ json: { ok: true, user: ADMIN } }) });
    act(() => { setAccountInitialized(true); });
    const app = await mountAccount();

    type(field(app, "username"), "admin");
    type(field(app, "password"), "correct horse battery");
    submit(app);
    // Deriving the origin password is real Argon2id, which runs far longer than
    // any drain of the queue, so the wait is on the request having gone out.
    await until("the sign-in request", () => seen.some((call) => call.path === "/v2/account/login"));
    await until("the gate to clear", () => accountStore.get().gate === "off");
    // Landing is not the end of the sign-in: the vault sync trails it, and the
    // "nothing was written" claim below is only worth making once it has run.
    await settle();

    const login = seen.find((call) => call.path === "/v2/account/login")!;
    expect((login.body as { password: string }).password).not.toBe("correct horse battery");
    expect((login.body as { password: string }).password).toMatch(/^[0-9a-f]{64}$/);
    // A signed-in phone hands the page back rather than stopping on an account
    // surface of its own.
    expect(appRoot().querySelector(".account-page")).toBeNull();
    expect(accountStore.get().username).toBe("admin");
    // No vault existed, and nothing local to carry up, so nothing was written.
    expect(seen.filter((call) => call.method === "PUT")).toEqual([]);
  }, 30_000);

  test("a refused sign-in explains itself and keeps what was typed", async () => {
    serve({
      "GET /v2/account/state": () => ({ json: { ok: true, initialized: true, user: null } }),
      "POST /v2/account/login": () => ({ status: 401, json: { ok: false, error: { code: "bad_credentials" } } }),
    });
    act(() => { setAccountInitialized(true); });
    const app = await mountAccount();

    type(field(app, "username"), "admin");
    type(field(app, "password"), "wrong passphrase");
    submit(app);
    // Same Argon2id cost on the way to being told no: wait for the refusal to
    // have been rendered rather than for a fixed number of turns.
    await until("the refusal", () => appRoot().textContent.includes(t("account.error.badCredentials")));

    expect(appRoot().querySelector(".account-page")).toBeTruthy();
    expect(appRoot().textContent).toContain(t("account.error.badCredentials"));
    // Retyping a whole passphrase to fix one character is the reason people
    // give up, so a refusal leaves the draft alone.
    expect(field(appRoot(), "username").value).toBe("admin");
    expect(field(appRoot(), "password").value).toBe("wrong passphrase");
  }, 30_000);
});

describe("the device list", () => {
  function signedIn(): void {
    act(() => {
      batch(() => {
        adoptAccountIdentity({ userId: ADMIN.user_id, username: "admin", role: "admin" });
      });
    });
  }

  test("a signed-in phone with no credential is sent to pairing, not to a list", async () => {
    serveSignedIn();
    signedIn();
    await mountAccount();
    await act(async () => { await resumeAccountAtBoot(); });
    await settle();

    // Nothing to resume means nothing to list, so the account plane steps out of
    // the way and pairing takes over rather than showing a page whose only
    // content would be a button to leave it.
    expect(accountStore.get().gate).toBe("off");
    expect(appRoot().querySelector(".account-page")).toBeNull();
    expect(computersStore.get().addingComputer).toBeTrue();
  });

  test("a reopened browser unseals the vault from the stored wrapping key", async () => {
    // The cross-device resume: the session cookie outlived the page and no
    // passphrase was typed. The wrapping key persisted at sign-in is what lets
    // this reload open the vault, so the machines synced from another device are
    // usable here instead of merely named.
    const wrapKey = new Uint8Array(32).fill(7);
    await rememberWrapKey(wrapKey);
    serve({
      "GET /v2/account/state": () => ({ json: { ok: true, initialized: true, user: ADMIN } }),
      "GET /v2/account/devices": () => ({
        json: { ok: true, devices: [{ daemon_id: DAEMON_A, label: "desk", bound_at: 1, live: false }] },
      }),
      "GET /v2/account/vault": () => ({ status: 404, json: { ok: false, error: { code: "unbound" } } }),
    });
    await mountAccount();
    await act(async () => { await resumeAccountAtBoot(); });
    await settle();

    // The key is back in the record, which is the difference between a phone
    // that can open its vault after a reload and one that cannot.
    expect(accountStore.get().wrapKey).not.toBeNull();
    expect(accountStore.get().gate).toBe("off");
  });

  test("signing out forgets the stored wrapping key", async () => {
    await rememberWrapKey(new Uint8Array(32).fill(9));
    serveSignedIn({ "POST /v2/account/logout": () => ({ json: { ok: true } }) });
    signedIn();
    await mountAccount();

    await act(async () => { await signOutOfAccount(); });
    await settle();

    // Leaving it behind would let the next person on this phone reopen the vault
    // of an account they have just been signed out of.
    expect(await readWrapKey()).toBeNull();
  });

  test("signing out drops the identity and returns to the sign-in form", async () => {
    serveSignedIn({ "POST /v2/account/logout": () => ({ json: { ok: true } }) });
    signedIn();
    act(() => { setAccountDevices([{ daemonId: DAEMON_A, label: "desk", boundAt: 1, live: true }]); });
    const app = await mountAccount();

    await act(async () => { await signOutOfAccount(); });
    await settle();

    const record = accountStore.get();
    expect(record.userId).toBeNull();
    expect(record.vaultKey).toBeNull();
    expect(record.wrapKey).toBeNull();
    expect(record.devices).toEqual([]);
    // The deployment still has an account; forgetting that would offer the next
    // person the bootstrap form.
    expect(record.initialized).toBeTrue();
    expect(appRoot().querySelector(".account-form")).toBeTruthy();
  });

  for (const failure of ["network", "server"] as const) {
    test(`${failure} logout failure preserves identity and reports the error`, async () => {
      serveSignedIn({ "POST /v2/account/logout": () => {
        if (failure === "network") throw new TypeError("offline");
        return { status: 503, json: { ok: false, error: { code: "internal" } } };
      } });
      signedIn();
      setAccountDevices([{ daemonId: DAEMON_A, label: "desk", boundAt: 1, live: true }]);
      const before = accountStore.get();
      const app = await mountAccount();
      let result = true;
      await act(async () => { result = await switchAccount(); });
      expect(result).toBeFalse();
      expect(accountStore.get().userId).toBe(before.userId);
      expect(accountStore.get().wrapKey).toEqual(before.wrapKey);
      expect(accountStore.get().devices).toEqual(before.devices);
      expect(accountStore.get().gate).toBe("entry");
      expect(accountStore.get().errorCode).toBe(failure === "network" ? "bad_relay" : "internal");
      expect(app.textContent).toContain(t(failure === "network" ? "account.error.offline" : "account.error.unknown"));
      expect(storageDeletes).toEqual([]);
    });
  }

  test("successful logout closes both pooled sessions and clears the current credential", async () => {
    serveSignedIn({ "POST /v2/account/logout": () => ({ json: { ok: true } }) });
    signedIn();
    setAccountDevices([DAEMON_A, DAEMON_B].map((daemonId) => ({ daemonId, label: "desk", boundAt: 1, live: true })));
    const a = poolSession();
    const b = poolSession();
    await act(async () => {
      await establish(credential(DAEMON_A), async () => a);
      await establish(credential(DAEMON_B), async () => b);
    });
    expect(a.closed).toBe(0);
    expect(b.closed).toBe(0);
    expect(liveSession()).toBe(b);
    let result = false;
    await act(async () => { result = await signOutOfAccount(); });
    expect(result).toBeTrue();
    expect(a.closed).toBe(1);
    expect(b.closed).toBe(1);
    expect(liveSession()).toBeNull();
    expect(computersStore.get().credential).toBeNull();
    for (const daemonId of [DAEMON_A, DAEMON_B]) {
      expect(storageDeletes).toContainEqual(["credentials", daemonId]);
      expect(storageDeletes).toContainEqual(["snapshots", daemonId]);
    }
    // Removing again must be a no-op: neither session remains in the pool.
    closeComputerSession(DAEMON_A);
    closeComputerSession(DAEMON_B);
    expect(a.closed).toBe(1);
    expect(b.closed).toBe(1);
  });

  for (const failure of ["credentials", "snapshots", "snapshot-open"] as const) {
    test(`${failure} cleanup failure is visible and does not repopulate the signed-out catalogue`, async () => {
      serveSignedIn({ "POST /v2/account/logout": () => ({ json: { ok: true } }) });
      signedIn();
      setAccountDevices([{ daemonId: DAEMON_A, label: "desk", boundAt: 1, live: true }]);
      await saveCredential(credential(DAEMON_A));
      const app = await mountAccount();
      if (failure === "snapshot-open") snapshotOpenFailure = true;
      else deleteFailureStore = failure;
      let result = true;
      await act(async () => { result = await switchAccount(); });
      expect(result).toBeFalse();
      expect(accountStore.get().userId).toBeNull();
      expect(accountStore.get().errorCode).toBe("unknown");
      expect(app.textContent).toContain(t("account.error.unknown"));
      expect(computersStore.get().computers).toEqual([]);
      expect(computersStore.get().credential).toBeNull();
      if (failure === "credentials") {
        expect((await loadCatalog(location.origin)).credentials.map((pair) => pair.daemonId)).toEqual([DAEMON_A]);
      }
    });
  }

  test("switching accounts clears the form the previous person left behind", async () => {
    serveSignedIn({ "POST /v2/account/logout": () => ({ json: { ok: true } }) });
    signedIn();
    const app = await mountAccount();

    await act(async () => { await switchAccount(); });
    await settle();

    expect(accountStore.get().wantsRegister).toBeFalse();
    expect(accountStore.get().errorCode).toBeNull();
    expect(field(appRoot(), "username").value).toBe("");
    expect(field(appRoot(), "password").value).toBe("");
  });
});

describe("pairing announces a machine to the account", () => {
  test("the seam is empty until a claimer installs, so pairing works without an account", () => {
    // notifyDevicePaired is called on every successful pairing, including on a
    // build with no account plane. Throwing here would break pairing itself.
    expect(() => notifyDevicePaired(DAEMON_A, "desk")).not.toThrow();
  });

  test("an installed claimer is handed the machine that was just paired", () => {
    const claims: Array<[string, string | null]> = [];
    registerPairedDeviceClaimer((daemonId, label) => { claims.push([daemonId, label]); });
    notifyDevicePaired(DAEMON_A, "desk");
    expect(claims).toEqual([[DAEMON_A, "desk"]]);
  });
});

/**
 * Pressing 立即同步 and being told what happened.
 *
 * Every case here is one the button used to answer with an unchanged screen. The
 * assertions are on the published outcome rather than on a rendered string,
 * because the outcome is what the page has to have before any copy can appear;
 * sync-feedback.test.ts owns the sentence each outcome resolves to.
 */
describe("syncing the account on demand", () => {
  test("a successful sync is published rather than leaving the screen unchanged", async () => {
    serveSignedIn();
    act(() => { adoptAccountIdentity({ userId: ADMIN.user_id, username: ADMIN.username, role: "admin" }); });
    await settle();

    await act(async () => { await syncAccountVault(null); });
    await settle();

    expect(accountStore.get().syncOutcome).toBe("ok");
    expect(accountStore.get().syncCode).toBeNull();
  });

  test("pressing again re-answers instead of going quiet on an unchanged outcome", async () => {
    serveSignedIn();
    act(() => { adoptAccountIdentity({ userId: ADMIN.user_id, username: ADMIN.username, role: "admin" }); });
    await settle();

    await act(async () => { await syncAccountVault(null); });
    await settle();
    const first = accountStore.get().syncSeq;

    await act(async () => { await syncAccountVault(null); });
    await settle();

    // Same outcome twice is still two answers to two presses.
    expect(accountStore.get().syncOutcome).toBe("ok");
    expect(accountStore.get().syncSeq).toBeGreaterThan(first);
  });

  test("the button reports in flight so a slow sync does not look dead", async () => {
    let release: (() => void) | null = null;
    const holding = new Promise<void>((resolve) => { release = resolve; });
    serve({
      "GET /v2/account/state": () => ({ json: { ok: true, initialized: true, user: ADMIN } }),
      "GET /v2/account/devices": () => ({ json: { ok: true, devices: [] } }),
      "GET /v2/account/vault": () => ({ status: 404, json: { ok: false, error: { code: "unbound" } } }),
    });
    act(() => { adoptAccountIdentity({ userId: ADMIN.user_id, username: ADMIN.username, role: "admin" }); });
    await settle();

    const slowFetch = globalThis.fetch;
    globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
      if (String(input).includes("/v2/account/devices")) await holding;
      return slowFetch(input, init);
    }) as typeof fetch;

    const sync = syncAccountVault(null);
    await until("the sync to report itself busy", () => accountStore.get().busy);
    expect(accountStore.get().busy).toBe(true);

    release!();
    await act(async () => { await sync; });
    await settle();

    // The flag is released whatever the answer was, or the button stays dead.
    expect(accountStore.get().busy).toBe(false);
    globalThis.fetch = slowFetch;
  });

  test("a vault this phone cannot open asks for the passphrase, not a retry", async () => {
    // A real stored vault whose cost record this build cannot decode. That is the
    // sealed case, and it is not an exception, which is exactly why it used to
    // pass for an ordinary successful no-op.
    serve({
      "GET /v2/account/state": () => ({ json: { ok: true, initialized: true, user: ADMIN } }),
      "GET /v2/account/devices": () => ({
        json: { ok: true, devices: [{ daemon_id: DAEMON_A, label: "desk", bound_at: 1, live: false }] },
      }),
      "GET /v2/account/vault": () => ({
        json: {
          ok: true,
          vault: {
            ciphertext: "AAAA", nonce: "AAAA", kdf: "not-a-kdf-record", version: 7, updated_at: 1,
          },
        },
      }),
    });
    act(() => { adoptAccountIdentity({ userId: ADMIN.user_id, username: ADMIN.username, role: "admin" }); });
    await settle();

    await act(async () => { await syncAccountVault(null); });
    await settle();

    expect(accountStore.get().syncOutcome).toBe("sealed");
    // Sealed must never publish: writing here is a winning compare-and-set over
    // a blob whose plaintext nobody holds.
    expect(seen.filter((call) => call.method === "PUT")).toEqual([]);
  });

  test("an expired session reopens the form instead of offering a hopeless retry", async () => {
    serve({
      "GET /v2/account/state": () => ({ json: { ok: true, initialized: true, user: null } }),
      "GET /v2/account/devices": () => ({ status: 401, json: { ok: false, error: { code: "unauthenticated" } } }),
    });
    act(() => { adoptAccountIdentity({ userId: ADMIN.user_id, username: ADMIN.username, role: "admin" }); });
    await settle();

    await act(async () => { await syncAccountVault(null); });
    await settle();

    expect(accountStore.get().username).toBeNull();
    expect(accountStore.get().gate).toBe("entry");
    // Not reported as a retryable sync failure: retrying cannot mint a session.
    expect(accountStore.get().syncOutcome).not.toBe("failed");
  });

  test("a relay failure keeps the code so the message can be specific", async () => {
    serve({
      "GET /v2/account/state": () => ({ json: { ok: true, initialized: true, user: ADMIN } }),
      "GET /v2/account/devices": () => ({ status: 429, json: { ok: false, error: { code: "rate_limited" } } }),
    });
    act(() => { adoptAccountIdentity({ userId: ADMIN.user_id, username: ADMIN.username, role: "admin" }); });
    await settle();

    await act(async () => { await syncAccountVault(null); });
    await settle();

    expect(accountStore.get().syncOutcome).toBe("failed");
    expect(accountStore.get().syncCode).toBe("rate_limited");
  });

  test("a press with no session left says so instead of doing nothing at all", async () => {
    serveSignedIn();
    act(() => {
      clearAccountSession();
      // The signed-in branch can still be on screen when the identity is gone.
      setAccountGate("off");
    });
    await settle();

    await act(async () => { await syncAccountVault(null); });
    await settle();

    // Silence here is indistinguishable from a broken button.
    expect(accountStore.get().gate).toBe("entry");
  });
});
