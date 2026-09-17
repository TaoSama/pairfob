import { describe, expect, test } from "bun:test";
import { PAIR_REF, lastJSON, makeRoom } from "../testutil/make-room.ts";
import { GATE_COOLDOWN_BASE_MS, GATE_FREE_ATTEMPTS, GATE_WINDOW_MS } from "./gate-throttle.ts";
import { MAX_PAIRING } from "../constants.ts";
import { ZERO_ROUTE, sha256Hex } from "../crypto.ts";
import { Typ } from "../envelope.ts";
import { encodeJSON } from "../frames.ts";
import type { FakeSocket } from "./fake-socket.ts";
import { onMessage } from "./ws.ts";

// The SPAKE2+ proof travels end-to-end inside opaque FWD payloads, so the relay
// never sees a guess. It therefore charges the attempt at PAIR_ATTACH, the one
// point every guesser must pass through, rather than waiting for the daemon's
// `bad_pair_code` verdict — an attacker reads the daemon's SPAKE2+ answer,
// checks it offline, and drops the socket without ever provoking one.
// These tests drive that charge and the cooldown it feeds.

async function daemonRoom(): Promise<{ h: ReturnType<typeof makeRoom>; daemon: FakeSocket }> {
  const h = makeRoom();
  const token = "rt_" + "77".repeat(16);
  h.core.enroll({ reconnect_hash: await sha256Hex(token), grant_id: "g_" + "77".repeat(8) });
  const d = h.accept("daemon");
  await onMessage(
    h.core,
    d.ws!,
    encodeJSON(Typ.HELLO_DAEMON, ZERO_ROUTE, {
      v: 2,
      op: "RegisterDaemon",
      daemon_id: h.core.daemonId,
      reconnect_token: token,
    }),
  );
  await onMessage(
    h.core,
    d.ws!,
    encodeJSON(Typ.PAIR_OPEN, ZERO_ROUTE, {
      v: 2,
      op: "CreatePairing",
      daemon_id: h.core.daemonId,
      pair_ref: PAIR_REF,
      ttl_s: 180,
    }),
  );
  return { h, daemon: d.ws! };
}

/** Run one phone through HELLO + PAIR_ATTACH and hand back its socket. */
async function attachPhone(h: ReturnType<typeof makeRoom>): Promise<FakeSocket> {
  const p = h.accept("phone");
  await onMessage(h.core, p.ws!, encodeJSON(Typ.HELLO_CLIENT, ZERO_ROUTE, { v: 2, protocol: 2 }));
  await onMessage(h.core, p.ws!, encodeJSON(Typ.PAIR_ATTACH, ZERO_ROUTE, { v: 2, pair_ref: PAIR_REF }));
  return p.ws!;
}

/** The daemon rejecting a proof on a route, exactly as internal/daemon/pairing.go sends it. */
function badPairCode(daemon: FakeSocket, h: ReturnType<typeof makeRoom>, routeHex: string): Promise<void> {
  const rid = new Uint8Array(16);
  for (let i = 0; i < 16; i++) rid[i] = Number.parseInt(routeHex.slice(i * 2, i * 2 + 2), 16);
  return Promise.resolve(
    onMessage(
      h.core,
      daemon,
      encodeJSON(Typ.ERROR, rid, { v: 2, code: "bad_pair_code", route_id: routeHex, message: "pairing proof rejected" }),
    ),
  );
}

/** Attach a phone, have the daemon reject its proof, and return the closed socket. */
async function failOneAttempt(h: ReturnType<typeof makeRoom>, daemon: FakeSocket): Promise<void> {
  const phone = await attachPhone(h);
  const attached = lastJSON(phone);
  expect(attached.typ).toBe(Typ.PAIR_ATTACHED);
  await badPairCode(daemon, h, attached.body.route_id as string);
}

describe("gate throttle on the pairing route", () => {
  test("an attach is recorded as a failed gate attempt until it is proven otherwise", async () => {
    const { h, daemon } = await daemonRoom();
    const rows: boolean[] = [];
    Object.assign(h.store, {
      recordGateAttempt(_at: number, ok: boolean): void {
        rows.push(ok);
      },
      gateFailuresSince: () => ({ count: 0, lastAt: 0 }),
      pruneGateAttempts: () => {},
    });

    await failOneAttempt(h, daemon);

    expect(rows).toEqual([false]);
  });

  // The regression that motivated moving the charge. An attacker has no reason
  // to stay connected: the daemon's SPAKE2+ answer is checkable offline, so the
  // cheapest dictionary run is attach, read, hang up, repeat. Measured before
  // the fix: 25 consecutive probes were all answered and the ledger held 0 rows,
  // so the cooldown could never arm and the run was unbounded.
  test("a guesser who hangs up without provoking a verdict is still billed", async () => {
    const { h } = await daemonRoom();
    const rows: boolean[] = [];
    Object.assign(h.store, {
      recordGateAttempt(_at: number, ok: boolean): void {
        rows.push(ok);
      },
      gateFailuresSince: () => ({ count: 0, lastAt: 0 }),
      pruneGateAttempts: () => {},
    });

    // Attach and walk away — no ERROR, no FWD, nothing the relay could read as
    // a verdict.
    const phone = await attachPhone(h);
    expect(lastJSON(phone).typ).toBe(Typ.PAIR_ATTACHED);

    expect(rows).toEqual([false]);
  });

  // The same attack driven all the way to its consequence: the run must stop.
  //
  // Each guesser closes its socket, which is what a real dictionary run does
  // and what makes the run possible at all: MAX_PAIRING would otherwise stop
  // the second attach at pair_busy, and a probe whose phones stay connected
  // measures that limit instead of the throttle.
  test("repeated attach-and-hang-up guesses arm the cooldown", async () => {
    const { h } = await daemonRoom();

    let answered = 0;
    for (let i = 0; i < GATE_FREE_ATTEMPTS + 3; i++) {
      const phone = await attachPhone(h);
      if (lastJSON(phone).typ === Typ.PAIR_ATTACHED) answered++;
      phone.close(1000, "guesser hangs up");
      h.core.onClose(phone);
    }

    expect(h.core.gateCheck().allowed).toBeFalse();
    // The free budget is the whole allowance; anything more means the throttle
    // is not actually bounding the run.
    expect(answered).toBeLessThanOrEqual(GATE_FREE_ATTEMPTS + 1);
  });

  test("relay errors that are not the daemon's verdict are not counted", async () => {
    const { h, daemon } = await daemonRoom();
    const rows: boolean[] = [];
    Object.assign(h.store, {
      recordGateAttempt(_at: number, ok: boolean): void {
        rows.push(ok);
      },
      gateFailuresSince: () => ({ count: 0, lastAt: 0 }),
      pruneGateAttempts: () => {},
    });

    const phone = await attachPhone(h);
    // The attach itself is the charge, so the ledger already holds exactly one
    // row before the ERROR arrives.
    expect(rows).toEqual([false]);
    const routeHex = lastJSON(phone).body.route_id as string;
    const rid = new Uint8Array(16);
    for (let i = 0; i < 16; i++) rid[i] = Number.parseInt(routeHex.slice(i * 2, i * 2 + 2), 16);
    // A transport-level complaint says nothing about the passphrase.
    await onMessage(
      h.core,
      daemon,
      encodeJSON(Typ.ERROR, rid, { v: 2, code: "internal", route_id: routeHex, message: "daemon hiccup" }),
    );

    // Still one row: the error added nothing on top of the attach charge.
    expect(rows).toEqual([false]);
  });

  test("PAIR_ATTACH is refused while the room cools down", async () => {
    const { h, daemon } = await daemonRoom();

    for (let i = 0; i < GATE_FREE_ATTEMPTS + 1; i++) await failOneAttempt(h, daemon);

    const blocked = await attachPhone(h);
    const err = lastJSON(blocked);
    expect(err.typ).toBe(Typ.ERROR);
    expect(err.body.code).toBe("rate_limited");
    expect(err.body.retry_after_ms as number).toBeGreaterThan(0);
    // The guesser never got a route, so the daemon was never bothered.
    expect(h.core.countKinds().pairing).toBe(0);
  });

  test("the cooldown lapses and pairing works again", async () => {
    const { h, daemon } = await daemonRoom();
    for (let i = 0; i < GATE_FREE_ATTEMPTS + 1; i++) await failOneAttempt(h, daemon);
    expect(lastJSON(await attachPhone(h)).body.code).toBe("rate_limited");

    h.tick(GATE_COOLDOWN_BASE_MS);

    const ok = await attachPhone(h);
    expect(lastJSON(ok).typ).toBe(Typ.PAIR_ATTACHED);
  });

  test("failures ageing out of the window release the gate", async () => {
    const { h, daemon } = await daemonRoom();
    for (let i = 0; i < GATE_FREE_ATTEMPTS + 1; i++) await failOneAttempt(h, daemon);

    h.tick(GATE_WINDOW_MS + 1);

    expect(lastJSON(await attachPhone(h)).typ).toBe(Typ.PAIR_ATTACHED);
  });

  test("a wrong guess costs the attacker an exponentially longer wait", async () => {
    const { h, daemon } = await daemonRoom();
    for (let i = 0; i < GATE_FREE_ATTEMPTS + 1; i++) await failOneAttempt(h, daemon);
    const first = h.core.gateCheck().retryAfterMs;

    // Serve out the wait, then burn one more attempt.
    h.tick(GATE_COOLDOWN_BASE_MS);
    await failOneAttempt(h, daemon);

    expect(h.core.gateCheck().retryAfterMs).toBeGreaterThan(first);
  });

  test("the relay records the verdict without reading the proof", async () => {
    const { h, daemon } = await daemonRoom();
    const rows: Array<{ at: number; ok: boolean }> = [];
    Object.assign(h.store, {
      recordGateAttempt(at: number, ok: boolean): void {
        rows.push({ at, ok });
      },
      gateFailuresSince: () => ({ count: 0, lastAt: 0 }),
      pruneGateAttempts: () => {},
    });

    const phone = await attachPhone(h);
    const routeHex = lastJSON(phone).body.route_id as string;
    await badPairCode(daemon, h, routeHex);

    // Only a clock reading and a boolean. Nothing ties the row to this phone.
    for (const r of rows) expect(Object.keys(r).sort()).toEqual(["at", "ok"]);
    expect(JSON.stringify(rows)).not.toContain(routeHex);
    expect(JSON.stringify(rows)).not.toContain(PAIR_REF);
  });

  test("MAX_PAIRING keeps the daemon's single pairing slot uncontended", async () => {
    const { h } = await daemonRoom();
    expect(MAX_PAIRING).toBe(1);

    const first = await attachPhone(h);
    expect(lastJSON(first).typ).toBe(Typ.PAIR_ATTACHED);

    // A second phone must get an explicit refusal rather than silently
    // overwriting the daemon's pair.routeID mid-handshake.
    const second = await attachPhone(h);
    expect(lastJSON(second).body.code).toBe("pair_busy");
    expect(h.core.countKinds().pairing).toBe(MAX_PAIRING);
  });
});
