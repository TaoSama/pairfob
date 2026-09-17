import { describe, expect, test } from "bun:test";
import { sha256Hex } from "../crypto.ts";
import { Typ } from "../envelope.ts";
import { ZERO_ROUTE } from "../crypto.ts";
import { encodeJSON } from "../frames.ts";
import { onMessage } from "./ws.ts";
import { PAIR_REF, lastJSON, makeRoom } from "../testutil/make-room.ts";
import { GATE_COOLDOWN_BASE_MS, GATE_FREE_ATTEMPTS, GATE_WINDOW_MS } from "./gate-throttle.ts";

// Exercises the throttle through RoomCore's real entry points.

interface Attempt {
  at: number;
  ok: boolean;
}

/**
 * Shadow the store's ledger with an inspectable array.
 *
 * RoomStore implements the ledger natively, but these own properties take
 * precedence over the prototype so a test can read back the exact rows and so
 * ledger writes stay out of stats.sql — which `a cooled-down room never reaches
 * the pairing slot` relies on to prove the refusal short-circuited.
 */
function installLedger(store: object): Attempt[] {
  const rows: Attempt[] = [];
  Object.assign(store, {
    recordGateAttempt(at: number, ok: boolean): void {
      rows.push({ at, ok });
    },
    gateFailuresSince(since: number): { count: number; lastAt: number } {
      const fails = rows.filter((r) => !r.ok && r.at >= since);
      return { count: fails.length, lastAt: fails.reduce((m, r) => Math.max(m, r.at), 0) };
    },
    pruneGateAttempts(before: number): void {
      for (let i = rows.length - 1; i >= 0; i--) if (rows[i].at < before) rows.splice(i, 1);
    },
  });
  return rows;
}

/** Bring a room up to the point where it holds a live pairing slot. */
async function openPairing(h: ReturnType<typeof makeRoom>): Promise<string> {
  const token = "rt_" + "11".repeat(16);
  h.core.enroll({ reconnect_hash: await sha256Hex(token), grant_id: "g_" + "11".repeat(8) });
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
  return h.store.loadSlot()!.pair_loc;
}

const WRONG_LOC = "zzzzzzzzzz";
const BAD_TICKET = "de".repeat(16);

describe("RoomCore gate throttle wiring", () => {
  test("issueTicket cools down after repeated location misses", async () => {
    const h = makeRoom();
    installLedger(h.store);
    const loc = await openPairing(h);

    for (let i = 0; i < GATE_FREE_ATTEMPTS + 1; i++) {
      expect((await h.core.issueTicket(WRONG_LOC)).ok).toBe(false);
    }

    // The correct location is now refused too: the room itself is cooling down.
    expect((await h.core.issueTicket(loc)).ok).toBe(false);

    h.tick(GATE_COOLDOWN_BASE_MS);
    expect((await h.core.issueTicket(loc)).ok).toBe(true);
  });

  test("a cooled-down room never reaches the pairing slot", async () => {
    const h = makeRoom();
    installLedger(h.store);
    await openPairing(h);

    for (let i = 0; i < GATE_FREE_ATTEMPTS + 1; i++) await h.core.issueTicket(WRONG_LOC);

    const before = h.store.stats.sql;
    expect((await h.core.issueTicket(WRONG_LOC)).ok).toBe(false);
    // Refusal is decided from the ledger alone. The test ledger is not counted
    // by stats.sql, so a delta of zero proves the refusal short-circuited
    // before loadSlot()/insertTicket() — nothing is forwarded onward.
    expect(h.store.stats.sql - before).toBe(0);
  });

  test("consumeUpgrade cools down after repeated bad tickets", async () => {
    const h = makeRoom();
    installLedger(h.store);
    const loc = await openPairing(h);

    for (let i = 0; i < GATE_FREE_ATTEMPTS + 1; i++) {
      expect(h.core.consumeUpgrade(new URLSearchParams({ pair_ticket: BAD_TICKET }), "client").ok).toBe(false);
    }

    const issued = await h.core.issueTicket(loc);
    expect(issued.ok).toBe(false);

    h.tick(GATE_COOLDOWN_BASE_MS);
    const good = await h.core.issueTicket(loc);
    expect(good.ok).toBe(true);
    if (!good.ok) return;
    expect(h.core.consumeUpgrade(new URLSearchParams({ pair_ticket: good.pair_ticket }), "client").ok).toBe(true);
  });

  test("upgrades without a ticket are untouched by the throttle", async () => {
    const h = makeRoom();
    installLedger(h.store);
    await openPairing(h);

    for (let i = 0; i < GATE_FREE_ATTEMPTS + 1; i++) await h.core.issueTicket(WRONG_LOC);

    // Daemon reconnects and plain hellos carry no ticket, so the gate is not
    // involved and a cooldown must not lock the daemon out of its own room.
    expect(h.core.consumeUpgrade(new URLSearchParams(), "daemon").ok).toBe(true);
    expect(h.core.consumeUpgrade(new URLSearchParams(), "client").ok).toBe(true);
  });

  test("the ledger records only timestamps and outcomes", async () => {
    const h = makeRoom();
    const rows = installLedger(h.store);
    const loc = await openPairing(h);

    await h.core.issueTicket(WRONG_LOC);
    await h.core.issueTicket(loc);
    h.core.consumeUpgrade(new URLSearchParams({ pair_ticket: BAD_TICKET }), "client");

    expect(rows.length).toBeGreaterThan(0);
    for (const r of rows) {
      expect(Object.keys(r).sort()).toEqual(["at", "ok"]);
      expect(typeof r.at).toBe("number");
      expect(typeof r.ok).toBe("boolean");
    }
    // Neither the guessed location nor the guessed ticket is anywhere in the ledger.
    const dump = JSON.stringify(rows);
    expect(dump).not.toContain(WRONG_LOC);
    expect(dump).not.toContain(BAD_TICKET);
    expect(dump).not.toContain(loc);
  });

  test("failures ageing out of the window release the room", async () => {
    const h = makeRoom();
    installLedger(h.store);
    const loc = await openPairing(h);

    for (let i = 0; i < GATE_FREE_ATTEMPTS + 1; i++) await h.core.issueTicket(WRONG_LOC);
    expect((await h.core.issueTicket(loc)).ok).toBe(false);

    h.tick(GATE_WINDOW_MS + 1);
    expect((await h.core.issueTicket(loc)).ok).toBe(true);
  });

  test("throttle state survives a hibernation cold start", async () => {
    const h = makeRoom();
    installLedger(h.store);
    const loc = await openPairing(h);
    for (let i = 0; i < GATE_FREE_ATTEMPTS + 1; i++) await h.core.issueTicket(WRONG_LOC);

    // coldStart() rebuilds in-memory maps; the ledger is the only throttle state.
    h.core.coldStart();

    expect((await h.core.issueTicket(loc)).ok).toBe(false);
    h.tick(GATE_COOLDOWN_BASE_MS);
    expect((await h.core.issueTicket(loc)).ok).toBe(true);
  });

  test("the real store throttles without any test ledger installed", async () => {
    const h = makeRoom();
    const loc = await openPairing(h);

    // No installLedger(): RoomStore now carries the ledger natively, so the
    // throttle engages against the shipping implementation.
    for (let i = 0; i < GATE_FREE_ATTEMPTS + 1; i++) {
      expect((await h.core.issueTicket(WRONG_LOC)).ok).toBe(false);
    }
    expect((await h.core.issueTicket(loc)).ok).toBe(false);

    h.tick(GATE_COOLDOWN_BASE_MS);
    expect((await h.core.issueTicket(loc)).ok).toBe(true);
  });

  test("a guesser who hangs up before confirming is still throttled", async () => {
    const h = makeRoom();
    await openPairing(h);

    // The cheapest attack never sends a confirm. SPAKE2+ hands the guesser a
    // confirm_v it can check offline, so it reads the daemon's reply and drops
    // the socket; the daemon therefore never emits the bad_pair_code verdict.
    // Billing the attempt on that verdict alone counted none of this: measured
    // on an earlier tree, 25 consecutive attach-then-hang-up probes were all
    // answered and the ledger held 0 rows. The assertion is deliberately on
    // "the run is bounded" rather than on where the charge is written, so a
    // future refactor that moves the charge cannot silently reopen the hole.
    const attempts = 25;
    let answered = 0;
    for (let i = 0; i < attempts; i++) {
      const p = h.accept("phone");
      await onMessage(h.core, p.ws!, encodeJSON(Typ.HELLO_CLIENT, ZERO_ROUTE, { v: 2, protocol: 2 }));
      await onMessage(h.core, p.ws!, encodeJSON(Typ.PAIR_ATTACH, ZERO_ROUTE, { v: 2, pair_ref: PAIR_REF }));
      if (lastJSON(p.ws!).typ === Typ.PAIR_ATTACHED) answered++;
      h.core.onClose?.(p.ws!);
    }

    expect(answered).toBeLessThanOrEqual(GATE_FREE_ATTEMPTS + 3);
    expect(answered).toBeLessThan(attempts);
  });

  test("a store predating the ledger fails open instead of breaking", async () => {
    const h = makeRoom();
    const loc = await openPairing(h);

    // Simulate a DO whose store predates migration id=2: asGateStore() must
    // return null and the gate must not lock the room out. Only the three
    // ledger methods are hidden; the rest of the store stays intact.
    for (const m of ["recordGateAttempt", "gateFailuresSince", "pruneGateAttempts"]) {
      Object.defineProperty(h.store, m, { value: undefined, configurable: true });
    }

    for (let i = 0; i < GATE_FREE_ATTEMPTS + 5; i++) {
      expect((await h.core.issueTicket(WRONG_LOC)).ok).toBe(false);
    }
    expect((await h.core.issueTicket(loc)).ok).toBe(true);
  });
});
