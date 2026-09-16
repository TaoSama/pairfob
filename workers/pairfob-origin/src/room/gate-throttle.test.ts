import { describe, expect, test } from "bun:test";
import {
  GATE_COOLDOWN_BASE_MS,
  GATE_COOLDOWN_MAX_MS,
  GATE_FREE_ATTEMPTS,
  GATE_PRUNE_INTERVAL_MS,
  GATE_RETAIN_MS,
  GATE_WINDOW_MS,
  GateThrottle,
  gateCooldownMs,
  type GateAttemptStore,
} from "./gate-throttle.ts";


/** Mirrors the SQL the real store runs, so window/prune semantics are exercised. */
class FakeGateStore implements GateAttemptStore {
  rows: Array<{ at: number; ok: boolean }> = [];
  pruneCalls = 0;

  recordGateAttempt(at: number, ok: boolean): void {
    this.rows.push({ at, ok });
  }

  gateFailuresSince(since: number): { count: number; lastAt: number } {
    const fails = this.rows.filter((r) => !r.ok && r.at >= since);
    return { count: fails.length, lastAt: fails.reduce((m, r) => Math.max(m, r.at), 0) };
  }

  pruneGateAttempts(before: number): void {
    this.pruneCalls++;
    this.rows = this.rows.filter((r) => r.at >= before);
  }
}

function failTimes(t: GateThrottle, at: number, n: number): void {
  for (let i = 0; i < n; i++) t.record(at, false);
}

describe("gate cooldown curve", () => {
  test("stays open through the free allowance", () => {
    for (let n = 0; n <= GATE_FREE_ATTEMPTS; n++) expect(gateCooldownMs(n)).toBe(0);
  });

  test("doubles per failure past the allowance", () => {
    expect(gateCooldownMs(GATE_FREE_ATTEMPTS + 1)).toBe(GATE_COOLDOWN_BASE_MS);
    expect(gateCooldownMs(GATE_FREE_ATTEMPTS + 2)).toBe(GATE_COOLDOWN_BASE_MS * 2);
    expect(gateCooldownMs(GATE_FREE_ATTEMPTS + 3)).toBe(GATE_COOLDOWN_BASE_MS * 4);
    expect(gateCooldownMs(GATE_FREE_ATTEMPTS + 4)).toBe(GATE_COOLDOWN_BASE_MS * 8);
  });

  test("is capped and never overflows for absurd failure counts", () => {
    expect(gateCooldownMs(GATE_FREE_ATTEMPTS + 40)).toBe(GATE_COOLDOWN_MAX_MS);
    expect(gateCooldownMs(1e9)).toBe(GATE_COOLDOWN_MAX_MS);
    expect(Number.isFinite(gateCooldownMs(1e9))).toBe(true);
  });
});

describe("GateThrottle", () => {
  test("allows attempts up to the threshold", () => {
    const store = new FakeGateStore();
    const t = new GateThrottle(store);
    for (let i = 0; i < GATE_FREE_ATTEMPTS; i++) {
      expect(t.check(1000 + i).allowed).toBe(true);
      t.record(1000 + i, false);
    }
    expect(t.check(1000 + GATE_FREE_ATTEMPTS).allowed).toBe(true);
  });

  test("refuses once the threshold is exceeded", () => {
    const store = new FakeGateStore();
    const t = new GateThrottle(store);
    failTimes(t, 1000, GATE_FREE_ATTEMPTS + 1);

    const d = t.check(1000);
    expect(d.allowed).toBe(false);
    expect(d.retryAfterMs).toBe(GATE_COOLDOWN_BASE_MS);
  });

  test("recovers once the cooldown elapses", () => {
    const store = new FakeGateStore();
    const t = new GateThrottle(store);
    failTimes(t, 1000, GATE_FREE_ATTEMPTS + 1);

    expect(t.check(1000 + GATE_COOLDOWN_BASE_MS - 1).allowed).toBe(false);
    expect(t.check(1000 + GATE_COOLDOWN_BASE_MS).allowed).toBe(true);
  });

  test("backs off exponentially as failures continue", () => {
    const store = new FakeGateStore();
    const t = new GateThrottle(store);
    failTimes(t, 1000, GATE_FREE_ATTEMPTS + 1);
    expect(t.check(1000).retryAfterMs).toBe(GATE_COOLDOWN_BASE_MS);

    t.record(1000 + GATE_COOLDOWN_BASE_MS, false);
    expect(t.check(1000 + GATE_COOLDOWN_BASE_MS).retryAfterMs).toBe(GATE_COOLDOWN_BASE_MS * 2);
  });

  test("a refused attempt is not recorded, so flooding cannot extend the cooldown", () => {
    const store = new FakeGateStore();
    const t = new GateThrottle(store);
    failTimes(t, 1000, GATE_FREE_ATTEMPTS + 1);
    const rowsAfterTrip = store.rows.length;

    for (let i = 0; i < 50; i++) expect(t.check(1000).allowed).toBe(false);

    expect(store.rows.length).toBe(rowsAfterTrip);
    expect(t.check(1000 + GATE_COOLDOWN_BASE_MS).allowed).toBe(true);
  });

  test("failures ageing out of the window stop counting", () => {
    const store = new FakeGateStore();
    const t = new GateThrottle(store);
    failTimes(t, 1000, GATE_FREE_ATTEMPTS + 1);
    expect(t.check(1000).allowed).toBe(false);

    // Past the window the old failures carry no weight.
    expect(t.check(1000 + GATE_WINDOW_MS + 1).allowed).toBe(true);
  });

  test("success is logged but does not reset the backoff", () => {
    const store = new FakeGateStore();
    const t = new GateThrottle(store);
    failTimes(t, 1000, GATE_FREE_ATTEMPTS + 1);
    t.record(1000, true);

    expect(store.rows.filter((r) => r.ok).length).toBe(1);
    expect(t.check(1000).allowed).toBe(false);
  });

  test("prunes rows outside the retention horizon", () => {
    const store = new FakeGateStore();
    const t = new GateThrottle(store);
    t.record(1000, false);
    const early = store.pruneCalls;

    t.record(1000 + GATE_PRUNE_INTERVAL_MS + 1, false);

    expect(store.pruneCalls).toBeGreaterThan(early);
    // The stale row is gone; the fresh one survives.
    expect(store.rows.every((r) => r.at >= 1000 + GATE_PRUNE_INTERVAL_MS + 1 - GATE_RETAIN_MS)).toBe(true);
  });

  test("the table does not grow without bound under a sustained flood", () => {
    const store = new FakeGateStore();
    const t = new GateThrottle(store);
    let now = 1000;
    for (let i = 0; i < 5000; i++) {
      now += 1000;
      if (t.check(now).allowed) t.record(now, false);
    }
    // Retention plus the throttle itself keeps the ledger small.
    expect(store.rows.length).toBeLessThan(200);
    // Pruning runs on write, so a row can outlive retention by at most one
    // sweep interval. Stale rows never affect a decision: the window query
    // filters on `at`, so this is a storage bound, not a correctness one.
    expect(store.rows.every((r) => r.at >= now - GATE_RETAIN_MS - GATE_PRUNE_INTERVAL_MS)).toBe(true);
  });

  test("decisions survive hibernation because they are recomputed from storage", () => {
    const store = new FakeGateStore();
    const before = new GateThrottle(store);
    failTimes(before, 1000, GATE_FREE_ATTEMPTS + 1);
    expect(before.check(1000).allowed).toBe(false);

    // Cold start: a brand new instance over the same rows must refuse identically.
    const after = new GateThrottle(store);
    expect(after.check(1000).allowed).toBe(false);
    expect(after.check(1000).retryAfterMs).toBe(GATE_COOLDOWN_BASE_MS);
    expect(after.check(1000 + GATE_COOLDOWN_BASE_MS).allowed).toBe(true);
  });
});
