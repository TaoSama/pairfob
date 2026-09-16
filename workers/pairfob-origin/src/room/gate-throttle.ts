// Per-room brute-force throttle for the passphrase gate.
//
// The relay is an opaque forwarder and never sees the passphrase, so the only
// signal available here is "an attempt happened at time T and it failed".
// That is deliberately all we persist: no passphrase, no hash, no IP, no
// device identifier. The room itself is the rate-limiting subject, which is
// the coarsest grain that still keeps guess traffic away from the daemon.
//
// All state lives in SQLite and every decision is recomputed from it, so a
// hibernated Durable Object resumes throttling correctly with no warm-up and
// no in-memory reconstruction step.

/** Sliding window over which failed attempts accumulate. */
export const GATE_WINDOW_MS = 60_000;

/** Failures tolerated inside the window before cooldown engages. */
export const GATE_FREE_ATTEMPTS = 5;

/** First cooldown step, doubled for each failure past the free allowance. */
export const GATE_COOLDOWN_BASE_MS = 1_000;

/** Ceiling on the exponential backoff, so a room is never bricked. */
export const GATE_COOLDOWN_MAX_MS = 60_000;

/** How long the ledger is kept; rows older than this carry no decision weight. */
export const GATE_RETAIN_MS = GATE_WINDOW_MS;

/** Minimum spacing between prune sweeps, to keep the hot path cheap. */
export const GATE_PRUNE_INTERVAL_MS = 60_000;

/** Storage port for the `gate_attempts` ledger (migration id=2). */
export interface GateAttemptStore {
  recordGateAttempt(at: number, ok: boolean): void;
  gateFailuresSince(since: number): { count: number; lastAt: number };
  pruneGateAttempts(before: number): void;
}

/**
 * Compile-time tie between the port and `RoomStore`.
 *
 * `RoomStore` declares the ledger methods inline so that types.ts carries no
 * throttle import. That leaves the two free to drift, and drift is silent at
 * runtime: `asGateStore` would just return null and the throttle would quietly
 * stop protecting anything. Referencing the store type here makes tsc fail
 * instead. Type-only, so it costs nothing at runtime.
 */
export type RoomStoreSatisfiesGatePort<T extends GateAttemptStore> = T;

/**
 * Narrow an arbitrary store to the gate ledger port.
 *
 * The three methods land in `RoomStore` alongside the id=2 migration; until
 * every implementation carries them this keeps the throttle decoupled from
 * the store interface. Returns null when the backing store cannot persist
 * attempts, which the caller must treat as "throttle unavailable".
 */
export function asGateStore(store: unknown): GateAttemptStore | null {
  const s = store as Partial<GateAttemptStore> | null;
  if (!s) return null;
  if (
    typeof s.recordGateAttempt !== "function" ||
    typeof s.gateFailuresSince !== "function" ||
    typeof s.pruneGateAttempts !== "function"
  ) {
    return null;
  }
  return s as GateAttemptStore;
}

export interface GateDecision {
  allowed: boolean;
  /** Milliseconds until the next attempt is permitted; 0 when allowed. */
  retryAfterMs: number;
}

/**
 * Exponential backoff for a given failure count inside the window.
 * Returns 0 while the count is still within the free allowance.
 */
export function gateCooldownMs(failures: number): number {
  const over = failures - GATE_FREE_ATTEMPTS;
  if (over <= 0) return 0;
  // Shift past 30 would overflow into nonsense; the cap makes it moot anyway.
  const steps = Math.min(over - 1, 30);
  return Math.min(GATE_COOLDOWN_BASE_MS * 2 ** steps, GATE_COOLDOWN_MAX_MS);
}

export class GateThrottle {
  /**
   * Prune bookkeeping only. Losing it to hibernation just means the next
   * attempt sweeps, which is harmless — it is never read for a decision.
   */
  private lastPruneAt = 0;

  constructor(private readonly store: GateAttemptStore) {}

  /**
   * Decide whether an attempt may proceed. Read-only: a refused attempt is not
   * written back, so flooding during a cooldown cannot extend it or grow the
   * table without bound.
   */
  check(now: number): GateDecision {
    const { count, lastAt } = this.store.gateFailuresSince(now - GATE_WINDOW_MS);
    const cooldown = gateCooldownMs(count);
    if (cooldown === 0) return { allowed: true, retryAfterMs: 0 };
    const elapsed = now - lastAt;
    if (elapsed >= cooldown) return { allowed: true, retryAfterMs: 0 };
    return { allowed: false, retryAfterMs: cooldown - elapsed };
  }

  /**
   * Record the outcome of an attempt that was actually evaluated.
   *
   * A success is logged but does not clear the window: the relay cannot tell a
   * legitimate unlock from an attacker who landed a guess, so letting success
   * reset the counter would hand out a free escape from the backoff.
   */
  record(now: number, ok: boolean): void {
    this.store.recordGateAttempt(now, ok);
    this.maybePrune(now);
  }

  private maybePrune(now: number): void {
    if (now - this.lastPruneAt < GATE_PRUNE_INTERVAL_MS) return;
    this.lastPruneAt = now;
    this.store.pruneGateAttempts(now - GATE_RETAIN_MS);
  }
}
