import { beforeEach, describe, expect, test } from "bun:test";
import { handleAccount } from "./account.ts";
import { inviteGlobalSubject } from "./account-auth.ts";
import {
  COUNT_AUTH_FAILURES_SQL,
  SELECT_INVITE_SQL,
  countFailures,
  releaseFailureBudget,
  reserveFailureBudget,
} from "./account-store.ts";
import { AUTH_LOCKOUT_MS, AUTH_LOCKOUT_STRIKES } from "./constants.ts";
import { resetLimits } from "./limits.ts";
import { FakeD1 } from "./testutil/fake-d1.ts";
import { testEnv } from "./testutil/make-room.ts";
import {
  MEMBER_PASSWORD,
  accountReq,
  bodyOf,
  inviteOf,
  makeAdmin,
} from "./testutil/account-harness.ts";

beforeEach(() => resetLimits());

const ATTACKER = "203.0.113.150";

/** Bootstrap mints the first code, so the live global budget is version 1. */
const GLOBAL_V1 = inviteGlobalSubject(1);

/**
 * A round trip that actually takes time. With the double resolving on
 * microtasks, two requests interleave but a batch of six still completes in
 * arrival order, so a read-then-write ledger looks safe. A timer-backed gate
 * lets all six reach their first await before any answer comes back, which is
 * what a real network hop to D1 does and what the lockout has to survive.
 */
function slowD1(): FakeD1 {
  const d1 = new FakeD1();
  d1.latencyMs = 1;
  return d1;
}

function wrongCodeFor(invite: string): string {
  return invite === "ZZZZ" ? "YYYY" : "ZZZZ";
}

function registerReq(invite: string, i: number, ip = ATTACKER): Request {
  return accountReq("/v2/account/register", {
    method: "POST",
    ip,
    body: { username: "probe" + i, password: MEMBER_PASSWORD, invite_code: invite },
  });
}

describe("invite guessing under concurrency", () => {
  /**
   * The requirement is three wrong codes from one source, then an hour shut.
   * An attacker does not send them one at a time and wait: it opens all of them
   * at once. If the budget is spent only after the code has been compared,
   * every request in the burst compares against the live code and the fourth,
   * fifth and sixth guesses are free.
   */
  test("a burst of wrong codes spends a strike each and stops at the limit", async () => {
    const d1 = slowD1();
    const env = testEnv({ d1 });
    const adminCookie = await makeAdmin(env);
    const invite = await inviteOf(env, adminCookie);
    const wrong = wrongCodeFor(invite);
    resetLimits();

    const before = d1.count(SELECT_INVITE_SQL);
    const burst = 6;
    const results = await Promise.all(
      Array.from({ length: burst }, (_, i) => handleAccount(registerReq(wrong, i), env, 1_700_000)),
    );

    // The property that matters: only three of the six guesses ever reach the
    // stored code. The rest are refused by the budget before it is read, so the
    // extra concurrency buys the attacker no extra comparisons.
    expect(d1.count(SELECT_INVITE_SQL) - before).toBe(AUTH_LOCKOUT_STRIKES);

    // Every one of them is refused, and none of them is told anything else.
    const codes = (await Promise.all(results.map((r) => bodyOf(r)))).map(
      (b) => (b.error as { code: string }).code,
    );
    expect(codes.every((c) => c === "bad_invite" || c === "locked_out")).toBe(true);
    expect(results.every((r) => r?.status === 401 || r?.status === 429)).toBe(true);
    expect(d1.accounts.users.size).toBe(1);

    // The ledger holds exactly the strikes that were granted, not one per
    // request that happened to be in flight when the burst landed.
    expect(await countFailures(d1, await ipKeyOf(env), 1_700_000)).toBe(AUTH_LOCKOUT_STRIKES);
    expect(await countFailures(d1, GLOBAL_V1, 1_700_000)).toBe(AUTH_LOCKOUT_STRIKES);
  });

  test("the correct code no longer helps the source once the burst has shut it", async () => {
    const d1 = slowD1();
    const env = testEnv({ d1 });
    const adminCookie = await makeAdmin(env);
    const invite = await inviteOf(env, adminCookie);
    resetLimits();

    await Promise.all(
      Array.from({ length: 6 }, (_, i) =>
        handleAccount(registerReq(wrongCodeFor(invite), i), env, 1_710_000),
      ),
    );

    const honest = await handleAccount(registerReq(invite, 9), env, 1_710_001);
    expect(honest?.status).toBe(429);
    expect(await bodyOf(honest)).toEqual({ ok: false, error: { code: "locked_out" } });
    expect(honest!.headers.get("Retry-After")).toBe(String(AUTH_LOCKOUT_MS / 1000));
    expect(d1.accounts.users.size).toBe(1);

    // An hour later the source is clean again, without an admin touching it.
    const later = await handleAccount(registerReq(invite, 10), env, 1_710_001 + AUTH_LOCKOUT_MS + 1);
    expect(later?.status).toBe(201);
  });

  /**
   * A correct code must leave the ledger as it found it, or a client that
   * registers a few devices in quick succession would talk itself into an hour
   * of lockout. Holding the strike only for the length of the comparison means
   * a burst can momentarily fill the budget, so the refund has to be complete:
   * nothing persists, and the next attempt is served immediately.
   */
  test("concurrent correct codes leave no strike behind", async () => {
    const d1 = slowD1();
    const env = testEnv({ d1 });
    const adminCookie = await makeAdmin(env);
    const invite = await inviteOf(env, adminCookie);
    resetLimits();

    const results = await Promise.all(
      Array.from({ length: 4 }, (_, i) => handleAccount(registerReq(invite, i), env, 1_720_000)),
    );
    // Whoever got through registered; nobody was told the code was wrong.
    expect(results.some((r) => r?.status === 201)).toBe(true);
    expect(results.every((r) => r?.status === 201 || r?.status === 429)).toBe(true);

    // Every reservation a correct code took has been handed back, on both the
    // source budget and the shared global one.
    expect(await countFailures(d1, await ipKeyOf(env), 1_720_000)).toBe(0);
    expect(await countFailures(d1, GLOBAL_V1, 1_720_000)).toBe(0);
    expect(d1.accounts.failures.length).toBe(0);

    // So a request that lost the burst succeeds on its very next try, rather
    // than being shut out for the hour a genuine guesser would be.
    resetLimits();
    const retry = await handleAccount(registerReq(invite, 9), env, 1_720_001);
    expect(retry?.status).toBe(201);
  });

  /**
   * Two sources guessing at the same time must not share a budget: the per
   * source count is what the product promises, and a neighbour's burst cannot
   * be allowed to shut an innocent address out.
   */
  test("one source's burst does not spend another source's budget", async () => {
    const d1 = slowD1();
    const env = testEnv({ d1 });
    const adminCookie = await makeAdmin(env);
    const invite = await inviteOf(env, adminCookie);
    const wrong = wrongCodeFor(invite);
    resetLimits();

    await Promise.all(
      Array.from({ length: 6 }, (_, i) => handleAccount(registerReq(wrong, i, ATTACKER), env, 1_730_000)),
    );

    resetLimits();
    const neighbour = await handleAccount(registerReq(invite, 9, "203.0.113.151"), env, 1_730_001);
    expect(neighbour?.status).toBe(201);
  });

  /**
   * The global ceiling exists because four letters fall to a guess spread over
   * many addresses. A success must clear the source that succeeded and nothing
   * else, or one registration resets the whole campaign.
   */
  test("a success clears its own source but not the global invite budget", async () => {
    const d1 = slowD1();
    const env = testEnv({ d1 });
    const adminCookie = await makeAdmin(env);
    const invite = await inviteOf(env, adminCookie);
    const wrong = wrongCodeFor(invite);
    resetLimits();

    await handleAccount(registerReq(wrong, 0), env, 1_740_000);
    expect(await countFailures(d1, GLOBAL_V1, 1_740_000)).toBe(1);

    resetLimits();
    const ok = await handleAccount(registerReq(invite, 1, "203.0.113.152"), env, 1_740_001);
    expect(ok?.status).toBe(201);
    expect(await countFailures(d1, GLOBAL_V1, 1_740_001)).toBe(1);
  });
});

describe("the reservation primitive", () => {
  /**
   * The budget is handed out by position, not by arrival. Six callers at once
   * must see six distinct positions, and only the first three may spend.
   */
  test("concurrent reservations take distinct positions", async () => {
    const d1 = slowD1();
    const taken = await Promise.all(
      Array.from({ length: 6 }, () => reserveFailureBudget(d1, "ip:burst", 1_800_000)),
    );

    const granted = taken.filter((t) => t.granted);
    expect(granted.length).toBe(AUTH_LOCKOUT_STRIKES);
    expect(granted.map((t) => t.strikes).sort((a, b) => a - b)).toEqual([1, 2, 3]);
    // A refused reservation writes nothing, so the ledger holds only the
    // strikes that were actually granted.
    expect(await countFailures(d1, "ip:burst", 1_800_000)).toBe(AUTH_LOCKOUT_STRIKES);
  });

  test("a reservation is refused once the window is full and granted again after it", async () => {
    const d1 = new FakeD1();
    for (let i = 0; i < AUTH_LOCKOUT_STRIKES; i++) {
      expect((await reserveFailureBudget(d1, "ip:one", 1_810_000 + i)).granted).toBe(true);
    }
    expect((await reserveFailureBudget(d1, "ip:one", 1_810_010)).granted).toBe(false);

    const after = 1_810_010 + AUTH_LOCKOUT_MS + 1;
    const fresh = await reserveFailureBudget(d1, "ip:one", after);
    expect(fresh.granted).toBe(true);
    expect(fresh.strikes).toBe(1);
  });

  /**
   * Reserving must not read the ledger before it writes: the count has to come
   * out of the same round trip as the insert, or the window reopens.
   */
  test("a reservation is one round trip", async () => {
    const d1 = new FakeD1();
    d1.statements = [];
    await reserveFailureBudget(d1, "ip:trip", 1_820_000);
    // The count is read inside the batch that wrote the row, never before it.
    const counts = d1.statements.filter((s) => s === COUNT_AUTH_FAILURES_SQL);
    expect(counts.length).toBe(1);
    expect(d1.statements.indexOf(COUNT_AUTH_FAILURES_SQL)).toBeGreaterThan(0);
  });

  /**
   * The global invite budget is one subject shared by every source, so refunds
   * on it collide. A release must take back the exact row its own reservation
   * wrote, or an honest registration hands an attacker a strike back.
   */
  test("a release returns only the row its own reservation took", async () => {
    const d1 = new FakeD1();
    const at = 1_830_000;
    const mine = await reserveFailureBudget(d1, GLOBAL_V1, at, 10);
    const theirs = await reserveFailureBudget(d1, GLOBAL_V1, at, 10);
    expect(mine.granted && theirs.granted).toBe(true);
    expect(mine.id).not.toBe(theirs.id);

    await releaseFailureBudget(d1, mine);
    // The other source's strike, taken in the same millisecond on the same
    // subject, is untouched.
    expect(await countFailures(d1, GLOBAL_V1, at - 1)).toBe(1);
    expect(d1.accounts.failures.map((f) => f.id)).toEqual([theirs.id]);
  });

  test("a refused reservation releases nothing", async () => {
    const d1 = new FakeD1();
    for (let i = 0; i < AUTH_LOCKOUT_STRIKES; i++) {
      await reserveFailureBudget(d1, "ip:full", 1_840_000 + i);
    }
    const refused = await reserveFailureBudget(d1, "ip:full", 1_840_010);
    expect(refused.granted).toBe(false);

    // Releasing a reservation that was never granted must not hand back a
    // strike someone else is paying for.
    await releaseFailureBudget(d1, refused);
    expect(await countFailures(d1, "ip:full", 1_840_000 - 1)).toBe(AUTH_LOCKOUT_STRIKES);
  });
});

async function ipKeyOf(env: ReturnType<typeof testEnv>): Promise<string> {
  const { sourceSubject } = await import("./account-auth.ts");
  return sourceSubject(env.IP_HASH_PEPPER, "invite", "203.0.113.150");
}
