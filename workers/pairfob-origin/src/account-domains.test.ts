import { beforeEach, describe, expect, test } from "bun:test";
import { handleAccount } from "./account.ts";
import { inviteGlobalSubject, sourceSubject } from "./account-auth.ts";
import { countFailures, getInvite, lockedUntil } from "./account-store.ts";
import { AUTH_LOCKOUT_MS, AUTH_LOCKOUT_STRIKES, INVITE_GLOBAL_STRIKES } from "./constants.ts";
import { resetLimits } from "./limits.ts";
import { FakeD1 } from "./testutil/fake-d1.ts";
import { testEnv } from "./testutil/make-room.ts";
import {
  ADMIN_PASSWORD,
  MEMBER_PASSWORD,
  SERVICE_TOKEN,
  accountReq,
  bodyOf,
  inviteOf,
  makeAdmin,
  type TestEnv,
} from "./testutil/account-harness.ts";

beforeEach(() => resetLimits());

const SOURCE = "203.0.113.170";

function wrongCodeFor(invite: string): string {
  return invite === "ZZZZ" ? "YYYY" : "ZZZZ";
}

async function world(): Promise<{ d1: FakeD1; env: TestEnv; admin: string; invite: string }> {
  const d1 = new FakeD1();
  const env = testEnv({ d1 });
  const admin = await makeAdmin(env, 1_000_000);
  const invite = await inviteOf(env, admin, 1_000_001);
  resetLimits();
  return { d1, env, admin, invite };
}

/** Each of these spends from a different domain's budget. */
function tryInvite(env: TestEnv, code: string, i: number, now: number, ip = SOURCE) {
  resetLimits();
  return handleAccount(
    accountReq("/v2/account/register", {
      method: "POST",
      ip,
      body: { username: "probe" + i + "_" + now, password: MEMBER_PASSWORD, invite_code: code },
    }),
    env,
    now,
  );
}

function tryLogin(env: TestEnv, password: string, now: number, ip = SOURCE) {
  resetLimits();
  return handleAccount(
    accountReq("/v2/account/login", { method: "POST", ip, body: { username: "admin", password } }),
    env,
    now,
  );
}

function tryBootstrap(env: TestEnv, token: string, now: number, ip = SOURCE) {
  resetLimits();
  return handleAccount(
    accountReq("/v2/account/bootstrap", {
      method: "POST",
      ip,
      body: { service_token: token, password: ADMIN_PASSWORD },
    }),
    env,
    now,
  );
}

describe("failure budgets are kept per credential kind", () => {
  /**
   * The reported hole. With one bucket per source, a successful sign-in cleared
   * the strikes earned by wrong invite codes, so two guesses and a login, over
   * and over, never reached three. Six rounds is twelve wrong codes: four times
   * the budget.
   */
  test("alternating wrong codes with a correct login never resets the invite budget", async () => {
    const { d1, env, invite } = await world();
    const wrong = wrongCodeFor(invite);
    let at = 1_100_000;
    let refused = 0;

    for (let round = 0; round < 6; round++) {
      for (let i = 0; i < 2; i++) {
        const res = await tryInvite(env, wrong, round * 2 + i, (at += 10));
        if (res?.status === 429) refused++;
      }
      // The correct password is accepted every time: signing in is not the
      // thing being rate limited, and this account is innocent.
      expect((await tryLogin(env, ADMIN_PASSWORD, (at += 10)))?.status).toBe(200);
    }

    // Twelve wrong codes cost the source its hour, and the login never bought
    // it back. Most of the attempts never reached the comparison at all.
    expect(refused).toBeGreaterThan(0);
    const inviteKey = await sourceSubject(env.IP_HASH_PEPPER, "invite", SOURCE);
    expect(await lockedUntil(d1, inviteKey, at)).toBeGreaterThan(at);

    // And the source is still shut even presenting the right code.
    expect((await tryInvite(env, invite, 99, (at += 10)))?.status).toBe(429);
  });

  test("a locked invite source can still sign in and use its devices", async () => {
    const { env, invite } = await world();
    const wrong = wrongCodeFor(invite);
    let at = 1_200_000;
    for (let i = 0; i < AUTH_LOCKOUT_STRIKES; i++) await tryInvite(env, wrong, i, (at += 10));
    expect((await tryInvite(env, invite, 9, (at += 10)))?.status).toBe(429);

    // Guessing invite codes says nothing about whether this address holds a
    // legitimate account, so the global protection must not ground existing
    // users. Only registration from here is shut.
    expect((await tryLogin(env, ADMIN_PASSWORD, (at += 10)))?.status).toBe(200);
  });

  test("wrong passwords do not spend the invite budget", async () => {
    const { d1, env, invite } = await world();
    let at = 1_300_000;
    for (let i = 0; i < AUTH_LOCKOUT_STRIKES + 2; i++) {
      await tryLogin(env, "wrong", (at += 10));
    }
    const inviteKey = await sourceSubject(env.IP_HASH_PEPPER, "invite", SOURCE);
    expect(await countFailures(d1, inviteKey, at)).toBe(0);
    expect(await lockedUntil(d1, inviteKey, at)).toBe(0);
    expect(await countFailures(d1, inviteGlobalSubject(1), at)).toBe(0);

    // So registration from this address, with the right code, still works.
    expect((await tryInvite(env, invite, 1, (at += 10)))?.status).toBe(201);
  });

  test("wrong invite codes do not lock the source out of signing in", async () => {
    const { d1, env, invite } = await world();
    const wrong = wrongCodeFor(invite);
    let at = 1_350_000;
    for (let i = 0; i < AUTH_LOCKOUT_STRIKES + 2; i++) await tryInvite(env, wrong, i, (at += 10));

    const loginKey = await sourceSubject(env.IP_HASH_PEPPER, "login", SOURCE);
    expect(await countFailures(d1, loginKey, at)).toBe(0);
    expect((await tryLogin(env, ADMIN_PASSWORD, (at += 10)))?.status).toBe(200);
  });

  test("a wrong bootstrap token spends neither the login nor the invite budget", async () => {
    const d1 = new FakeD1();
    const env = testEnv({ d1 });
    let at = 1_400_000;
    for (let i = 0; i < AUTH_LOCKOUT_STRIKES; i++) {
      expect((await tryBootstrap(env, "not-the-token", (at += 10)))?.status).toBe(401);
    }
    expect((await tryBootstrap(env, SERVICE_TOKEN, (at += 10)))?.status).toBe(429);

    for (const domain of ["login", "invite"] as const) {
      const key = await sourceSubject(env.IP_HASH_PEPPER, domain, SOURCE);
      expect(await countFailures(d1, key, at)).toBe(0);
      expect(await lockedUntil(d1, key, at)).toBe(0);
    }
  });
});

describe("the hour runs from the failure that caused it", () => {
  /**
   * Three strikes inside a trailing hour is not the same rule as an hour from
   * the third strike. Under the first, the oldest strike ages out 1ms after the
   * window opens and the source is free again, having served far less than the
   * hour it was sentenced to.
   */
  test("a source stays shut for the full hour after its third wrong code", async () => {
    const { d1, env, invite } = await world();
    const wrong = wrongCodeFor(invite);
    const first = 1_500_000;

    // Three failures spread across most of an hour, so the first is nearly out
    // of the trailing window by the time the third lands.
    await tryInvite(env, wrong, 0, first);
    await tryInvite(env, wrong, 1, first + AUTH_LOCKOUT_MS / 2);
    const third = first + AUTH_LOCKOUT_MS - 1_000;
    await tryInvite(env, wrong, 2, third);

    const key = await sourceSubject(env.IP_HASH_PEPPER, "invite", SOURCE);
    expect(await lockedUntil(d1, key, third)).toBe(third + AUTH_LOCKOUT_MS);

    // The instant the first strike leaves the window, a count-based rule would
    // read two and let this through.
    const slidOut = first + AUTH_LOCKOUT_MS + 1;
    expect(slidOut).toBeLessThan(third + AUTH_LOCKOUT_MS);
    expect((await tryInvite(env, invite, 3, slidOut))?.status).toBe(429);

    // Released only once its own hour is actually up.
    expect((await tryInvite(env, invite, 4, third + AUTH_LOCKOUT_MS + 1))?.status).toBe(201);
  });

  test("a burst of correct codes leaves no ban behind", async () => {
    const d1 = new FakeD1();
    d1.latencyMs = 1;
    const env = testEnv({ d1 });
    const admin = await makeAdmin(env, 1_600_000);
    const invite = await inviteOf(env, admin, 1_600_001);
    resetLimits();

    // Reservations exist to bound requests still in flight, before anyone knows
    // whether the credential is wrong. Losing that race is not a failure, so
    // the losers must leave no strike and certainly no ban.
    const at = 1_600_010;
    const results = await Promise.all(
      Array.from({ length: 5 }, (_, i) =>
        handleAccount(
          accountReq("/v2/account/register", {
            method: "POST",
            ip: SOURCE,
            body: { username: "rush" + i, password: MEMBER_PASSWORD, invite_code: invite },
          }),
          env,
          at,
        ),
      ),
    );
    expect(results.some((r) => r?.status === 201)).toBe(true);
    expect(results.every((r) => r?.status === 201 || r?.status === 429)).toBe(true);

    const key = await sourceSubject(env.IP_HASH_PEPPER, "invite", SOURCE);
    expect(await lockedUntil(d1, key, at)).toBe(0);
    expect(await countFailures(d1, key, at)).toBe(0);
    expect(d1.accounts.failures.length).toBe(0);
  });
});

describe("rotating the invite code", () => {
  /**
   * The code and the budget protecting it are one unit. Rotating lifted the
   * suspension but left the exhausted global counter in place, so the fresh
   * code was refused for the rest of the hour.
   */
  test("a new code gets a new global budget", async () => {
    const { d1, env, admin, invite } = await world();
    const wrong = wrongCodeFor(invite);
    let at = 1_700_000;

    // One guess per address: never enough to trip a per-source lockout, which
    // is exactly the shape the global ceiling exists to catch.
    for (let i = 0; i < INVITE_GLOBAL_STRIKES; i++) {
      await tryInvite(env, wrong, i, (at += 10), "198.51.100." + (i + 1));
    }
    expect((await getInvite(d1))!.suspended_at).toBeGreaterThan(0);
    expect((await tryInvite(env, invite, 90, (at += 10), "198.51.100.240"))?.status).toBe(409);

    const rotated = await handleAccount(
      accountReq("/v2/account/invite/rotate", { method: "POST", cookie: admin }),
      env,
      (at += 10),
    );
    expect(rotated?.status).toBe(200);
    const body = await bodyOf(rotated);
    const fresh = String(body.invite_code);
    expect(body.version).toBe(2);

    // A clean source registers immediately with the new code.
    expect((await tryInvite(env, fresh, 91, (at += 10), "198.51.100.241"))?.status).toBe(201);
    // The old code is refused, and being wrong now costs the new budget, not
    // the spent one.
    expect((await tryInvite(env, invite, 92, (at += 10), "198.51.100.242"))?.status).toBe(401);
    expect(await countFailures(d1, inviteGlobalSubject(2), at)).toBe(1);
    expect((await getInvite(d1))!.suspended_at).toBe(0);
  });

  test("rotating does not forgive a source serving its hour", async () => {
    const { d1, env, admin, invite } = await world();
    const wrong = wrongCodeFor(invite);
    let at = 1_800_000;
    for (let i = 0; i < AUTH_LOCKOUT_STRIKES; i++) await tryInvite(env, wrong, i, (at += 10));

    const banned = at;
    const rotated = await handleAccount(
      accountReq("/v2/account/invite/rotate", { method: "POST", cookie: admin }),
      env,
      (at += 10),
    );
    const fresh = String((await bodyOf(rotated)).invite_code);

    // An address that guessed is still an address that guessed. Rotating is an
    // administrative act about the code, not an amnesty for the guesser.
    expect((await tryInvite(env, fresh, 90, (at += 10)))?.status).toBe(429);
    const key = await sourceSubject(env.IP_HASH_PEPPER, "invite", SOURCE);
    expect(await lockedUntil(d1, key, at)).toBeGreaterThan(banned);

    // A different address is unaffected.
    expect((await tryInvite(env, fresh, 91, (at += 10), "198.51.100.243"))?.status).toBe(201);
  });

  /**
   * The rotator is an ordinary account that happens to hold the code, and it
   * may be sitting at the very address that just spent its budget guessing.
   * Rotating must not be a way to lift your own ban.
   */
  test("an admin cannot rotate away a ban on its own address", async () => {
    const { d1, env, invite } = await world();
    const wrong = wrongCodeFor(invite);
    let at = 1_850_000;
    for (let i = 0; i < AUTH_LOCKOUT_STRIKES; i++) await tryInvite(env, wrong, i, (at += 10));

    // The admin signs in from the banned address and rotates from there.
    const login = await handleAccount(
      accountReq("/v2/account/login", {
        method: "POST",
        ip: SOURCE,
        body: { username: "admin", password: ADMIN_PASSWORD },
      }),
      env,
      (at += 10),
    );
    expect(login?.status).toBe(200);
    const cookie = (login!.headers.get("Set-Cookie") ?? "").split(";")[0];

    resetLimits();
    const rotated = await handleAccount(
      accountReq("/v2/account/invite/rotate", { method: "POST", ip: SOURCE, cookie }),
      env,
      (at += 10),
    );
    expect(rotated?.status).toBe(200);
    const fresh = String((await bodyOf(rotated)).invite_code);

    const key = await sourceSubject(env.IP_HASH_PEPPER, "invite", SOURCE);
    expect(await lockedUntil(d1, key, at)).toBeGreaterThan(at);
    expect((await tryInvite(env, fresh, 90, (at += 10)))?.status).toBe(429);
  });

  /**
   * A request that read the old code and only reaches its verdict after the
   * rotation must not suspend the code that replaced it, and must not spend the
   * budget that protects it.
   */
  test("a wrong-code request that lands after a rotation cannot touch the new code", async () => {
    const { d1, env, admin, invite } = await world();
    const wrong = wrongCodeFor(invite);
    let at = 1_900_000;

    // Burn the old budget down to its last strike, so the straggler below is
    // the one that would have suspended the code it was comparing against.
    for (let i = 0; i < INVITE_GLOBAL_STRIKES - 1; i++) {
      await tryInvite(env, wrong, i, (at += 10), "198.51.100." + (i + 1));
    }
    expect((await getInvite(d1))!.suspended_at).toBe(0);

    // The straggler reserves against version 1 and pauses before comparing.
    d1.accounts.pauseNextInviteRead();
    const straggler = tryInvite(env, wrong, 80, (at += 10), "198.51.100.200");
    await d1.accounts.inviteReadReached();

    const rotated = await handleAccount(
      accountReq("/v2/account/invite/rotate", { method: "POST", cookie: admin }),
      env,
      (at += 10),
    );
    const fresh = String((await bodyOf(rotated)).invite_code);
    d1.accounts.resumeInviteRead();
    await straggler;

    // It exhausted version 1's budget, but version 1 is gone. The new code is
    // live, unsuspended, and its own budget is untouched.
    expect((await getInvite(d1))!.suspended_at).toBe(0);
    expect((await getInvite(d1))!.version).toBe(2);
    expect(await countFailures(d1, inviteGlobalSubject(2), at)).toBe(0);
    expect((await tryInvite(env, fresh, 81, (at += 10), "198.51.100.244"))?.status).toBe(201);
  });
});
