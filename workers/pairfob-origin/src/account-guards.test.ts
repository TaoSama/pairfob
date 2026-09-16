import { beforeEach, describe, expect, test } from "bun:test";
import { handleAccount } from "./account.ts";
import { inviteGlobalSubject, newClaimProof } from "./account-auth.ts";
import { countFailures, getInvite, spendFailureBudget } from "./account-store.ts";
import { AUTH_LOCKOUT_STRIKES, INVITE_GLOBAL_STRIKES } from "./constants.ts";
import { PASSWORD_ITERATIONS, PASSWORD_ITERATIONS_MAX } from "./crypto.ts";
import { resetLimits } from "./limits.ts";
import { FakeD1 } from "./testutil/fake-d1.ts";
import { testEnv } from "./testutil/make-room.ts";
import {
  ADMIN_PASSWORD,
  MEMBER_PASSWORD,
  OPERATOR_TOKEN,
  SERVICE_TOKEN,
  accountReq,
  bodyOf,
  daemonIdOf,
  enrollDaemonId,
  inviteOf,
  makeAdmin,
  makeMember,
  proofFor,
} from "./testutil/account-harness.ts";

beforeEach(() => resetLimits());

describe("bootstrap credential separation", () => {
  test("the relay operator token does not open the first account", async () => {
    const d1 = new FakeD1();
    const env = testEnv({ d1 });
    expect(env.OPERATOR_TOKEN).not.toBe(env.BOOTSTRAP_SERVICE_TOKEN);

    const res = await handleAccount(
      accountReq("/v2/account/bootstrap", {
        method: "POST",
        body: { service_token: OPERATOR_TOKEN, password: ADMIN_PASSWORD },
      }),
      env,
      1_000_000,
    );
    expect(res?.status).toBe(401);
    expect(res!.headers.get("Set-Cookie")).toBeNull();
    expect(d1.accounts.users.size).toBe(0);
  });

  test("an unset bootstrap token closes the route rather than matching an empty string", async () => {
    const d1 = new FakeD1();
    const env = testEnv({ d1 });
    env.BOOTSTRAP_SERVICE_TOKEN = "";
    const res = await handleAccount(
      accountReq("/v2/account/bootstrap", {
        method: "POST",
        body: { service_token: "", password: ADMIN_PASSWORD },
      }),
      env,
      1_000_000,
    );
    expect(res?.status).toBe(503);
    expect(d1.accounts.users.size).toBe(0);
  });

  test("a replayed bootstrap is refused before the token is compared", async () => {
    const d1 = new FakeD1();
    const env = testEnv({ d1 });
    await makeAdmin(env);
    const before = d1.accounts.failures.length;

    // A wrong token on a closed route must read as already_initialized, not
    // bad_credentials: otherwise the two answers separate a wrong guess from a
    // right one long after bootstrap is over.
    const res = await handleAccount(
      accountReq("/v2/account/bootstrap", {
        method: "POST",
        body: { service_token: "definitely-not-the-token", password: ADMIN_PASSWORD },
      }),
      env,
      1_000_010,
    );
    expect(res?.status).toBe(409);
    expect(await bodyOf(res)).toEqual({ ok: false, error: { code: "already_initialized" } });
    expect(d1.accounts.failures.length).toBe(before);
  });
});

describe("password derivation cost", () => {
  test("the iteration count stays inside the per-request CPU ceiling", () => {
    expect(PASSWORD_ITERATIONS).toBeLessThanOrEqual(PASSWORD_ITERATIONS_MAX);
    expect(PASSWORD_ITERATIONS_MAX).toBeLessThanOrEqual(100_000);
    expect(PASSWORD_ITERATIONS).toBeGreaterThanOrEqual(50_000);
  });

  test("a stored hash above the ceiling never verifies", async () => {
    const { verifyPassword } = await import("./crypto.ts");
    const inflated = `pbkdf2-sha256$${PASSWORD_ITERATIONS_MAX + 1}$${"ab".repeat(16)}$${"cd".repeat(32)}`;
    expect(await verifyPassword(inflated, ADMIN_PASSWORD)).toBe(false);
  });
});

describe("invite code failure budgets", () => {
  test("concurrent strikes each see their own position, not a stale count", async () => {
    const d1 = new FakeD1();
    // Six attempts in flight at once. A ledger that counts and then records
    // lets every one of them read zero and answer "first strike"; counting
    // inside the same transaction hands each its true position.
    const counts = await Promise.all(
      Array.from({ length: 6 }, () => spendFailureBudget(d1, "ip:swarm", 1_400_000)),
    );
    expect([...counts].sort((a, b) => a - b)).toEqual([1, 2, 3, 4, 5, 6]);
    expect(d1.accounts.failures.length).toBe(6);
    expect(counts.filter((n) => n >= AUTH_LOCKOUT_STRIKES).length).toBe(4);
  });

  test("a wrong code from one source locks that source out and no other", async () => {
    const d1 = new FakeD1();
    const env = testEnv({ d1 });
    const adminCookie = await makeAdmin(env);
    const invite = await inviteOf(env, adminCookie);
    const attacker = "203.0.113.77";
    const wrong = invite === "ZZZZ" ? "YYYY" : "ZZZZ";

    for (let i = 0; i < AUTH_LOCKOUT_STRIKES; i++) {
      const res = await handleAccount(
        accountReq("/v2/account/register", {
          method: "POST",
          ip: attacker,
          body: { username: "swarm" + i, password: MEMBER_PASSWORD, invite_code: wrong },
        }),
        env,
        1_400_000 + i,
      );
      expect(res?.status === 401 || res?.status === 429).toBe(true);
    }

    // The correct code no longer helps this source.
    const next = await handleAccount(
      accountReq("/v2/account/register", {
        method: "POST",
        ip: attacker,
        body: { username: "swarm9", password: MEMBER_PASSWORD, invite_code: invite },
      }),
      env,
      1_400_020,
    );
    expect(next?.status).toBe(429);
    expect(await bodyOf(next)).toEqual({ ok: false, error: { code: "locked_out" } });
  });

  test("a wrong code spends the global budget and a success does not refund it", async () => {
    const d1 = new FakeD1();
    const env = testEnv({ d1 });
    const adminCookie = await makeAdmin(env);
    const invite = await inviteOf(env, adminCookie);

    const wrong = invite === "ZZZZ" ? "YYYY" : "ZZZZ";
    await handleAccount(
      accountReq("/v2/account/register", {
        method: "POST",
        ip: "203.0.113.120",
        body: { username: "probe", password: MEMBER_PASSWORD, invite_code: wrong },
      }),
      env,
      1_450_000,
    );
    const spent = await countFailures(d1, inviteGlobalSubject(1), 1_450_001);
    expect(spent).toBe(1);

    await makeMember(env, "clark", invite, 1_450_002, "203.0.113.121");
    // A legitimate registration clears only its own source budget; leaving the
    // global one intact is what stops a campaign resetting itself.
    expect(await countFailures(d1, inviteGlobalSubject(1), 1_450_003)).toBe(1);
  });

  test("a guess spread across many sources still suspends the code", async () => {
    const d1 = new FakeD1();
    const env = testEnv({ d1 });
    const adminCookie = await makeAdmin(env);
    const invite = await inviteOf(env, adminCookie);
    const wrong = invite === "ZZZZ" ? "YYYY" : "ZZZZ";

    // One wrong guess per address never trips the per-source lockout, which is
    // exactly the shape the global ceiling exists to catch.
    for (let i = 0; i < INVITE_GLOBAL_STRIKES; i++) {
      resetLimits();
      await handleAccount(
        accountReq("/v2/account/register", {
          method: "POST",
          ip: "198.51.100." + (i + 1),
          body: { username: "wide" + i, password: MEMBER_PASSWORD, invite_code: wrong },
        }),
        env,
        1_460_000 + i,
      );
    }
    expect((await getInvite(d1))!.suspended_at).toBeGreaterThan(0);

    resetLimits();
    const honest = await handleAccount(
      accountReq("/v2/account/register", {
        method: "POST",
        ip: "198.51.100.250",
        body: { username: "honest", password: MEMBER_PASSWORD, invite_code: invite },
      }),
      env,
      1_470_000,
    );
    expect(honest?.status).toBe(409);
    expect(await bodyOf(honest)).toEqual({ ok: false, error: { code: "invite_suspended" } });

    // Rotating is the way back. Lifting the suspension is not enough on its
    // own: the budget that caused it must also be left behind, or the fresh
    // code is refused for the rest of the hour by a ceiling it never spent.
    const rotated = await handleAccount(
      accountReq("/v2/account/invite/rotate", { method: "POST", cookie: adminCookie }),
      env,
      1_470_010,
    );
    expect(rotated?.status).toBe(200);
    expect((await getInvite(d1))!.suspended_at).toBe(0);

    const fresh = String((await bodyOf(rotated)).invite_code);
    resetLimits();
    const after = await handleAccount(
      accountReq("/v2/account/register", {
        method: "POST",
        ip: "198.51.100.251",
        body: { username: "after", password: MEMBER_PASSWORD, invite_code: fresh },
      }),
      env,
      1_470_020,
    );
    expect(after?.status).toBe(201);
  });

  test("wrong passwords never lock the username itself out", async () => {
    const d1 = new FakeD1();
    const env = testEnv({ d1 });
    await makeAdmin(env);

    // Three wrong passwords from one address must not follow the account to a
    // different one, or anyone could lock a known user out everywhere.
    for (let i = 0; i < 5; i++) {
      resetLimits();
      await handleAccount(
        accountReq("/v2/account/login", {
          method: "POST",
          ip: "203.0.113.200",
          body: { username: "admin", password: "wrong" },
        }),
        env,
        1_480_000 + i,
      );
    }
    // Every subject is a hashed source in the sign-in domain. Nothing is keyed
    // by the username, and nothing lands in the invite domain, so a mistyped
    // password neither follows the account around nor spends invite budget.
    for (const row of d1.accounts.failures) {
      expect(row.subject.startsWith("login:ip:")).toBe(true);
      expect(row.subject).not.toContain("admin");
    }

    resetLimits();
    const elsewhere = await handleAccount(
      accountReq("/v2/account/login", {
        method: "POST",
        ip: "203.0.113.201",
        body: { username: "admin", password: ADMIN_PASSWORD },
      }),
      env,
      1_480_010,
    );
    expect(elsewhere?.status).toBe(200);
  });
});

describe("device claim proofs", () => {
  test("a daemon id alone claims nothing", async () => {
    const d1 = new FakeD1();
    const env = testEnv({ d1 });
    const cookie = await makeAdmin(env);
    const daemonId = await enrollDaemonId(env, "41", 2_300_000);

    const res = await handleAccount(
      accountReq("/v2/account/devices", { method: "POST", cookie, body: { daemon_id: daemonId } }),
      env,
      2_300_001,
    );
    expect(res?.status).toBe(403);
    expect(d1.accounts.devices.size).toBe(0);
  });

  test("a forged proof is refused", async () => {
    const d1 = new FakeD1();
    const env = testEnv({ d1 });
    const cookie = await makeAdmin(env);
    const daemonId = await enrollDaemonId(env, "42", 2_310_000);

    const res = await handleAccount(
      accountReq("/v2/account/devices", {
        method: "POST",
        cookie,
        body: { daemon_id: daemonId, claim_proof: newClaimProof() },
      }),
      env,
      2_310_001,
    );
    expect(res?.status).toBe(403);
    expect(d1.accounts.devices.size).toBe(0);
  });

  test("a proof is single use", async () => {
    const d1 = new FakeD1();
    const env = testEnv({ d1 });
    const cookie = await makeAdmin(env);
    const first = await enrollDaemonId(env, "43", 2_320_000);
    const second = await enrollDaemonId(env, "44", 2_320_001);
    const proof = await proofFor(d1, "admin", first, 2_320_002);

    expect(
      (await handleAccount(
        accountReq("/v2/account/devices", {
          method: "POST",
          cookie,
          body: { daemon_id: first, claim_proof: proof },
        }),
        env,
        2_320_003,
      ))?.status,
    ).toBe(201);

    // The same proof against a different device, and a replay against its own,
    // both fail: the row is gone.
    const elsewhere = await handleAccount(
      accountReq("/v2/account/devices", {
        method: "POST",
        cookie,
        body: { daemon_id: second, claim_proof: proof },
      }),
      env,
      2_320_004,
    );
    expect(elsewhere?.status).toBe(403);
    expect(d1.accounts.devices.size).toBe(1);
  });

  test("an expired proof is refused", async () => {
    const d1 = new FakeD1();
    const env = testEnv({ d1 });
    const cookie = await makeAdmin(env);
    const daemonId = await enrollDaemonId(env, "45", 2_330_000);
    const proof = await proofFor(d1, "admin", daemonId, 2_330_001, 1_000);

    const res = await handleAccount(
      accountReq("/v2/account/devices", {
        method: "POST",
        cookie,
        body: { daemon_id: daemonId, claim_proof: proof },
      }),
      env,
      2_330_001 + 5_000,
    );
    expect(res?.status).toBe(403);
    expect(d1.accounts.devices.size).toBe(0);
  });

  test("a proof issued to another account is refused", async () => {
    const d1 = new FakeD1();
    const env = testEnv({ d1 });
    const adminCookie = await makeAdmin(env);
    const invite = await inviteOf(env, adminCookie);
    const memberCookie = await makeMember(env, "diana", invite, 2_340_000);
    const daemonId = await enrollDaemonId(env, "46", 2_340_001);
    const adminProof = await proofFor(d1, "admin", daemonId, 2_340_002);

    const res = await handleAccount(
      accountReq("/v2/account/devices", {
        method: "POST",
        cookie: memberCookie,
        body: { daemon_id: daemonId, claim_proof: adminProof },
      }),
      env,
      2_340_003,
    );
    expect(res?.status).toBe(403);
    expect(d1.accounts.devices.size).toBe(0);

    // It remains spendable by the account it was actually issued to.
    const owner = await handleAccount(
      accountReq("/v2/account/devices", {
        method: "POST",
        cookie: adminCookie,
        body: { daemon_id: daemonId, claim_proof: adminProof },
      }),
      env,
      2_340_004,
    );
    expect(owner?.status).toBe(201);
  });

  test("a proof for one daemon does not claim another", async () => {
    const d1 = new FakeD1();
    const env = testEnv({ d1 });
    const cookie = await makeAdmin(env);
    const mine = await enrollDaemonId(env, "47", 2_350_000);
    const theirs = await enrollDaemonId(env, "48", 2_350_001);
    const proof = await proofFor(d1, "admin", mine, 2_350_002);

    const res = await handleAccount(
      accountReq("/v2/account/devices", {
        method: "POST",
        cookie,
        body: { daemon_id: theirs, claim_proof: proof },
      }),
      env,
      2_350_003,
    );
    expect(res?.status).toBe(403);
    expect(d1.accounts.devices.size).toBe(0);
  });

  test("two accounts racing one device leave exactly one owner", async () => {
    const d1 = new FakeD1();
    const env = testEnv({ d1 });
    const adminCookie = await makeAdmin(env);
    const invite = await inviteOf(env, adminCookie);
    const memberCookie = await makeMember(env, "diana", invite, 2_360_000);
    const daemonId = await enrollDaemonId(env, "49", 2_360_001);
    const adminProof = await proofFor(d1, "admin", daemonId, 2_360_002);
    const memberProof = await proofFor(d1, "diana", daemonId, 2_360_002);

    const [a, b] = await Promise.all([
      handleAccount(
        accountReq("/v2/account/devices", {
          method: "POST",
          cookie: adminCookie,
          body: { daemon_id: daemonId, claim_proof: adminProof },
        }),
        env,
        2_360_003,
      ),
      handleAccount(
        accountReq("/v2/account/devices", {
          method: "POST",
          cookie: memberCookie,
          body: { daemon_id: daemonId, claim_proof: memberProof },
        }),
        env,
        2_360_003,
      ),
    ]);

    const created = [a, b].filter((r) => r?.status === 201).length;
    expect(created).toBe(1);
    expect(d1.accounts.devices.size).toBe(1);
  });

  test("an unauthenticated caller cannot claim even with a well-formed proof", async () => {
    const d1 = new FakeD1();
    const env = testEnv({ d1 });
    await makeAdmin(env);
    const daemonId = daemonIdOf("50");

    const res = await handleAccount(
      accountReq("/v2/account/devices", {
        method: "POST",
        body: { daemon_id: daemonId, claim_proof: newClaimProof() },
      }),
      env,
      2_370_000,
    );
    expect(res?.status).toBe(401);
    expect(d1.accounts.devices.size).toBe(0);
  });
});
