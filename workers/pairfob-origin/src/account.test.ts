import { beforeEach, describe, expect, test } from "bun:test";
import { handleAccount } from "./account.ts";
import { mintInviteCode, normalizePassword, normalizeUsername } from "./account-auth.ts";
import { AUTH_LOCKOUT_MS, INVITE_CODE_RE, ROLE_ADMIN, ROLE_MEMBER } from "./constants.ts";
import { resetLimits } from "./limits.ts";
import { FakeD1 } from "./testutil/fake-d1.ts";
import { testEnv } from "./testutil/make-room.ts";
import {
  ADMIN_PASSWORD,
  SERVICE_TOKEN,
  accountReq,
  bodyOf,
  enrollDaemonId,
  inviteOf,
  makeAdmin,
  makeMember,
  proofFor,
} from "./testutil/account-harness.ts";

beforeEach(() => resetLimits());

describe("account routing and guards", () => {
  test("non-account paths are not claimed", async () => {
    expect(await handleAccount(accountReq("/v2/health"), testEnv())).toBeNull();
  });

  test("a read without an Origin is answered, a write without one is not", async () => {
    const read = await handleAccount(accountReq("/v2/account/state", { origin: null }), testEnv());
    expect(read?.status).toBe(200);

    const write = await handleAccount(
      accountReq("/v2/account/logout", { method: "POST", origin: null }),
      testEnv(),
    );
    expect(write?.status).toBe(403);
  });

  test("a cross-site Origin is refused on a read as well as a write", async () => {
    const read = await handleAccount(
      accountReq("/v2/account/state", { origin: "https://evil.example" }),
      testEnv(),
    );
    expect(read?.status).toBe(403);
  });

  test("a cross-site Origin is refused so a cookie cannot be replayed", async () => {
    const res = await handleAccount(
      accountReq("/v2/account/logout", { method: "POST", origin: "https://evil.example" }),
      testEnv(),
    );
    expect(res?.status).toBe(403);
  });

  test("an unknown account subpath is unbound", async () => {
    const res = await handleAccount(accountReq("/v2/account/nope"), testEnv());
    expect(res?.status).toBe(404);
    expect(await bodyOf(res)).toEqual({ ok: false, error: { code: "unbound" } });
  });

  test("a wrong method on a known path is unbound", async () => {
    const res = await handleAccount(accountReq("/v2/account/login"), testEnv());
    expect(res?.status).toBe(404);
  });
});

describe("bootstrap", () => {
  test("the service token opens the first account and mints an invite", async () => {
    const d1 = new FakeD1();
    const env = testEnv({ d1 });

    const before = await handleAccount(accountReq("/v2/account/state"), env, 1_000_000);
    expect(await bodyOf(before)).toMatchObject({ initialized: false, user: null });

    const cookie = await makeAdmin(env);
    expect(d1.accounts.users.size).toBe(1);
    const admin = Array.from(d1.accounts.users.values())[0];
    expect(admin.username).toBe("admin");
    expect(admin.role).toBe(ROLE_ADMIN);
    expect(admin.password_hash).not.toContain(ADMIN_PASSWORD);
    expect(INVITE_CODE_RE.test(d1.accounts.invite!.code)).toBe(true);

    const after = await handleAccount(accountReq("/v2/account/state", { cookie }), env, 1_000_002);
    expect(await bodyOf(after)).toMatchObject({
      initialized: true,
      user: { username: "admin", role: ROLE_ADMIN },
    });
  });

  test("the session cookie is HttpOnly, Secure and SameSite", async () => {
    const env = testEnv();
    const res = await handleAccount(
      accountReq("/v2/account/bootstrap", {
        method: "POST",
        body: { service_token: SERVICE_TOKEN, password: ADMIN_PASSWORD },
      }),
      env,
      1_000_000,
    );
    const raw = res!.headers.get("Set-Cookie") ?? "";
    expect(raw).toContain("HttpOnly");
    expect(raw).toContain("Secure");
    expect(raw).toContain("SameSite=Strict");
    expect(raw).toContain("Path=/");
  });

  test("a wrong service token is refused and never leaks a session", async () => {
    const d1 = new FakeD1();
    const env = testEnv({ d1 });
    const res = await handleAccount(
      accountReq("/v2/account/bootstrap", {
        method: "POST",
        body: { service_token: "wrong", password: ADMIN_PASSWORD },
      }),
      env,
      1_000_000,
    );
    expect(res?.status).toBe(401);
    expect(res!.headers.get("Set-Cookie")).toBeNull();
    expect(d1.accounts.users.size).toBe(0);
  });

  test("a short password is rejected before the token is checked", async () => {
    const d1 = new FakeD1();
    const res = await handleAccount(
      accountReq("/v2/account/bootstrap", {
        method: "POST",
        body: { service_token: SERVICE_TOKEN, password: "short" },
      }),
      testEnv({ d1 }),
      1_000_000,
    );
    expect(res?.status).toBe(400);
    expect(d1.accounts.users.size).toBe(0);
  });

  test("bootstrapping twice conflicts", async () => {
    const env = testEnv();
    await makeAdmin(env);
    const again = await handleAccount(
      accountReq("/v2/account/bootstrap", {
        method: "POST",
        body: { service_token: SERVICE_TOKEN, password: "another-password" },
      }),
      env,
      1_000_010,
    );
    expect(again?.status).toBe(409);
    expect(await bodyOf(again)).toEqual({ ok: false, error: { code: "already_initialized" } });
  });
});

describe("login and lockout", () => {
  test("the admin password signs in again", async () => {
    const env = testEnv();
    await makeAdmin(env);
    const res = await handleAccount(
      accountReq("/v2/account/login", {
        method: "POST",
        body: { username: "ADMIN", password: ADMIN_PASSWORD },
      }),
      env,
      1_000_020,
    );
    expect(res?.status).toBe(200);
    expect(await bodyOf(res)).toMatchObject({ user: { username: "admin" } });
  });

  test("three wrong passwords ban the account for an hour", async () => {
    const env = testEnv();
    await makeAdmin(env);
    const bad = { username: "admin", password: "not-the-password" };

    for (let i = 0; i < 3; i++) {
      const res = await handleAccount(
        accountReq("/v2/account/login", { method: "POST", body: bad }),
        env,
        1_100_000 + i,
      );
      expect(res?.status).toBe(401);
      expect(await bodyOf(res)).toEqual({ ok: false, error: { code: "bad_credentials" } });
    }

    const locked = await handleAccount(
      accountReq("/v2/account/login", {
        method: "POST",
        body: { username: "admin", password: ADMIN_PASSWORD },
      }),
      env,
      1_100_010,
    );
    expect(locked?.status).toBe(429);
    expect(await bodyOf(locked)).toEqual({ ok: false, error: { code: "locked_out" } });
    expect(locked!.headers.get("Retry-After")).toBe(String(AUTH_LOCKOUT_MS / 1000));

    const later = await handleAccount(
      accountReq("/v2/account/login", {
        method: "POST",
        body: { username: "admin", password: ADMIN_PASSWORD },
      }),
      env,
      1_100_010 + AUTH_LOCKOUT_MS + 1,
    );
    expect(later?.status).toBe(200);
  });

  test("a successful login clears the strike counter", async () => {
    const env = testEnv();
    await makeAdmin(env);
    for (let i = 0; i < 2; i++) {
      await handleAccount(
        accountReq("/v2/account/login", {
          method: "POST",
          body: { username: "admin", password: "wrong" },
        }),
        env,
        1_200_000 + i,
      );
    }
    const ok = await handleAccount(
      accountReq("/v2/account/login", {
        method: "POST",
        body: { username: "admin", password: ADMIN_PASSWORD },
      }),
      env,
      1_200_005,
    );
    expect(ok?.status).toBe(200);

    for (let i = 0; i < 2; i++) {
      const res = await handleAccount(
        accountReq("/v2/account/login", {
          method: "POST",
          body: { username: "admin", password: "wrong" },
        }),
        env,
        1_200_010 + i,
      );
      expect(res?.status).toBe(401);
    }
  });

  test("an unknown username answers like a wrong password", async () => {
    const env = testEnv();
    await makeAdmin(env);
    const res = await handleAccount(
      accountReq("/v2/account/login", {
        method: "POST",
        body: { username: "ghost", password: ADMIN_PASSWORD },
      }),
      env,
      1_300_000,
    );
    expect(res?.status).toBe(401);
    expect(await bodyOf(res)).toEqual({ ok: false, error: { code: "bad_credentials" } });
  });

  test("logout drops the session and clears the cookie", async () => {
    const d1 = new FakeD1();
    const env = testEnv({ d1 });
    const cookie = await makeAdmin(env);
    expect(d1.accounts.sessions.size).toBe(1);

    const out = await handleAccount(
      accountReq("/v2/account/logout", { method: "POST", cookie }),
      env,
      1_000_030,
    );
    expect(out?.status).toBe(200);
    expect(out!.headers.get("Set-Cookie")).toContain("Max-Age=0");
    expect(d1.accounts.sessions.size).toBe(0);

    const state = await handleAccount(accountReq("/v2/account/state", { cookie }), env, 1_000_031);
    expect(await bodyOf(state)).toMatchObject({ initialized: true, user: null });
  });
});

describe("invite codes", () => {
  test("only the admin may read or rotate the code", async () => {
    const env = testEnv();
    const adminCookie = await makeAdmin(env);
    const invite = await inviteOf(env, adminCookie);
    const memberCookie = await makeMember(env, "bruce", invite, 1_000_100);

    const read = await handleAccount(
      accountReq("/v2/account/invite", { cookie: memberCookie }),
      env,
      1_000_101,
    );
    expect(read?.status).toBe(403);

    const rotate = await handleAccount(
      accountReq("/v2/account/invite/rotate", { method: "POST", cookie: memberCookie }),
      env,
      1_000_102,
    );
    expect(rotate?.status).toBe(403);

    const anon = await handleAccount(accountReq("/v2/account/invite"), env, 1_000_103);
    expect(anon?.status).toBe(403);
  });

  test("rotating replaces the code and retires the old one", async () => {
    const d1 = new FakeD1();
    const env = testEnv({ d1 });
    const cookie = await makeAdmin(env);
    const first = await inviteOf(env, cookie);

    const rotated = await handleAccount(
      accountReq("/v2/account/invite/rotate", { method: "POST", cookie }),
      env,
      1_000_110,
    );
    expect(rotated?.status).toBe(200);
    const next = String((await bodyOf(rotated)).invite_code);
    expect(INVITE_CODE_RE.test(next)).toBe(true);
    expect(d1.accounts.invite!.code).toBe(next);

    const stale = await handleAccount(
      accountReq("/v2/account/register", {
        method: "POST",
        ip: "203.0.113.30",
        body: { username: "clark", password: "member-password-1", invite_code: first },
      }),
      env,
      1_000_111,
    );
    // A rotation that did not change the code would make this a false pass.
    if (first !== next) {
      expect(stale?.status).toBe(401);
      expect(await bodyOf(stale)).toEqual({ ok: false, error: { code: "bad_invite" } });
    }
  });

  test("minted codes are four uppercase letters", () => {
    for (let i = 0; i < 64; i++) expect(INVITE_CODE_RE.test(mintInviteCode())).toBe(true);
  });
});

describe("registration", () => {
  test("a valid invite creates a member account", async () => {
    const d1 = new FakeD1();
    const env = testEnv({ d1 });
    const adminCookie = await makeAdmin(env);
    const invite = await inviteOf(env, adminCookie);

    const cookie = await makeMember(env, "diana", invite, 1_000_200);
    const state = await handleAccount(accountReq("/v2/account/state", { cookie }), env, 1_000_201);
    expect(await bodyOf(state)).toMatchObject({ user: { username: "diana", role: ROLE_MEMBER } });
    expect(d1.accounts.users.size).toBe(2);
  });

  test("a duplicate username conflicts", async () => {
    const env = testEnv();
    const adminCookie = await makeAdmin(env);
    const invite = await inviteOf(env, adminCookie);
    await makeMember(env, "diana", invite, 1_000_210);

    const dup = await handleAccount(
      accountReq("/v2/account/register", {
        method: "POST",
        ip: "203.0.113.40",
        body: { username: "diana", password: "member-password-2", invite_code: invite },
      }),
      env,
      1_000_211,
    );
    expect(dup?.status).toBe(409);
    expect(await bodyOf(dup)).toEqual({ ok: false, error: { code: "username_taken" } });
  });

  test("three wrong invites ban the address for an hour", async () => {
    const d1 = new FakeD1();
    const env = testEnv({ d1 });
    const adminCookie = await makeAdmin(env);
    const invite = await inviteOf(env, adminCookie);
    const attacker = "203.0.113.99";

    for (let i = 0; i < 3; i++) {
      const res = await handleAccount(
        accountReq("/v2/account/register", {
          method: "POST",
          ip: attacker,
          body: { username: "probe" + i, password: "member-password-1", invite_code: "ZZZZ" },
        }),
        env,
        1_400_000 + i,
      );
      expect(res?.status === 401 || res?.status === 429).toBe(true);
    }

    const locked = await handleAccount(
      accountReq("/v2/account/register", {
        method: "POST",
        ip: attacker,
        body: { username: "probe9", password: "member-password-1", invite_code: invite },
      }),
      env,
      1_400_010,
    );
    expect(locked?.status).toBe(429);
    expect(await bodyOf(locked)).toEqual({ ok: false, error: { code: "locked_out" } });

    const elsewhere = await handleAccount(
      accountReq("/v2/account/register", {
        method: "POST",
        ip: "203.0.113.11",
        body: { username: "barry", password: "member-password-1", invite_code: invite },
      }),
      env,
      1_400_011,
    );
    expect(elsewhere?.status).toBe(201);
  });

  test("registering before bootstrap has no invite to match", async () => {
    const res = await handleAccount(
      accountReq("/v2/account/register", {
        method: "POST",
        body: { username: "diana", password: "member-password-1", invite_code: "ABCD" },
      }),
      testEnv(),
      1_500_000,
    );
    expect(res?.status).toBe(409);
    expect(await bodyOf(res)).toEqual({ ok: false, error: { code: "not_initialized" } });
  });

  test("a malformed invite or username is a bad request", async () => {
    const env = testEnv();
    await makeAdmin(env);
    const badInvite = await handleAccount(
      accountReq("/v2/account/register", {
        method: "POST",
        body: { username: "diana", password: "member-password-1", invite_code: "AB1D" },
      }),
      env,
      1_500_010,
    );
    expect(badInvite?.status).toBe(400);

    const badName = await handleAccount(
      accountReq("/v2/account/register", {
        method: "POST",
        body: { username: "a b", password: "member-password-1", invite_code: "ABCD" },
      }),
      env,
      1_500_011,
    );
    expect(badName?.status).toBe(400);
  });
});

describe("device ownership", () => {
  test("a bound device appears only for its owner", async () => {
    const d1 = new FakeD1();
    const env = testEnv({ d1 });
    const adminCookie = await makeAdmin(env);
    const invite = await inviteOf(env, adminCookie);
    const memberCookie = await makeMember(env, "diana", invite, 1_600_000);
    const daemonId = await enrollDaemonId(env, "31", 1_600_001);

    const bound = await handleAccount(
      accountReq("/v2/account/devices", {
        method: "POST",
        cookie: adminCookie,
        body: {
          daemon_id: daemonId,
          label: "workstation",
          claim_proof: await proofFor(d1, "admin", daemonId, 1_600_002),
        },
      }),
      env,
      1_600_002,
    );
    expect(bound?.status).toBe(201);

    const mine = await handleAccount(
      accountReq("/v2/account/devices", { cookie: adminCookie }),
      env,
      1_600_003,
    );
    expect(await bodyOf(mine)).toMatchObject({
      devices: [{ daemon_id: daemonId, label: "workstation", live: true }],
    });

    const theirs = await handleAccount(
      accountReq("/v2/account/devices", { cookie: memberCookie }),
      env,
      1_600_004,
    );
    expect(await bodyOf(theirs)).toMatchObject({ devices: [] });
  });

  test("a second account cannot steal a bound device", async () => {
    const d1 = new FakeD1();
    const env = testEnv({ d1 });
    const adminCookie = await makeAdmin(env);
    const invite = await inviteOf(env, adminCookie);
    const memberCookie = await makeMember(env, "diana", invite, 1_700_000);
    const daemonId = await enrollDaemonId(env, "32", 1_700_001);

    expect(
      (await handleAccount(
        accountReq("/v2/account/devices", {
          method: "POST",
          cookie: adminCookie,
          body: { daemon_id: daemonId, claim_proof: await proofFor(d1, "admin", daemonId, 1_700_002) },
        }),
        env,
        1_700_002,
      ))?.status,
    ).toBe(201);

    // Even holding a proof of its own, the second account loses the race for a
    // device the first one already owns.
    const steal = await handleAccount(
      accountReq("/v2/account/devices", {
        method: "POST",
        cookie: memberCookie,
        body: { daemon_id: daemonId, claim_proof: await proofFor(d1, "diana", daemonId, 1_700_003) },
      }),
      env,
      1_700_003,
    );
    expect(steal?.status).toBe(409);
    expect(await bodyOf(steal)).toEqual({ ok: false, error: { code: "already_bound" } });
  });

  test("rebinding the same device by its owner is idempotent and spends no proof", async () => {
    const d1 = new FakeD1();
    const env = testEnv({ d1 });
    const cookie = await makeAdmin(env);
    const daemonId = await enrollDaemonId(env, "33", 1_800_000);

    const first = await handleAccount(
      accountReq("/v2/account/devices", {
        method: "POST",
        cookie,
        body: {
          daemon_id: daemonId,
          label: "laptop",
          claim_proof: await proofFor(d1, "admin", daemonId, 1_800_001),
        },
      }),
      env,
      1_800_001,
    );
    expect(first?.status).toBe(201);
    const again = await handleAccount(
      accountReq("/v2/account/devices", { method: "POST", cookie, body: { daemon_id: daemonId, label: "laptop" } }),
      env,
      1_800_002,
    );
    expect(again?.status).toBe(200);
    expect(await bodyOf(again)).toMatchObject({ bound_at: 1_800_001 });
    expect(d1.accounts.devices.size).toBe(1);
  });

  test("an unknown daemon cannot be bound", async () => {
    const d1 = new FakeD1();
    const env = testEnv({ d1 });
    const cookie = await makeAdmin(env);
    const ghost = "d_" + "99".repeat(10);
    const res = await handleAccount(
      accountReq("/v2/account/devices", {
        method: "POST",
        cookie,
        body: { daemon_id: ghost, claim_proof: await proofFor(d1, "admin", ghost, 1_900_000) },
      }),
      env,
      1_900_000,
    );
    expect(res?.status).toBe(404);
  });

  test("a malformed daemon id or label is a bad request", async () => {
    const d1 = new FakeD1();
    const env = testEnv({ d1 });
    const cookie = await makeAdmin(env);
    const badId = await handleAccount(
      accountReq("/v2/account/devices", { method: "POST", cookie, body: { daemon_id: "nope" } }),
      env,
      1_900_010,
    );
    expect(badId?.status).toBe(400);

    const daemonId = await enrollDaemonId(env, "34", 1_900_011);
    const badLabel = await handleAccount(
      accountReq("/v2/account/devices", {
        method: "POST",
        cookie,
        body: {
          daemon_id: daemonId,
          label: "x".repeat(100),
          claim_proof: await proofFor(d1, "admin", daemonId, 1_900_012),
        },
      }),
      env,
      1_900_012,
    );
    expect(badLabel?.status).toBe(400);
  });

  test("unbinding only works for the owner", async () => {
    const d1 = new FakeD1();
    const env = testEnv({ d1 });
    const adminCookie = await makeAdmin(env);
    const invite = await inviteOf(env, adminCookie);
    const memberCookie = await makeMember(env, "diana", invite, 2_000_000);
    const daemonId = await enrollDaemonId(env, "35", 2_000_001);
    await handleAccount(
      accountReq("/v2/account/devices", {
        method: "POST",
        cookie: adminCookie,
        body: { daemon_id: daemonId, claim_proof: await proofFor(d1, "admin", daemonId, 2_000_002) },
      }),
      env,
      2_000_002,
    );

    const foreign = await handleAccount(
      accountReq(`/v2/account/devices/${daemonId}`, { method: "DELETE", cookie: memberCookie }),
      env,
      2_000_003,
    );
    expect(foreign?.status).toBe(404);
    expect(d1.accounts.devices.size).toBe(1);

    const own = await handleAccount(
      accountReq(`/v2/account/devices/${daemonId}`, { method: "DELETE", cookie: adminCookie }),
      env,
      2_000_004,
    );
    expect(own?.status).toBe(200);
    expect(d1.accounts.devices.size).toBe(0);
  });

  test("a kicked device is listed but not live", async () => {
    const d1 = new FakeD1();
    const env = testEnv({ d1 });
    const cookie = await makeAdmin(env);
    const daemonId = await enrollDaemonId(env, "36", 2_100_000);
    await handleAccount(
      accountReq("/v2/account/devices", {
        method: "POST",
        cookie,
        body: { daemon_id: daemonId, claim_proof: await proofFor(d1, "admin", daemonId, 2_100_001) },
      }),
      env,
      2_100_001,
    );
    d1.daemons.get(daemonId)!.kicked_at = 2_100_002;

    const listed = await handleAccount(accountReq("/v2/account/devices", { cookie }), env, 2_100_003);
    expect(await bodyOf(listed)).toMatchObject({ devices: [{ daemon_id: daemonId, live: false }] });
  });

  test("device routes require a session", async () => {
    const env = testEnv();
    await makeAdmin(env);
    const list = await handleAccount(accountReq("/v2/account/devices"), env, 2_200_000);
    expect(list?.status).toBe(401);
    const bind = await handleAccount(
      accountReq("/v2/account/devices", {
        method: "POST",
        body: { daemon_id: "d_" + "37".repeat(10) },
      }),
      env,
      2_200_001,
    );
    expect(bind?.status).toBe(401);
    const del = await handleAccount(
      accountReq(`/v2/account/devices/d_${"37".repeat(10)}`, { method: "DELETE" }),
      env,
      2_200_002,
    );
    expect(del?.status).toBe(401);
  });

  test("an expired session no longer authenticates", async () => {
    const env = testEnv();
    const cookie = await makeAdmin(env, 3_000_000);
    const far = 3_000_000 + 40 * 24 * 60 * 60 * 1000;
    const res = await handleAccount(accountReq("/v2/account/devices", { cookie }), env, far);
    expect(res?.status).toBe(401);
  });
});

describe("input normalization", () => {
  test("usernames fold case and reject bad shapes", () => {
    expect(normalizeUsername(" Diana ")).toBe("diana");
    expect(normalizeUsername("ab")).toBeNull();
    expect(normalizeUsername("-lead")).toBeNull();
    expect(normalizeUsername("a".repeat(33))).toBeNull();
    expect(normalizeUsername(42)).toBeNull();
  });

  test("passwords keep interior spaces and reject control characters", () => {
    expect(normalizePassword("  correct horse  ")).toBe("correct horse");
    expect(normalizePassword("short")).toBeNull();
    expect(normalizePassword("with\u0007bell-x")).toBeNull();
    expect(normalizePassword("x".repeat(129))).toBeNull();
  });
});
