import { describe, expect, test } from "bun:test";
import { ProtocolError } from "./protocol/errors.ts";
import {
  bootstrapAccount,
  claimDevice,
  listBoundDevices,
  loginAccount,
  logoutAccount,
  readAccountState,
  readClaimProof,
  readInviteCode,
  readVault,
  registerAccount,
  releaseDevice,
  rotateInviteCode,
  VaultConflictError,
  writeVault,
} from "./account-api.ts";

const DAEMON = "d_0123456789abcdef0123";
const USER = { user_id: "u_0123456789abcdef", username: "admin", role: "admin" };

type Call = { url: string; method: string; cache?: string; credentials?: string; body: unknown };

/** Records what the client sent and replies with a fixed response. */
function stub(status: number, body: unknown) {
  const calls: Call[] = [];
  const fetchImpl = async (input: RequestInfo | URL, init?: RequestInit) => {
    calls.push({
      url: String(input),
      method: init?.method ?? "GET",
      cache: init?.cache,
      credentials: init?.credentials,
      body: typeof init?.body === "string" ? JSON.parse(init.body) : null,
    });
    return new Response(body === null ? "" : JSON.stringify(body), { status });
  };
  return { calls, fetchImpl };
}

async function codeOf(run: () => Promise<unknown>): Promise<string> {
  try {
    await run();
  } catch (error) {
    expect(error).toBeInstanceOf(ProtocolError);
    return (error as ProtocolError).code;
  }
  throw new Error("expected the call to reject");
}

describe("account transport", () => {
  test("every request carries the session cookie and bypasses the cache", async () => {
    // A cached /state would show a signed-out phone as signed in, and a request
    // without the cookie would make every authenticated route look unauthorized.
    const { calls, fetchImpl } = stub(200, { ok: true, initialized: true, user: USER });
    await readAccountState(fetchImpl);
    await loginAccount("admin", "hunter2hunter2", fetchImpl);
    for (const call of calls) {
      expect(call.credentials).toBe("same-origin");
      expect(call.cache).toBe("no-store");
    }
  });

  test("routes are addressed under the account prefix", async () => {
    const { calls, fetchImpl } = stub(200, { ok: true, initialized: false, user: null });
    await readAccountState(fetchImpl);
    expect(calls[0].url).toBe("/v2/account/state");
    expect(calls[0].method).toBe("GET");
  });

  test("a transport failure becomes a protocol error rather than a raw TypeError", async () => {
    const code = await codeOf(() =>
      readAccountState(async () => {
        throw new TypeError("Failed to fetch");
      }),
    );
    expect(code).toBe("bad_relay");
  });

  test("the origin's error code is preferred over the status it arrived with", async () => {
    const { fetchImpl } = stub(409, { ok: false, error: { code: "already_initialized" } });
    expect(await codeOf(() => bootstrapAccount("token", "hunter2hunter2", fetchImpl))).toBe("already_initialized");
  });

  test("a body-less rejection still yields a code the UI can branch on", async () => {
    expect(await codeOf(() => loginAccount("admin", "x", stub(401, null).fetchImpl))).toBe("bad_credentials");
    expect(await codeOf(() => listBoundDevices(stub(429, null).fetchImpl))).toBe("rate_limited");
    expect(await codeOf(() => readInviteCode(stub(403, null).fetchImpl))).toBe("forbidden");
  });

  test("the three-strikes lockout stays distinct from infrastructure throttling", async () => {
    // They ask the user to wait for very different reasons and very different
    // lengths of time, so collapsing them would mislead.
    const locked = stub(429, { ok: false, error: { code: "locked_out" } });
    expect(await codeOf(() => registerAccount("bob", "hunter2hunter2", "ABCD", locked.fetchImpl))).toBe("locked_out");
    const throttled = stub(429, { ok: false, error: { code: "rate_limited" } });
    expect(await codeOf(() => registerAccount("bob", "hunter2hunter2", "ABCD", throttled.fetchImpl))).toBe("rate_limited");
  });
});

describe("account state", () => {
  test("an uninitialized relay reports no account and no user", async () => {
    const { fetchImpl } = stub(200, { ok: true, initialized: false, user: null });
    expect(await readAccountState(fetchImpl)).toEqual({ initialized: false, user: null });
  });

  test("a signed-in response carries the identity the settings page needs", async () => {
    const { fetchImpl } = stub(200, { ok: true, initialized: true, user: USER });
    const state = await readAccountState(fetchImpl);
    expect(state.initialized).toBeTrue();
    expect(state.user).toEqual({ userId: "u_0123456789abcdef", username: "admin", role: "admin" });
  });

  test("an unrecognized role is not accepted as a user", async () => {
    // Treating an unknown role as a signed-in member would grant a capability
    // this build cannot reason about.
    const { fetchImpl } = stub(200, { ok: true, initialized: true, user: { ...USER, role: "root" } });
    expect((await readAccountState(fetchImpl)).user).toBeNull();
  });

  test("a response that omits initialized is refused rather than guessed", async () => {
    expect(await codeOf(() => readAccountState(stub(200, { ok: true }).fetchImpl))).toBe("internal");
  });
});

describe("sign-in routes", () => {
  test("bootstrap sends the service token and the chosen password", async () => {
    const { calls, fetchImpl } = stub(201, { ok: true, user: USER });
    const user = await bootstrapAccount("svc-token", "hunter2hunter2", fetchImpl);
    expect(user.username).toBe("admin");
    expect(calls[0].body).toEqual({ service_token: "svc-token", password: "hunter2hunter2" });
  });

  test("registration sends the invite code alongside the new credentials", async () => {
    const { calls, fetchImpl } = stub(201, { ok: true, user: { ...USER, username: "bob", role: "member" } });
    const user = await registerAccount("bob", "hunter2hunter2", "WXYZ", fetchImpl);
    expect(user.role).toBe("member");
    expect(calls[0].body).toEqual({ username: "bob", password: "hunter2hunter2", invite_code: "WXYZ" });
  });

  test("a wrong invite code is reported as such, not as a bad password", async () => {
    const { fetchImpl } = stub(401, { ok: false, error: { code: "bad_invite" } });
    expect(await codeOf(() => registerAccount("bob", "hunter2hunter2", "AAAA", fetchImpl))).toBe("bad_invite");
  });

  test("a 200 that carries no user is a failure, not a silent sign-in", async () => {
    expect(await codeOf(() => loginAccount("admin", "hunter2hunter2", stub(200, { ok: true }).fetchImpl))).toBe("internal");
  });

  test("logout accepts only the origin's explicit idempotent success", async () => {
    await logoutAccount(stub(200, { ok: true }).fetchImpl);
    for (const status of [401, 403, 404, 500, 502]) {
      await expect(logoutAccount(stub(status, { ok: true }).fetchImpl)).rejects.toBeInstanceOf(ProtocolError);
    }
    expect(await codeOf(() => logoutAccount(stub(200, { ok: false }).fetchImpl))).toBe("internal");
    expect(await codeOf(() => logoutAccount(stub(500, { ok: false, error: { code: "internal" } }).fetchImpl))).toBe("internal");
  });

  test("logout propagates a network failure", async () => {
    expect(await codeOf(() => logoutAccount(async () => {
      throw new TypeError("offline");
    }))).toBe("bad_relay");
  });
});

describe("invite code", () => {
  test("a four-letter code is read and rotated", async () => {
    const read = stub(200, { ok: true, invite_code: "QRST", updated_at: 7 });
    expect(await readInviteCode(read.fetchImpl)).toEqual({ code: "QRST", updatedAt: 7 });
    const rotated = stub(200, { ok: true, invite_code: "ZZZZ", updated_at: 9 });
    expect((await rotateInviteCode(rotated.fetchImpl)).code).toBe("ZZZZ");
    expect(rotated.calls[0].method).toBe("POST");
  });

  test("a code that is not four uppercase letters is refused", async () => {
    // Showing a malformed code would have the admin read it aloud to someone who
    // then cannot register.
    expect(await codeOf(() => readInviteCode(stub(200, { ok: true, invite_code: "ab12" }).fetchImpl))).toBe("internal");
    expect(await codeOf(() => readInviteCode(stub(200, { ok: true, invite_code: "ABCDE" }).fetchImpl))).toBe("internal");
  });
});

describe("claim proof", () => {
  const PROOF = "cp_" + "a".repeat(32);

  test("a pairing the daemon has not accepted yet reports not-ready, not a failure", async () => {
    // This is the normal answer for most of a pairing. Treating it as an error
    // would abandon the bind a second after the code was entered.
    const { calls, fetchImpl } = stub(200, { ok: true, ready: false });
    expect(await readClaimProof(DAEMON, fetchImpl)).toEqual({ ready: false });
    expect(calls[0].url).toBe(`/v2/account/claim-proof?daemon_id=${DAEMON}`);
    expect(calls[0].method).toBe("GET");
  });

  test("an accepted pairing yields the proof and its remaining life", async () => {
    const { fetchImpl } = stub(200, { ok: true, ready: true, claim_proof: PROOF, expires_in: 600 });
    expect(await readClaimProof(DAEMON, fetchImpl)).toEqual({ ready: true, proof: PROOF, expiresIn: 600 });
  });

  test("a ready answer carrying a malformed proof is refused rather than sent on", async () => {
    // Posting a nonsense proof spends the bind attempt and returns 403, which
    // reads to the user as the daemon rejecting them.
    const { fetchImpl } = stub(200, { ok: true, ready: true, claim_proof: "nonsense" });
    expect(await codeOf(() => readClaimProof(DAEMON, fetchImpl))).toBe("internal");
  });

  test("polling while signed out is an error, not an endless not-ready", async () => {
    const { fetchImpl } = stub(401, { ok: false, error: { code: "unauthenticated" } });
    expect(await codeOf(() => readClaimProof(DAEMON, fetchImpl))).toBe("unauthenticated");
  });

  test("the daemon id is escaped into the query rather than concatenated", async () => {
    const { calls, fetchImpl } = stub(200, { ok: true, ready: false });
    await readClaimProof("d_ /?&", fetchImpl);
    expect(calls[0].url).toBe("/v2/account/claim-proof?daemon_id=d_%20%2F%3F%26");
  });
});

describe("device binding", () => {
  test("the bound list is parsed into the fields the computers screen shows", async () => {
    const { fetchImpl } = stub(200, {
      ok: true,
      devices: [{ daemon_id: DAEMON, label: "desk", bound_at: 12, live: true }],
    });
    expect(await listBoundDevices(fetchImpl)).toEqual([{ daemonId: DAEMON, label: "desk", boundAt: 12, live: true }]);
  });

  test("an unparseable entry is dropped without losing the rest of the list", async () => {
    const { fetchImpl } = stub(200, {
      ok: true,
      devices: [{ daemon_id: "nonsense", bound_at: 1 }, { daemon_id: DAEMON, label: null, bound_at: 2, live: false }],
    });
    const devices = await listBoundDevices(fetchImpl);
    expect(devices).toHaveLength(1);
    expect(devices[0]).toEqual({ daemonId: DAEMON, label: null, boundAt: 2, live: false });
  });

  test("claiming always sends a proof, so a daemon id alone cannot bind", async () => {    const { calls, fetchImpl } = stub(201, { ok: true, daemon_id: DAEMON, label: "desk", bound_at: 3 });
    await claimDevice(DAEMON, "cp_" + "a".repeat(32), "desk", fetchImpl);
    const body = calls[0].body as Record<string, unknown>;
    expect(body.claim_proof).toBe("cp_" + "a".repeat(32));
    expect(body.daemon_id).toBe(DAEMON);
  });

  test("an omitted label is left out rather than sent as null", async () => {
    const { calls, fetchImpl } = stub(201, { ok: true, daemon_id: DAEMON, label: null, bound_at: 3 });
    await claimDevice(DAEMON, "cp_" + "b".repeat(32), null, fetchImpl);
    expect("label" in (calls[0].body as Record<string, unknown>)).toBeFalse();
  });

  test("a device another account already owns is reported as a conflict", async () => {
    const { fetchImpl } = stub(409, { ok: false, error: { code: "already_bound" } });
    expect(await codeOf(() => claimDevice(DAEMON, "cp_" + "c".repeat(32), null, fetchImpl))).toBe("already_bound");
  });

  test("a rejected proof surfaces as forbidden rather than a successful bind", async () => {
    const { fetchImpl } = stub(403, { ok: false, error: { code: "forbidden" } });
    expect(await codeOf(() => claimDevice(DAEMON, "cp_" + "d".repeat(32), null, fetchImpl))).toBe("forbidden");
  });

  test("releasing addresses the device by id and reports a refusal", async () => {
    const ok = stub(200, { ok: true, daemon_id: DAEMON });
    await releaseDevice(DAEMON, ok.fetchImpl);
    expect(ok.calls[0].url).toBe(`/v2/account/devices/${DAEMON}`);
    expect(ok.calls[0].method).toBe("DELETE");
    expect(await codeOf(() => releaseDevice(DAEMON, stub(404, null).fetchImpl))).toBe("unbound");
  });
});

describe("vault transport", () => {
  const VAULT = { ciphertext: "AAAA", nonce: "BBBB", kdf: "{}", version: 3, updated_at: 99 };

  test("a stored vault is returned with its version and kdf record", async () => {
    const { fetchImpl } = stub(200, { ok: true, vault: VAULT });
    expect(await readVault(fetchImpl)).toEqual({
      ciphertext: "AAAA",
      nonce: "BBBB",
      kdf: "{}",
      version: 3,
      updatedAt: 99,
    });
  });

  test("an account that has never written a vault reads as empty, not as an error", async () => {
    expect(await readVault(stub(404, { ok: false, error: { code: "unbound" } }).fetchImpl)).toBeNull();
  });

  test("an unauthenticated read is an error, because empty would look like data loss", async () => {
    const { fetchImpl } = stub(401, { ok: false, error: { code: "unauthenticated" } });
    expect(await codeOf(() => readVault(fetchImpl))).toBe("unauthenticated");
  });

  test("a write states the version it replaces so a concurrent edit cannot be clobbered", async () => {
    const { calls, fetchImpl } = stub(200, { ok: true, version: 4 });
    const saved = await writeVault({ ciphertext: "CCCC", nonce: "DDDD", kdf: "{}", version: 3 }, fetchImpl);
    expect(calls[0].method).toBe("PUT");
    expect(calls[0].body).toEqual({ ciphertext: "CCCC", nonce: "DDDD", kdf: "{}", version: 3 });
    expect(saved).toBe(4);
  });

  test("the first write of a fresh account states version zero", async () => {
    const { calls, fetchImpl } = stub(200, { ok: true, version: 1 });
    expect(await writeVault({ ciphertext: "CCCC", nonce: "DDDD", kdf: "{}", version: 0 }, fetchImpl)).toBe(1);
    expect((calls[0].body as Record<string, unknown>).version).toBe(0);
  });

  test("a conflict carries the version the origin holds, so the caller can re-read and merge", async () => {
    // Retrying blindly would overwrite whatever the other phone just bound; the
    // version is what makes the recovery path possible at all.
    const { fetchImpl } = stub(409, { ok: false, error: { code: "conflict", version: 7 } });
    const write = { ciphertext: "CCCC", nonce: "DDDD", kdf: "{}", version: 3 };
    try {
      await writeVault(write, fetchImpl);
      throw new Error("expected the write to reject");
    } catch (error) {
      expect(error).toBeInstanceOf(VaultConflictError);
      expect((error as VaultConflictError).currentVersion).toBe(7);
      expect((error as VaultConflictError).code).toBe("conflict");
    }
  });

  test("an oversize vault is reported as too large rather than as a conflict", async () => {
    const { fetchImpl } = stub(413, { ok: false, error: { code: "too_large" } });
    const write = { ciphertext: "CCCC", nonce: "DDDD", kdf: "{}", version: 1 };
    expect(await codeOf(() => writeVault(write, fetchImpl))).toBe("too_large");
  });

  test("a vault missing its version is refused rather than decrypted at the wrong one", async () => {
    // The version is bound into the blob's AAD, so guessing it would fail to
    // open in a way that looks like corruption.
    const { fetchImpl } = stub(200, { ok: true, vault: { ...VAULT, version: undefined } });
    expect(await codeOf(() => readVault(fetchImpl))).toBe("internal");
  });
});
