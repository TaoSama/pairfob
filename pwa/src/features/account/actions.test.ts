import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import "../../../test-support/boot-dom";
import { encodeCredential, type StoredCredential } from "../../lib/credentials";
import { fingerprint16 } from "../../lib/protocol/hello";
import {
  decryptVault,
  deriveSession,
  encodeKdf,
  encryptVault,
  rewrapDescriptor,
} from "../../lib/account-vault";
import {
  accountStore,
  clearAccountSession,
  setAccountDevices,
  setAccountSession,
  setAccountVaultKey,
  setAccountVaultState,
} from "./account-store";
import {
  awaitClaimProof,
  bindDevice,
  publishCredentials,
  signOutAccount,
  submitAccount,
  syncAccountDevices,
  VaultSealedError,
} from "./actions";

/**
 * These exercise the account plane against a scripted origin.
 *
 * The passphrase cost is the production one here on purpose for the single
 * sign-in case, because that path's whole claim is that a second phone rederives
 * the same key; everything else seeds the session directly so the suite does not
 * pay Argon2id per test.
 */

const ADMIN = { user_id: "u_0123456789abcdef", username: "admin", role: "admin" };
const USER_ID = "u_0123456789abcdef";
const DAEMON_A = "d_aaaaaaaaaaaaaaaaaaaa";
const DAEMON_B = "d_bbbbbbbbbbbbbbbbbbbb";

function keyBytes(seed: number): Uint8Array {
  return new Uint8Array(32).fill(seed);
}

/**
 * Stand-ins for the two keys a real session holds: the passphrase-derived
 * wrapping key, and the random key the credentials are actually encrypted under.
 * Seeding both directly keeps Argon2id out of every test but the sign-in ones.
 */
const WRAP_KEY = keyBytes(0x31);
const VAULT_KEY = keyBytes(0x5a);

/** The kdf column as the relay would hold it: cost plus the wrapped vault key. */
function storedKdf(username = "admin"): string {
  return encodeKdf(rewrapDescriptor(WRAP_KEY, VAULT_KEY, username));
}

function credential(daemonId: string, createdAt: number, label = "desk"): StoredCredential {
  const daemonPk = keyBytes(daemonId.charCodeAt(2));
  return encodeCredential({
    daemonId,
    deviceId: "dev_" + "A".repeat(16),
    psk: keyBytes(7),
    daemonPk,
    relayOrigin: "https://pair.example",
    fp: fingerprint16(daemonPk),
    label,
    createdAt,
  });
}

function device(daemonId: string, label = "desk") {
  return { daemon_id: daemonId, label, bound_at: 1, live: true };
}

/** A session that has already read and opened a vault at `version`. */
function openVault(version: number): void {
  setAccountVaultState(version, storedKdf(), false);
  setAccountVaultKey(VAULT_KEY);
}

type Route = (body: unknown) => { status?: number; json: unknown };

const originalFetch = globalThis.fetch;
let routes: Record<string, Route>;
let seen: { path: string; method: string; body: unknown }[];

/** A scripted origin. Anything the code asks for that is not scripted is a failure. */
function serve(table: Record<string, Route>): void {
  routes = table;
  seen = [];
  globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input);
    const method = init?.method ?? "GET";
    const body = typeof init?.body === "string" ? JSON.parse(init.body) : null;
    seen.push({ path: url, method, body });
    const route = routes[`${method} ${url}`];
    if (!route) return new Response(JSON.stringify({ ok: false, error: { code: "internal" } }), { status: 500 });
    const { status = 200, json } = route(body);
    return new Response(JSON.stringify(json), { status });
  }) as typeof fetch;
}

beforeEach(() => {
  clearAccountSession();
});

afterEach(() => {
  globalThis.fetch = originalFetch;
  clearAccountSession();
});

describe("signing in", () => {
  test("the origin is sent a derived authenticator, never the passphrase", async () => {
    // The whole vault design rests on this: if the passphrase crossed the wire,
    // the origin could decrypt every credential it stores.
    serve({ "POST /v2/account/login": () => ({ json: { ok: true, user: ADMIN } }) });
    await submitAccount({ kind: "login", username: "admin", password: "correct horse battery" });

    const sent = seen[0].body as { username: string; password: string };
    expect(sent.username).toBe("admin");
    expect(sent.password).not.toBe("correct horse battery");
    expect(sent.password).toMatch(/^[0-9a-f]{64}$/);
  });

  test("the key that opens the vault is not the value the origin received", async () => {
    serve({ "POST /v2/account/login": () => ({ json: { ok: true, user: ADMIN } }) });
    await submitAccount({ kind: "login", username: "admin", password: "correct horse battery" });

    const sent = (seen[0].body as { password: string }).password;
    const key = accountStore.get().wrapKey;
    expect(key).not.toBeNull();
    expect(Buffer.from(key as Uint8Array).toString("hex")).not.toBe(sent);
  });

  test("two phones signing in to one account derive the same vault key", async () => {
    // This is what makes "log in and the computers are there" possible at all.
    serve({ "POST /v2/account/login": () => ({ json: { ok: true, user: ADMIN } }) });
    await submitAccount({ kind: "login", username: "admin", password: "correct horse battery" });
    const first = accountStore.get().wrapKey as Uint8Array;

    const second = await deriveSession("admin", "correct horse battery", location.host);
    expect([...second.wrapKey]).toEqual([...first]);
  });

  test("bootstrap opens the fixed first account and signs the phone in as it", async () => {
    serve({ "POST /v2/account/bootstrap": () => ({ status: 201, json: { ok: true, user: ADMIN } }) });
    await submitAccount({ kind: "bootstrap", serviceToken: "svc", password: "correct horse battery" });

    expect((seen[0].body as { service_token: string }).service_token).toBe("svc");
    expect(accountStore.get().username).toBe("admin");
    expect(accountStore.get().initialized).toBeTrue();
  });

  test("registration sends the invite code and signs in as an ordinary member", async () => {
    const member = { user_id: "u_fedcba9876543210", username: "bob", role: "member" };
    serve({ "POST /v2/account/register": () => ({ status: 201, json: { ok: true, user: member } }) });
    await submitAccount({
      kind: "register", username: "bob", password: "correct horse battery", inviteCode: "WXYZ",
    });

    expect((seen[0].body as { invite_code: string }).invite_code).toBe("WXYZ");
    expect(accountStore.get().role).toBe("member");
  });

  test("a refused sign-in leaves no session and no key behind", async () => {
    // A half-applied session would show an empty device list as though the
    // account owned nothing.
    serve({
      "POST /v2/account/login": () => ({ status: 401, json: { ok: false, error: { code: "bad_credentials" } } }),
    });
    await expect(
      submitAccount({ kind: "login", username: "admin", password: "wrong passphrase" }),
    ).rejects.toThrow();
    expect(accountStore.get().userId).toBeNull();
    expect(accountStore.get().wrapKey).toBeNull();
    expect(accountStore.get().busy).toBeFalse();
  });

  test("signing out forgets the key but remembers that the deployment has an account", async () => {
    // Forgetting that would offer the service-token form to the next person.
    serve({ "POST /v2/account/logout": () => ({ json: { ok: true } }) });
    setAccountSession({ userId: USER_ID, username: "admin", role: "admin" }, WRAP_KEY);
    await signOutAccount();

    expect(accountStore.get().wrapKey).toBeNull();
    expect(accountStore.get().userId).toBeNull();
    expect(accountStore.get().initialized).toBeTrue();
  });
});

describe("recovering an account's computers on a second phone", () => {
  beforeEach(() => {
    setAccountSession({ userId: USER_ID, username: "admin", role: "admin" }, WRAP_KEY);
  });

  test("a phone that has never paired recovers the credentials from the vault", async () => {
    const stored = credential(DAEMON_A, 10);
    const sealed = encryptVault(VAULT_KEY, [stored], USER_ID, 3);
    serve({
      "GET /v2/account/devices": () => ({ json: { ok: true, devices: [device(DAEMON_A)] } }),
      "GET /v2/account/vault": () => ({
        json: { ok: true, vault: { ...sealed, kdf: storedKdf(), version: 3, updated_at: 1 } },
      }),
    });

    const recovered = await syncAccountDevices(null, []);
    expect(recovered.map((c) => c.daemon_id)).toEqual([DAEMON_A]);
    expect(recovered[0].device_psk).toBe(stored.device_psk);
    expect(accountStore.get().vaultVersion).toBe(3);
  });

  test("a machine the relay no longer says this account owns is not offered", async () => {
    // Ownership is the relay's call. A credential left in the vault after an
    // unbind must not put a machine back on the list.
    const sealed = encryptVault(VAULT_KEY, [credential(DAEMON_A, 10), credential(DAEMON_B, 20)], USER_ID, 2);
    serve({
      "GET /v2/account/devices": () => ({ json: { ok: true, devices: [device(DAEMON_A)] } }),
      "GET /v2/account/vault": () => ({
        json: { ok: true, vault: { ...sealed, kdf: storedKdf(), version: 2, updated_at: 1 } },
      }),
    });

    expect((await syncAccountDevices(null, [])).map((c) => c.daemon_id)).toEqual([DAEMON_A]);
  });

  test("another account's credential sitting in this browser is filtered out", async () => {
    // Two people share a phone; the previous owner's machine must not appear
    // under the account that is signed in now.
    const theirs = credential(DAEMON_B, 50);
    serve({
      "GET /v2/account/devices": () => ({ json: { ok: true, devices: [device(DAEMON_A)] } }),
      "GET /v2/account/vault": () => ({ status: 404, json: { ok: false, error: { code: "unbound" } } }),
    });

    const scoped = await syncAccountDevices(null, [credential(DAEMON_A, 10), theirs]);
    expect(scoped.map((c) => c.daemon_id)).toEqual([DAEMON_A]);
  });

  test("an account with no vault yet keeps what this phone already paired", async () => {
    serve({
      "GET /v2/account/devices": () => ({ json: { ok: true, devices: [device(DAEMON_A)] } }),
      "GET /v2/account/vault": () => ({ status: 404, json: { ok: false, error: { code: "unbound" } } }),
    });

    const local = [credential(DAEMON_A, 10)];
    expect((await syncAccountDevices(null, local)).map((c) => c.daemon_id)).toEqual([DAEMON_A]);
    expect(accountStore.get().vaultVersion).toBe(0);
  });

  test("a vault written under an unreadable cost record does not erase the local list", async () => {
    // Deriving under a guessed cost yields a wrong key that reads as corruption;
    // keeping what this phone has is the recoverable outcome.
    serve({
      "GET /v2/account/devices": () => ({ json: { ok: true, devices: [device(DAEMON_A)] } }),
      "GET /v2/account/vault": () => ({
        json: { ok: true, vault: { ciphertext: "AAAA", nonce: "BBBB", kdf: "not json", version: 4, updated_at: 1 } },
      }),
    });

    const local = [credential(DAEMON_A, 10)];
    expect((await syncAccountDevices(null, local)).map((c) => c.daemon_id)).toEqual([DAEMON_A]);
    expect(accountStore.get().vaultVersion).toBe(4);
    expect(accountStore.get().vaultSealed).toBeTrue();
  });

  test("a signed-out phone syncs nothing rather than asking the origin", async () => {
    clearAccountSession();
    serve({});
    expect(await syncAccountDevices(null, [credential(DAEMON_A, 10)])).toEqual([]);
    expect(seen).toEqual([]);
  });
});

describe("publishing the credential list", () => {
  beforeEach(() => {
    setAccountSession({ userId: USER_ID, username: "admin", role: "admin" }, WRAP_KEY);
  });

  test("a write states the version it replaces and records the one it got back", async () => {
    openVault(3);
    serve({ "PUT /v2/account/vault": () => ({ json: { ok: true, version: 4 } }) });

    expect(await publishCredentials([credential(DAEMON_A, 10)])).toBe(4);
    expect((seen[0].body as { version: number }).version).toBe(3);
    expect(accountStore.get().vaultVersion).toBe(4);
  });

  test("the transmitted fields carry no key material", async () => {
    // The relay stores these two strings verbatim and can read them.
    const stored = credential(DAEMON_A, 10);
    serve({ "PUT /v2/account/vault": () => ({ json: { ok: true, version: 1 } }) });
    await publishCredentials([stored]);

    const body = seen[0].body as { ciphertext: string; nonce: string };
    expect(body.ciphertext).not.toContain(stored.device_psk);
    expect(body.nonce).not.toContain(stored.device_psk);
  });

  test("a concurrent edit from another phone is merged rather than overwritten", async () => {
    // Both phones bound a machine; a blind retry would drop one of them.
    const theirs = encryptVault(VAULT_KEY, [credential(DAEMON_B, 20)], USER_ID, 7);
    let puts = 0;
    serve({
      "PUT /v2/account/vault": () => {
        puts += 1;
        if (puts === 1) return { status: 409, json: { ok: false, error: { code: "conflict", version: 7 } } };
        return { json: { ok: true, version: 8 } };
      },
      "GET /v2/account/vault": () => ({
        json: { ok: true, vault: { ...theirs, kdf: storedKdf(), version: 7, updated_at: 1 } },
      }),
    });

    expect(await publishCredentials([credential(DAEMON_A, 10)])).toBe(8);
    expect(puts).toBe(2);
    expect((seen[seen.length - 1].body as { version: number }).version).toBe(7);
  });

  test("losing a first-write race adopts the winner's key instead of re-keying the vault", async () => {
    // Two phones both believe the account has no vault and each mint a random
    // vault key. The loser must re-encrypt under the key the winner's record
    // carries: writing its own key over their kdf column would leave a blob
    // neither phone could open, losing every credential already stored.
    const theirVaultKey = keyBytes(0x77);
    const theirKdf = encodeKdf(rewrapDescriptor(WRAP_KEY, theirVaultKey, "admin"));
    const theirs = encryptVault(theirVaultKey, [credential(DAEMON_B, 20)], USER_ID, 1);
    let puts = 0;
    serve({
      "PUT /v2/account/vault": () => {
        puts += 1;
        if (puts === 1) return { status: 409, json: { ok: false, error: { code: "conflict", version: 1 } } };
        return { json: { ok: true, version: 2 } };
      },
      "GET /v2/account/vault": () => ({
        json: { ok: true, vault: { ...theirs, kdf: theirKdf, version: 1, updated_at: 1 } },
      }),
    });

    expect(await publishCredentials([credential(DAEMON_A, 10)])).toBe(2);
    const wrote = seen[seen.length - 1].body as { kdf: string; ciphertext: string; nonce: string };
    expect(wrote.kdf).toBe(theirKdf);
    // Both machines survive, and the blob opens under the winner's key.
    const reopened = decryptVault(theirVaultKey, wrote, USER_ID, 2);
    expect(reopened.credentials.map((c) => c.daemon_id).sort()).toEqual([DAEMON_A, DAEMON_B]);
  });

  test("a second conflict is reported rather than retried forever", async () => {
    // Something is writing continuously; looping would drain the phone.
    const theirs = encryptVault(VAULT_KEY, [credential(DAEMON_B, 20)], USER_ID, 7);
    serve({
      "PUT /v2/account/vault": () => ({ status: 409, json: { ok: false, error: { code: "conflict", version: 7 } } }),
      "GET /v2/account/vault": () => ({
        json: { ok: true, vault: { ...theirs, kdf: storedKdf(), version: 7, updated_at: 1 } },
      }),
    });

    await expect(publishCredentials([credential(DAEMON_A, 10)])).rejects.toThrow();
  });

  test("a signed-out phone publishes nothing", async () => {
    clearAccountSession();
    serve({});
    expect(await publishCredentials([credential(DAEMON_A, 10)])).toBe(0);
    expect(seen).toEqual([]);
  });
});

/**
 * A vault that exists and will not open must never be written over.
 *
 * Every case here is one read that fails followed by the publish that used to
 * run next. The old code recorded the stored version, found no key, minted a
 * random one, and wrote it at that version — a compare-and-set that succeeds and
 * leaves a blob nobody holds the key to. Each test asserts the same two things:
 * nothing was PUT, and the stored ciphertext, kdf and version are unchanged.
 */
describe("refusing to overwrite a vault this phone cannot read", () => {
  const INTACT = { kdf: storedKdf(), version: 9 };

  beforeEach(() => {
    setAccountSession({ userId: USER_ID, username: "admin", role: "admin" }, WRAP_KEY);
  });

  /** A stored vault plus a PUT route that fails the test if it is ever reached. */
  function serveSealed(vault: Record<string, unknown>): void {
    serve({
      "GET /v2/account/devices": () => ({ json: { ok: true, devices: [device(DAEMON_A)] } }),
      "GET /v2/account/vault": () => ({ json: { ok: true, vault } }),
      "PUT /v2/account/vault": () => ({ json: { ok: true, version: 999 } }),
    });
  }

  /** The sequence that lost data: sync could not open the vault, then publish ran. */
  async function syncThenPublish(): Promise<unknown> {
    const local = [credential(DAEMON_A, 10)];
    const merged = await syncAccountDevices(null, local);
    return publishCredentials(merged).catch((error) => error);
  }

  function assertUntouched(): void {
    expect(seen.filter((call) => call.method === "PUT")).toEqual([]);
    expect(accountStore.get().vaultSealed).toBeTrue();
    expect(accountStore.get().vaultVersion).toBe(INTACT.version);
  }

  test("an unparseable kdf column is not replaced with a fresh key", async () => {
    serveSealed({ ciphertext: "AAAA", nonce: "BBBB", kdf: "not json", version: INTACT.version, updated_at: 1 });
    expect(await syncThenPublish()).toBeInstanceOf(VaultSealedError);
    assertUntouched();
  });

  test("a record this phone cannot unwrap is not replaced with a fresh key", async () => {
    // Right shape, right cost, wrong wrapping key: the unwrap tag fails. That is
    // the ordinary "signed in, vault still shut" state, and it must not write.
    const otherWrap = keyBytes(0x99);
    const sealed = encryptVault(VAULT_KEY, [credential(DAEMON_B, 20)], USER_ID, INTACT.version);
    serveSealed({
      ...sealed,
      kdf: encodeKdf(rewrapDescriptor(otherWrap, VAULT_KEY, "admin")),
      version: INTACT.version,
      updated_at: 1,
    });

    expect(await syncThenPublish()).toBeInstanceOf(VaultSealedError);
    assertUntouched();
    expect(accountStore.get().vaultKey).toBeNull();
  });

  test("ciphertext that does not open under a good key is not replaced", async () => {
    // The key unwraps, the blob does not decrypt. Truncated storage or a
    // mismatched version; either way re-keying would make it permanent.
    serveSealed({ ciphertext: "Zm9v", nonce: "YmFy", ...INTACT, updated_at: 1 });
    expect(await syncThenPublish()).toBeInstanceOf(VaultSealedError);
    assertUntouched();
  });

  test("a sealed session refuses every later publish without asking the origin", async () => {
    // The seal outlives the read that set it: a bind arriving a minute later
    // must not find a phone willing to mint a key again.
    serveSealed({ ciphertext: "Zm9v", nonce: "YmFy", ...INTACT, updated_at: 1 });
    await syncThenPublish();
    const before = seen.length;

    await expect(publishCredentials([credential(DAEMON_B, 20)])).rejects.toBeInstanceOf(VaultSealedError);
    expect(seen).toHaveLength(before);
  });

  test("a genuine first vault is still created after a 404", async () => {
    // The fail-closed rule must not cost a fresh account its first write.
    serve({
      "GET /v2/account/devices": () => ({ json: { ok: true, devices: [device(DAEMON_A)] } }),
      "GET /v2/account/vault": () => ({ status: 404, json: { ok: false, error: { code: "unbound" } } }),
      "PUT /v2/account/vault": () => ({ json: { ok: true, version: 1 } }),
    });

    const merged = await syncAccountDevices(null, [credential(DAEMON_A, 10)]);
    expect(await publishCredentials(merged)).toBe(1);
    expect((seen[seen.length - 1].body as { version: number }).version).toBe(0);
    expect(accountStore.get().vaultSealed).toBeFalse();
  });

  test("losing a first-write race to a record this phone cannot open does not overwrite it", async () => {
    // The 409 path had the same hole: re-read, fail to unwrap the winner's
    // record, and the old code threw the conflict onward while leaving the
    // minted key in the domain for the next publish to write with.
    const theirKdf = encodeKdf(rewrapDescriptor(keyBytes(0x99), keyBytes(0x77), "admin"));
    const theirs = encryptVault(keyBytes(0x77), [credential(DAEMON_B, 20)], USER_ID, 1);
    let puts = 0;
    serve({
      "PUT /v2/account/vault": () => {
        puts += 1;
        return { status: 409, json: { ok: false, error: { code: "conflict", version: 1 } } };
      },
      "GET /v2/account/vault": () => ({
        json: { ok: true, vault: { ...theirs, kdf: theirKdf, version: 1, updated_at: 1 } },
      }),
    });

    await expect(publishCredentials([credential(DAEMON_A, 10)])).rejects.toBeInstanceOf(VaultSealedError);
    expect(puts).toBe(1);
    expect(accountStore.get().vaultSealed).toBeTrue();
    // The minted key was never adopted, so the next attempt cannot write with it.
    expect(accountStore.get().vaultKey).toBeNull();
  });
});

describe("waiting for the daemon to accept", () => {
  const PROOF = "cp_" + "a".repeat(32);
  const never = async () => {};

  beforeEach(() => {
    setAccountSession({ userId: USER_ID, username: "admin", role: "admin" }, WRAP_KEY);
  });

  test("polling continues while the daemon has not accepted, then returns the proof", async () => {
    // Resolving a pairing code does not mint a proof; somebody still has to
    // confirm at the computer, and the wait is the normal case.
    let polls = 0;
    serve({
      [`GET /v2/account/claim-proof?daemon_id=${DAEMON_A}`]: () => {
        polls += 1;
        if (polls < 3) return { json: { ok: true, ready: false } };
        return { json: { ok: true, ready: true, claim_proof: PROOF, expires_in: 600 } };
      },
    });

    expect(await awaitClaimProof(DAEMON_A, { wait: never })).toBe(PROOF);
    expect(polls).toBe(3);
  });

  test("a pairing nobody confirms gives up rather than polling forever", async () => {
    serve({
      [`GET /v2/account/claim-proof?daemon_id=${DAEMON_A}`]: () => ({ json: { ok: true, ready: false } }),
    });

    expect(await awaitClaimProof(DAEMON_A, { attempts: 4, wait: never })).toBeNull();
    expect(seen).toHaveLength(4);
  });

  test("an aborted wait stops asking immediately", async () => {
    // The person left the pairing screen; the phone should not keep polling.
    const controller = new AbortController();
    controller.abort();
    serve({
      [`GET /v2/account/claim-proof?daemon_id=${DAEMON_A}`]: () => ({ json: { ok: true, ready: false } }),
    });

    expect(await awaitClaimProof(DAEMON_A, { wait: never, signal: controller.signal })).toBeNull();
    expect(seen).toEqual([]);
  });

  test("a signed-out poll surfaces the failure instead of waiting out the window", async () => {
    // Two minutes of silence after the session expired would look like the
    // daemon refusing, rather than a sign-in the person can redo.
    serve({
      [`GET /v2/account/claim-proof?daemon_id=${DAEMON_A}`]: () => ({
        status: 401, json: { ok: false, error: { code: "unauthenticated" } },
      }),
    });

    await expect(awaitClaimProof(DAEMON_A, { wait: never })).rejects.toThrow();
  });
});

describe("binding a machine to this account", () => {
  beforeEach(() => {
    setAccountSession({ userId: USER_ID, username: "admin", role: "admin" }, WRAP_KEY);
  });

  test("a bind always carries a proof and then trusts the relay's list", async () => {
    // Appending locally would show a bind the origin might have refused.
    serve({
      "POST /v2/account/devices": () => ({ status: 201, json: { ok: true, daemon_id: DAEMON_A, label: "desk", bound_at: 3 } }),
      "GET /v2/account/devices": () => ({ json: { ok: true, devices: [device(DAEMON_A)] } }),
    });

    const devices = await bindDevice(DAEMON_A, "cp_" + "a".repeat(32), "desk");
    expect((seen[0].body as { claim_proof: string }).claim_proof).toBe("cp_" + "a".repeat(32));
    expect(devices.map((d) => d.daemonId)).toEqual([DAEMON_A]);
    expect(accountStore.get().devices).toHaveLength(1);
  });

  test("a rejected proof leaves the device list untouched", async () => {
    setAccountDevices([{ daemonId: DAEMON_B, label: "old", boundAt: 1, live: false }]);
    serve({
      "POST /v2/account/devices": () => ({ status: 403, json: { ok: false, error: { code: "forbidden" } } }),
    });

    await expect(bindDevice(DAEMON_A, "cp_" + "b".repeat(32), null)).rejects.toThrow();
    expect(accountStore.get().devices.map((d) => d.daemonId)).toEqual([DAEMON_B]);
  });
});
