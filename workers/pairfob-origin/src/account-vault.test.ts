import { Database } from "bun:sqlite";
import { beforeEach, describe, expect, test } from "bun:test";
import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { resolveIdentity } from "./account-auth.ts";
import { handleAccount } from "./account.ts";
import {
  handleVault,
  INSERT_VAULT_SQL,
  SELECT_VAULT_SQL,
  UPDATE_VAULT_SQL,
} from "./account-vault.ts";
import { VAULT_MAX_BYTES } from "./constants.ts";
import { buildOf, noStore } from "./http.ts";
import { resetLimits } from "./limits.ts";
import { FakeD1 } from "./testutil/fake-d1.ts";
import { testEnv } from "./testutil/make-room.ts";
import {
  accountReq,
  bodyOf,
  inviteOf,
  makeAdmin,
  makeMember,
  type TestEnv,
} from "./testutil/account-harness.ts";

const PATH = "/v2/account/vault";

/** A blob the relay must treat as bytes: valid base64, no meaning here. */
const CIPHER = "c2VjcmV0LXZhdWx0LXBheWxvYWQ=";
const NONCE = "bm9uY2UtdHdlbHZlLWI=";
const KDF = "pbkdf2-sha256:600000";

beforeEach(() => resetLimits());

/** Goes through the real account router, so the wiring is covered too. */
async function vault(
  env: TestEnv,
  init: { method?: string; body?: unknown; cookie?: string },
  now = 2_000_000,
): Promise<Response> {
  const res = await handleAccount(accountReq(PATH, init), env, now);
  if (!res) throw new Error("the vault path is not routed");
  return res;
}

async function put(
  env: TestEnv,
  cookie: string,
  body: Record<string, unknown>,
  now = 2_000_000,
): Promise<Response> {
  return vault(env, { method: "PUT", cookie, body }, now);
}

/**
 * Fires several writes that are already past authentication, so what interleaves
 * is the database work. Resolving the cookie inside each racer would not do:
 * the hash is a real async primitive whose timing need not line up with the
 * store's, and one request can finish before the other has started.
 */
async function race(
  env: TestEnv,
  cookie: string,
  bodies: Array<Record<string, unknown>>,
  now = 2_000_000,
): Promise<number[]> {
  const reqs = bodies.map((body) => accountReq(PATH, { method: "PUT", cookie, body }));
  const ids = await Promise.all(reqs.map((req) => resolveIdentity(env.DB, req, now)));
  const out = await Promise.all(
    reqs.map((req, i) => handleVault(req, env, buildOf(env), noStore(), now, ids[i])),
  );
  return out.map((res) => res.status).sort();
}

describe("account vault storage", () => {
  test("a stored vault comes back byte for byte", async () => {
    const env = testEnv();
    const cookie = await makeAdmin(env);

    const wrote = await put(env, cookie, { ciphertext: CIPHER, nonce: NONCE, kdf: KDF, version: 0 });
    expect(wrote.status).toBe(200);
    expect(await bodyOf(wrote)).toEqual({ ok: true, version: 1 });

    const read = await vault(env, { cookie });
    expect(read.status).toBe(200);
    expect(await bodyOf(read)).toEqual({
      ok: true,
      vault: { ciphertext: CIPHER, nonce: NONCE, kdf: KDF, version: 1, updated_at: 2_000_000 },
    });
  });

  test("an account with no vault reads as unbound, not as an empty one", async () => {
    const env = testEnv();
    const cookie = await makeAdmin(env);
    const res = await vault(env, { cookie });
    expect(res.status).toBe(404);
    expect(await bodyOf(res)).toEqual({ ok: false, error: { code: "unbound" } });
  });

  test("each write advances the version by one", async () => {
    const env = testEnv();
    const cookie = await makeAdmin(env);
    await put(env, cookie, { ciphertext: CIPHER, nonce: NONCE, kdf: KDF, version: 0 });
    const second = await put(env, cookie, {
      ciphertext: "dXBkYXRlZA==",
      nonce: NONCE,
      kdf: KDF,
      version: 1,
    });
    expect(await bodyOf(second)).toEqual({ ok: true, version: 2 });

    const read = await vault(env, { cookie });
    expect((await bodyOf(read)).vault).toMatchObject({ ciphertext: "dXBkYXRlZA==", version: 2 });
  });
});

describe("vault write conflicts", () => {
  test("a stale writer is refused and the winning blob survives", async () => {
    const env = testEnv();
    const cookie = await makeAdmin(env);
    await put(env, cookie, { ciphertext: CIPHER, nonce: NONCE, kdf: KDF, version: 0 });
    await put(env, cookie, { ciphertext: "Zmlyc3Q=", nonce: NONCE, kdf: KDF, version: 1 });

    // This phone still believes version 1 is current; version 2 is.
    const stale = await put(env, cookie, {
      ciphertext: "c3RhbGU=",
      nonce: NONCE,
      kdf: KDF,
      version: 1,
    });
    expect(stale.status).toBe(409);
    expect(await bodyOf(stale)).toEqual({ ok: false, error: { code: "conflict", version: 2 } });

    const read = await vault(env, { cookie });
    expect((await bodyOf(read)).vault).toMatchObject({ ciphertext: "Zmlyc3Q=", version: 2 });
  });

  test("two creations race and only one wins", async () => {
    const env = testEnv();
    const cookie = await makeAdmin(env);
    const statuses = await race(env, cookie, [
      { ciphertext: "YQ==", nonce: NONCE, kdf: KDF, version: 0 },
      { ciphertext: "Yg==", nonce: NONCE, kdf: KDF, version: 0 },
    ]);
    expect(statuses).toEqual([200, 409]);

    const read = await vault(env, { cookie });
    expect((await bodyOf(read)).vault).toMatchObject({ version: 1 });
  });

  test("two updates from the same version race and only one wins", async () => {
    const env = testEnv();
    const cookie = await makeAdmin(env);
    await put(env, cookie, { ciphertext: CIPHER, nonce: NONCE, kdf: KDF, version: 0 });

    const statuses = await race(env, cookie, [
      { ciphertext: "YQ==", nonce: NONCE, kdf: KDF, version: 1 },
      { ciphertext: "Yg==", nonce: NONCE, kdf: KDF, version: 1 },
    ]);
    expect(statuses).toEqual([200, 409]);

    // The loser must not have overwritten the winner: exactly one bump happened.
    const read = await vault(env, { cookie });
    expect((await bodyOf(read)).vault).toMatchObject({ version: 2 });
  });

  test("a crowd of writers on one version yields exactly one winner", async () => {
    const env = testEnv();
    const cookie = await makeAdmin(env);
    await put(env, cookie, { ciphertext: CIPHER, nonce: NONCE, kdf: KDF, version: 0 });

    const statuses = await race(
      env,
      cookie,
      Array.from({ length: 6 }, (_, i) => ({
        ciphertext: "YQ==",
        nonce: NONCE,
        kdf: KDF,
        version: 1,
        seq: i,
      })),
    );
    expect(statuses.filter((s) => s === 200)).toHaveLength(1);
    expect(statuses.filter((s) => s === 409)).toHaveLength(5);

    const read = await vault(env, { cookie });
    expect((await bodyOf(read)).vault).toMatchObject({ version: 2 });
  });
});

describe("vault input limits", () => {
  test("a ciphertext over the ceiling is rejected and stores nothing", async () => {
    const env = testEnv();
    const cookie = await makeAdmin(env);
    const res = await put(env, cookie, {
      ciphertext: "A".repeat(VAULT_MAX_BYTES + 1),
      nonce: NONCE,
      kdf: KDF,
      version: 0,
    });
    expect(res.status).toBe(413);
    expect(await bodyOf(res)).toEqual({ ok: false, error: { code: "too_large" } });
    expect((await vault(env, { cookie })).status).toBe(404);
  });

  test("the ceiling counts UTF-8 bytes, not code units", async () => {
    const env = testEnv();
    const cookie = await makeAdmin(env);
    // Half the limit in characters, three bytes each: under the code-unit count
    // but over the byte budget.
    const res = await put(env, cookie, {
      ciphertext: "你".repeat(VAULT_MAX_BYTES / 2),
      nonce: NONCE,
      kdf: KDF,
      version: 0,
    });
    expect(res.status).toBe(413);
  });

  test("a payload exactly at the ceiling is accepted", async () => {
    const env = testEnv();
    const cookie = await makeAdmin(env);
    const res = await put(env, cookie, {
      ciphertext: "A".repeat(VAULT_MAX_BYTES),
      nonce: NONCE,
      kdf: KDF,
      version: 0,
    });
    expect(res.status).toBe(200);
  });

  test("non-base64 and missing fields are refused", async () => {
    const env = testEnv();
    const cookie = await makeAdmin(env);
    const bad: Array<Record<string, unknown>> = [
      { ciphertext: "not base64!", nonce: NONCE, kdf: KDF, version: 0 },
      { ciphertext: CIPHER, nonce: "nonce with spaces", kdf: KDF, version: 0 },
      { ciphertext: CIPHER, nonce: NONCE, kdf: "x".repeat(129), version: 0 },
      { ciphertext: CIPHER, nonce: NONCE, kdf: KDF },
      { ciphertext: CIPHER, nonce: NONCE, kdf: KDF, version: -1 },
      { ciphertext: CIPHER, nonce: NONCE, kdf: KDF, version: 1.5 },
      { ciphertext: CIPHER, nonce: NONCE, kdf: KDF, version: "1" },
      { ciphertext: "", nonce: NONCE, kdf: KDF, version: 0 },
      { nonce: NONCE, kdf: KDF, version: 0 },
      { ciphertext: 42, nonce: NONCE, kdf: KDF, version: 0 },
    ];
    for (const body of bad) {
      const res = await put(env, cookie, body);
      expect(await bodyOf(res)).toEqual({ ok: false, error: { code: "bad_token" } });
      expect(res.status).toBe(400);
    }
    expect((await vault(env, { cookie })).status).toBe(404);
  });

  test("a method the route does not serve is refused", async () => {
    const env = testEnv();
    const cookie = await makeAdmin(env);
    expect((await vault(env, { method: "DELETE", cookie })).status).toBe(405);
  });
});

describe("vault isolation", () => {
  test("one account never sees another's vault", async () => {
    const d1 = new FakeD1();
    const env = testEnv({ d1 });
    const admin = await makeAdmin(env);
    const invite = await inviteOf(env, admin);
    const member = await makeMember(env, "second-user", invite, 1_000_002);

    await put(env, admin, { ciphertext: CIPHER, nonce: NONCE, kdf: KDF, version: 0 });

    // The other account has no vault of its own and cannot reach this one.
    expect((await vault(env, { cookie: member })).status).toBe(404);

    // Writing at version 0 creates the member's own row rather than taking over.
    const wrote = await put(env, member, {
      ciphertext: "b3RoZXI=",
      nonce: NONCE,
      kdf: KDF,
      version: 0,
    });
    expect(wrote.status).toBe(200);

    const mine = await vault(env, { cookie: admin });
    expect((await bodyOf(mine)).vault).toMatchObject({ ciphertext: CIPHER });
    const theirs = await vault(env, { cookie: member });
    expect((await bodyOf(theirs)).vault).toMatchObject({ ciphertext: "b3RoZXI=" });
  });

  test("no cookie buys neither a read nor a write", async () => {
    const env = testEnv();
    await makeAdmin(env);
    const read = await vault(env, {});
    expect(read.status).toBe(401);
    expect(await bodyOf(read)).toEqual({ ok: false, error: { code: "unauthenticated" } });

    const wrote = await vault(env, {
      method: "PUT",
      body: { ciphertext: CIPHER, nonce: NONCE, kdf: KDF, version: 0 },
    });
    expect(wrote.status).toBe(401);
  });

  test("a forged cookie is not an identity", async () => {
    const env = testEnv();
    await makeAdmin(env);
    const res = await vault(env, { cookie: "pairfob_session=" + "a".repeat(64) });
    expect(res.status).toBe(401);
  });
});

/**
 * The double matches statements by string and reimplements them, so it cannot
 * show that the CAS predicate is the thing deciding the outcome. These run the
 * same statements against real SQLite over the real migrations.
 */
function migrated(): Database {
  const dir = join(import.meta.dir, "..", "migrations");
  const db = new Database(":memory:");
  for (const f of readdirSync(dir).filter((n) => n.endsWith(".sql")).sort()) {
    db.exec(readFileSync(join(dir, f), "utf8"));
  }
  return db;
}

function changes(db: Database, sql: string, ...values: unknown[]): number {
  return db.query(sql).run(...(values as never[])).changes;
}

test("the vault insert refuses a second create for one account", () => {
  const db = migrated();
  const args = (cipher: string) => ["u_a", cipher, NONCE, KDF, 1, 10, "u_a"];
  expect(changes(db, INSERT_VAULT_SQL, ...args("YQ=="))).toBe(1);
  expect(changes(db, INSERT_VAULT_SQL, ...args("Yg=="))).toBe(0);
  expect(db.query(SELECT_VAULT_SQL).get("u_a")).toMatchObject({ ciphertext: "YQ==", version: 1 });
});

test("the vault update writes only when the version still matches", () => {
  const db = migrated();
  changes(db, INSERT_VAULT_SQL, "u_a", "YQ==", NONCE, KDF, 1, 10, "u_a");

  expect(changes(db, UPDATE_VAULT_SQL, "Yg==", NONCE, KDF, 2, 20, "u_a", 0)).toBe(0);
  expect(changes(db, UPDATE_VAULT_SQL, "Yg==", NONCE, KDF, 2, 20, "u_a", 1)).toBe(1);
  // The version the loser held is now behind, so replaying it changes nothing.
  expect(changes(db, UPDATE_VAULT_SQL, "Yw==", NONCE, KDF, 2, 30, "u_a", 1)).toBe(0);
  expect(db.query(SELECT_VAULT_SQL).get("u_a")).toMatchObject({ ciphertext: "Yg==", version: 2 });
});

test("a vault update cannot reach across accounts", () => {
  const db = migrated();
  changes(db, INSERT_VAULT_SQL, "u_a", "YQ==", NONCE, KDF, 1, 10, "u_a");
  changes(db, INSERT_VAULT_SQL, "u_b", "Yg==", NONCE, KDF, 1, 10, "u_b");

  expect(changes(db, UPDATE_VAULT_SQL, "c3RvbGVu", NONCE, KDF, 2, 20, "u_b", 1)).toBe(1);
  expect(db.query(SELECT_VAULT_SQL).get("u_a")).toMatchObject({ ciphertext: "YQ==", version: 1 });
});
