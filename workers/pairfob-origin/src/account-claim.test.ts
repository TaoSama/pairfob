import { beforeEach, expect, test } from "bun:test";
import { handleAccount } from "./account.ts";
import { readyClaimProof } from "./account-store.ts";
import { CLAIM_PROOF_TTL_MS } from "./constants.ts";
import { ZERO_ROUTE, routeHex, sha256Hex } from "./crypto.ts";
import { Typ } from "./envelope.ts";
import { encodeJSON } from "./frames.ts";
import { IndexCore } from "./index/pairing-index.ts";
import { resetLimits } from "./limits.ts";
import { handlePairIntent } from "./pair-intent.ts";
import type { FakeSocket } from "./room/fake-socket.ts";
import { onMessage } from "./room/ws.ts";
import {
  ORIGIN,
  type TestEnv,
  accountReq,
  bodyOf,
  enrollDaemonId,
  inviteOf,
  makeAdmin,
  makeMember,
  userIdOf,
} from "./testutil/account-harness.ts";
import { FakeD1 } from "./testutil/fake-d1.ts";
import { FakeIndexNamespace, FakeRoomNamespace } from "./testutil/fake-ns.ts";
import { PAIR_REF, lastJSON, makeRoom, testEnv } from "./testutil/make-room.ts";

beforeEach(() => resetLimits());

const NOW = Date.now();

/** The bootstrap account's username is minted, so it is read back from the table. */
function bootstrapName(d1: FakeD1): string {
  for (const u of d1.accounts.users.values()) if (u.role === "admin") return u.username;
  throw new Error("no bootstrap account");
}


function intentReq(loc: string, cookie?: string, ip = "198.51.100.4"): Request {
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    Origin: ORIGIN,
    "CF-Connecting-IP": ip,
  };
  if (cookie) headers.Cookie = cookie;
  return new Request(ORIGIN + "/v2/pair-intent", {
    method: "POST",
    headers,
    body: JSON.stringify({ v: 2, pair_loc: loc }),
  });
}

/**
 * Brings up a real daemon that has opened a pairing slot, so a pairing code
 * genuinely resolves. Nothing here is injected: the loc comes out of the room's
 * own slot after the daemon sent PAIR_OPEN over the real frame handler.
 */
async function pairingWorld() {
  const d1 = new FakeD1();
  const index = new IndexCore(new Map(), () => Date.now());
  const idxNs = new FakeIndexNamespace(index);
  // The witness is the same one `room.ts` installs in production: the room
  // reports the confirmation, D1 decides whether a pending proof matches it.
  const claims = {
    confirm: (account: string, routeId: string) =>
      readyClaimProof(d1, account, daemonId, routeId, Date.now()).then(() => undefined),
  };
  const rooms = new FakeRoomNamespace((name) => makeRoom(name, index, { claims }));
  const env = testEnv({ d1, rooms, index: idxNs });

  const ownerCookie = await makeAdmin(env, NOW);
  const invite = await inviteOf(env, ownerCookie, NOW + 1);
  const attackerCookie = await makeMember(env, "mallory", invite, NOW + 2);
  const daemonId = await enrollDaemonId(env, "71", NOW + 3);

  const h = makeRoom(daemonId, index, { claims });
  rooms.harnesses.set(daemonId, h);
  const token = "rt_" + "71".repeat(16);
  h.core.enroll({ reconnect_hash: await sha256Hex(token), grant_id: "g_" + "71".repeat(8) });
  const daemonWs = h.accept("daemon");
  expect(daemonWs.ok).toBe(true);
  await onMessage(
    h.core,
    daemonWs.ws!,
    encodeJSON(Typ.HELLO_DAEMON, ZERO_ROUTE, {
      v: 2,
      op: "RegisterDaemon",
      daemon_id: daemonId,
      reconnect_token: token,
    }),
  );
  await onMessage(
    h.core,
    daemonWs.ws!,
    encodeJSON(Typ.PAIR_OPEN, ZERO_ROUTE, {
      v: 2,
      op: "CreatePairing",
      daemon_id: daemonId,
      pair_ref: PAIR_REF,
      ttl_s: 180,
    }),
  );
  const loc = h.store.loadSlot()!.pair_loc;
  resetLimits();

  return { d1, env, rooms, harness: h, daemon: daemonWs.ws!, ownerCookie, attackerCookie, daemonId, loc };
}

/**
 * Drives the phone half over the real frame handlers: attach a session, then
 * let the daemon accept it. That acceptance is what the relay can witness, and
 * it is the only thing that arms a pending claim.
 */
async function attachSession(
  h: ReturnType<typeof makeRoom>,
  account: string,
  owner = "",
): Promise<{ phone: FakeSocket; routeId: Uint8Array }> {
  const phone = h.accept("phone", new URLSearchParams(), { account, owner });
  expect(phone.ok).toBe(true);
  await onMessage(h.core, phone.ws!, encodeJSON(Typ.HELLO_CLIENT, ZERO_ROUTE, { v: 2, protocol: 2 }));
  await onMessage(
    h.core,
    phone.ws!,
    encodeJSON(Typ.SESSION_ATTACH, ZERO_ROUTE, { v: 2, daemon_id: h.core.daemonId }),
  );
  return { phone: phone.ws!, routeId: lastJSON(phone.ws!).routeId };
}

async function confirm(h: ReturnType<typeof makeRoom>, daemon: FakeSocket, routeId: Uint8Array): Promise<void> {
  await onMessage(
    h.core,
    daemon,
    encodeJSON(Typ.SESSION_ESTABLISHED, routeId, { v: 2, route_id: routeHex(routeId) }),
  );
}

async function readProof(env: TestEnv, cookie: string, daemonId: string, now: number): Promise<Record<string, unknown>> {
  const res = await handleAccount(
    accountReq(`/v2/account/claim-proof?daemon_id=${daemonId}`, { cookie }),
    env,
    now,
  );
  expect(res?.status).toBe(200);
  return bodyOf(res);
}

async function claim(
  env: TestEnv,
  cookie: string,
  daemonId: string,
  proof: string,
  now: number,
): Promise<Response> {
  const res = await handleAccount(
    accountReq("/v2/account/devices", {
      method: "POST",
      cookie,
      body: { daemon_id: daemonId, claim_proof: proof },
    }),
    env,
    now,
  );
  return res!;
}

async function ownedBy(env: TestEnv, cookie: string, now: number): Promise<unknown[]> {
  const res = await handleAccount(accountReq("/v2/account/devices", { cookie }), env, now);
  return (await bodyOf(res)).devices as unknown[];
}

/**
 * The attacker never completes SPAKE2+: it only reads the pairing code off the
 * screen, which is exactly the capability the code is assumed to leak. If
 * resolving that code is enough to take ownership, a shoulder-surfed six
 * characters silently transfers the computer.
 */
test("reading a pairing code does not let a bystander take the computer", async () => {
  const { env, attackerCookie, daemonId, loc } = await pairingWorld();

  const intent = await handlePairIntent(intentReq(loc, attackerCookie), env, NOW + 10);
  expect(intent.status).toBe(200);

  const pending = await readProof(env, attackerCookie, daemonId, NOW + 11);
  expect(pending.ready).toBe(false);
  expect(pending.claim_proof).toBeUndefined();

  const claim = await handleAccount(
    accountReq("/v2/account/devices", {
      method: "POST",
      cookie: attackerCookie,
      body: { daemon_id: daemonId, claim_proof: (await bodyOf(intent)).claim_proof ?? "" },
    }),
    env,
    NOW + 11,
  );
  expect(claim?.status).not.toBe(201);

  const devices = await handleAccount(
    accountReq("/v2/account/devices", { cookie: attackerCookie }),
    env,
    NOW + 12,
  );
  expect((await bodyOf(devices)).devices).toEqual([]);
});

/**
 * The same walk the owner actually takes. Without this the refusals above would
 * also be satisfied by a relay that never lets anyone bind anything.
 */
test("a pairing the daemon accepts binds the device to the account that started it", async () => {
  const { env, harness, daemon, ownerCookie, daemonId, loc } = await pairingWorld();
  const ownerId = userIdOf(env.DB as FakeD1, bootstrapName(env.DB as FakeD1));

  const intent = await handlePairIntent(intentReq(loc, ownerCookie), env, NOW + 10);
  expect(intent.status).toBe(200);
  expect((await bodyOf(intent)).claim_proof).toBeUndefined();

  const { routeId } = await attachSession(harness, ownerId);
  expect((await readProof(env, ownerCookie, daemonId, NOW + 11)).ready).toBe(false);

  await confirm(harness, daemon, routeId);

  const armed = await readProof(env, ownerCookie, daemonId, NOW + 12);
  expect(armed.ready).toBe(true);
  const proof = String(armed.claim_proof);

  const bound = await claim(env, ownerCookie, daemonId, proof, NOW + 13);
  expect(bound.status).toBe(201);
  expect(await ownedBy(env, ownerCookie, NOW + 14)).toHaveLength(1);

  // One armed proof, one binding. A replay of the same value finds no row.
  expect((await claim(env, ownerCookie, daemonId, proof, NOW + 15)).status).toBe(200);
});

/**
 * Each of these is a step short of the full walk. They all run through the same
 * handlers as the passing case, so none of them can be satisfied by arming the
 * proof from the test.
 */
test("a session that is attached but never accepted arms nothing", async () => {
  const { env, harness, ownerCookie, daemonId, loc } = await pairingWorld();
  const ownerId = userIdOf(env.DB as FakeD1, bootstrapName(env.DB as FakeD1));

  await handlePairIntent(intentReq(loc, ownerCookie), env, NOW + 10);
  await attachSession(harness, ownerId);

  expect((await readProof(env, ownerCookie, daemonId, NOW + 11)).ready).toBe(false);
  expect(await ownedBy(env, ownerCookie, NOW + 12)).toEqual([]);
});

test("a confirmation for one account does not arm another account's pending proof", async () => {
  const { env, harness, daemon, ownerCookie, attackerCookie, daemonId, loc } = await pairingWorld();
  const ownerId = userIdOf(env.DB as FakeD1, bootstrapName(env.DB as FakeD1));

  // Both accounts resolve the code, so both hold a pending proof. Only the
  // owner's phone actually completes a session the daemon accepts.
  await handlePairIntent(intentReq(loc, ownerCookie), env, NOW + 10);
  await handlePairIntent(intentReq(loc, attackerCookie), env, NOW + 11);

  const { routeId } = await attachSession(harness, ownerId);
  await confirm(harness, daemon, routeId);

  expect((await readProof(env, attackerCookie, daemonId, NOW + 12)).ready).toBe(false);
  expect((await readProof(env, ownerCookie, daemonId, NOW + 12)).ready).toBe(true);
});

test("an armed proof is readable only by the session it was minted for", async () => {
  const { env, harness, daemon, ownerCookie, attackerCookie, daemonId, loc } = await pairingWorld();
  const ownerId = userIdOf(env.DB as FakeD1, bootstrapName(env.DB as FakeD1));

  await handlePairIntent(intentReq(loc, ownerCookie), env, NOW + 10);
  const { routeId } = await attachSession(harness, ownerId);
  await confirm(harness, daemon, routeId);
  const proof = String((await readProof(env, ownerCookie, daemonId, NOW + 11)).claim_proof);

  // Another account cannot read it, and cannot spend it even handed the value.
  expect((await readProof(env, attackerCookie, daemonId, NOW + 12)).ready).toBe(false);
  expect((await claim(env, attackerCookie, daemonId, proof, NOW + 13)).status).toBe(403);
  // Anonymous callers get no proof at all.
  const anon = await handleAccount(
    accountReq(`/v2/account/claim-proof?daemon_id=${daemonId}`),
    env,
    NOW + 14,
  );
  expect(anon?.status).toBe(401);
  expect(await ownedBy(env, attackerCookie, NOW + 15)).toEqual([]);
});

test("an armed proof stops working once it expires", async () => {
  const { env, harness, daemon, ownerCookie, daemonId, loc } = await pairingWorld();
  const ownerId = userIdOf(env.DB as FakeD1, bootstrapName(env.DB as FakeD1));

  const intentAt = NOW + 10;
  await handlePairIntent(intentReq(loc, ownerCookie), env, intentAt);
  const { routeId } = await attachSession(harness, ownerId);
  await confirm(harness, daemon, routeId);
  const proof = String((await readProof(env, ownerCookie, daemonId, NOW + 11)).claim_proof);

  // The TTL runs from the moment the code was resolved, not from arming.
  const late = intentAt + CLAIM_PROOF_TTL_MS + 1;
  expect((await readProof(env, ownerCookie, daemonId, late)).ready).toBe(false);
  expect((await claim(env, ownerCookie, daemonId, proof, late)).status).toBe(403);
  expect(await ownedBy(env, ownerCookie, late)).toEqual([]);
});

test("resolving a code without signing in mints no proof to arm", async () => {
  const { env, harness, daemon, daemonId, loc, ownerCookie } = await pairingWorld();

  const intent = await handlePairIntent(intentReq(loc), env, NOW + 10);
  expect(intent.status).toBe(200);
  expect((await bodyOf(intent)).claim_proof).toBeUndefined();

  // The worker already refuses an anonymous upgrade, so this drives the room
  // directly to check the layer underneath: even if a socket arrived with no
  // account, a confirmation on it has nobody to attribute and arms nothing.
  const { routeId } = await attachSession(harness, "");
  await confirm(harness, daemon, routeId);
  expect((await readProof(env, ownerCookie, daemonId, NOW + 11)).ready).toBe(false);
});


