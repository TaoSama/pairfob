import { beforeEach, expect, test } from "bun:test";
import { handleAccount } from "./account.ts";
import { kickDaemonRow } from "./d1.ts";
import { handleDeviceRelease } from "./device-release.ts";
import { IndexCore } from "./index/pairing-index.ts";
import { resetLimits } from "./limits.ts";
import { handleFetch } from "./worker.ts";
import {
  ORIGIN,
  accountReq,
  bodyOf,
  enrollDaemonId,
  inviteOf,
  makeAdmin,
  makeMember,
  proofFor,
  type TestEnv,
} from "./testutil/account-harness.ts";
import { FakeD1 } from "./testutil/fake-d1.ts";
import { FakeIndexNamespace, FakeRoomNamespace } from "./testutil/fake-ns.ts";
import { makeRoom, testEnv } from "./testutil/make-room.ts";

beforeEach(() => resetLimits());

const NOW = 3_000_000;

/** The daemon speaks for itself, so it sends no cookie and no browser Origin. */
function releaseReq(daemonId: string, token: string): Request {
  return new Request(ORIGIN + "/v2/device-release", {
    method: "POST",
    headers: { "Content-Type": "application/json", "CF-Connecting-IP": "198.51.100.9" },
    body: JSON.stringify({ v: 2, daemon_id: daemonId, reconnect_token: token }),
  });
}

function tokenFor(seed: string): string {
  return "rt_" + seed.repeat(16);
}

/** One enrolled device, bound to the admin, with a stranger account standing by. */
async function boundWorld(seed = "61") {
  const d1 = new FakeD1();
  const index = new IndexCore(new Map(), () => Date.now());
  const rooms = new FakeRoomNamespace((name) => makeRoom(name, index));
  const env = testEnv({ d1, rooms, index: new FakeIndexNamespace(index) });

  const ownerCookie = await makeAdmin(env, NOW);
  const invite = await inviteOf(env, ownerCookie, NOW + 1);
  const strangerCookie = await makeMember(env, "diana", invite, NOW + 2);
  const daemonId = await enrollDaemonId(env, seed, NOW + 3);

  const bind = await handleAccount(
    accountReq("/v2/account/devices", {
      method: "POST",
      cookie: ownerCookie,
      body: { daemon_id: daemonId, claim_proof: await proofFor(d1, "admin", daemonId, NOW + 4) },
    }),
    env,
    NOW + 4,
  );
  expect(bind?.status).toBe(201);
  resetLimits();

  return { d1, env, ownerCookie, strangerCookie, daemonId, token: tokenFor(seed) };
}

async function devices(env: TestEnv, cookie: string, now: number): Promise<unknown[]> {
  const res = await handleAccount(accountReq("/v2/account/devices", { cookie }), env, now);
  return (await bodyOf(res)).devices as unknown[];
}

test("the computer itself can break a binding it should not be under", async () => {
  const { env, ownerCookie, daemonId, token } = await boundWorld();

  const res = await handleDeviceRelease(releaseReq(daemonId, token), env, NOW + 10);
  expect(res.status).toBe(200);
  expect(await bodyOf(res)).toMatchObject({ ok: true, daemon_id: daemonId, released: true });

  // The account that held it no longer does, so the device is free to be paired
  // again by whoever is actually at the keyboard.
  expect(await devices(env, ownerCookie, NOW + 11)).toEqual([]);
});

test("a wrong reconnect token releases nothing", async () => {
  const { env, ownerCookie, daemonId } = await boundWorld("62");

  const res = await handleDeviceRelease(releaseReq(daemonId, tokenFor("ff")), env, NOW + 10);
  expect(res.status).toBe(400);
  expect(await devices(env, ownerCookie, NOW + 11)).toHaveLength(1);
});

test("the release route does not reveal whether a device is bound", async () => {
  const { env, daemonId } = await boundWorld("63");

  // An unbound device and a bound one both answer 200, and a bad token answers
  // 400 either way, so this cannot be used to survey ownership.
  const bound = await handleDeviceRelease(releaseReq(daemonId, tokenFor("63")), env, NOW + 10);
  const again = await handleDeviceRelease(releaseReq(daemonId, tokenFor("63")), env, NOW + 11);
  expect(bound.status).toBe(200);
  expect(again.status).toBe(200);
  expect((await bodyOf(again)).released).toBe(false);
});

test("a browser cannot drive the release route", async () => {
  const { env, ownerCookie, daemonId, token } = await boundWorld("64");

  const req = new Request(ORIGIN + "/v2/device-release", {
    method: "POST",
    headers: { "Content-Type": "application/json", Origin: ORIGIN, "CF-Connecting-IP": "198.51.100.9" },
    body: JSON.stringify({ v: 2, daemon_id: daemonId, reconnect_token: token }),
  });
  const res = await handleDeviceRelease(req, env, NOW + 10);
  expect(res.status).toBe(403);
  expect(await devices(env, ownerCookie, NOW + 11)).toHaveLength(1);
});

test("a kicked computer cannot release anything", async () => {
  const { env, ownerCookie, daemonId, token } = await boundWorld("67");
  await kickDaemonRow(env.DB, daemonId, NOW + 5);

  const res = await handleDeviceRelease(releaseReq(daemonId, token), env, NOW + 10);
  expect(res.status).toBe(400);
  // The binding is untouched, so a kicked machine cannot be used to strip the
  // owner's record of it.
  expect(await devices(env, ownerCookie, NOW + 11)).toHaveLength(1);
});

test("the release route is reachable through the worker", async () => {
  const { env, ownerCookie, daemonId, token } = await boundWorld("68");

  const res = await handleFetch(releaseReq(daemonId, token), env);
  expect(res.status).toBe(200);
  expect((await bodyOf(res)).released).toBe(true);
  expect(await devices(env, ownerCookie, NOW + 11)).toEqual([]);
});

test("a stranger's account cannot unbind someone else's device", async () => {
  const { env, ownerCookie, strangerCookie, daemonId } = await boundWorld("65");

  const res = await handleAccount(
    accountReq(`/v2/account/devices/${daemonId}`, { method: "DELETE", cookie: strangerCookie }),
    env,
    NOW + 10,
  );
  expect(res?.status).toBe(404);
  expect(await devices(env, ownerCookie, NOW + 11)).toHaveLength(1);
});

test("the owner can release their own device without the machine", async () => {
  const { env, ownerCookie, daemonId } = await boundWorld("66");

  const res = await handleAccount(
    accountReq(`/v2/account/devices/${daemonId}`, { method: "DELETE", cookie: ownerCookie }),
    env,
    NOW + 10,
  );
  expect(res?.status).toBe(200);
  expect(await devices(env, ownerCookie, NOW + 11)).toEqual([]);
});
