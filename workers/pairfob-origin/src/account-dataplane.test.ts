import { beforeEach, describe, expect, test } from "bun:test";
import { handleAccount } from "./account.ts";
import { ACCOUNT_HEADER, DEVICE_OWNER_HEADER } from "./constants.ts";
import { IndexCore } from "./index/pairing-index.ts";
import { resetLimits } from "./limits.ts";
import { newAttachment, ownerMismatch } from "./room/attachment.ts";
import { handlePairAttach } from "./room/pairing.ts";
import { handleSessionAttach } from "./room/session.ts";
import { FakeD1 } from "./testutil/fake-d1.ts";
import { FakeIndexNamespace, FakeRoomNamespace } from "./testutil/fake-ns.ts";
import { makeRoom, testEnv } from "./testutil/make-room.ts";
import { handleFetch } from "./worker.ts";
import {
  ORIGIN,
  accountReq,
  enrollDaemonId,
  inviteOf,
  makeAdmin,
  makeMember,
  proofFor,
  userIdOf,
} from "./testutil/account-harness.ts";
import { encodeJSON } from "./frames.ts";
import { Typ, decode } from "./envelope.ts";
import { ZERO_ROUTE } from "./crypto.ts";

beforeEach(() => resetLimits());

function wsReq(daemonId: string, cookie?: string): Request {
  const headers: Record<string, string> = {
    Upgrade: "websocket",
    "Sec-WebSocket-Protocol": "pairfob.v2",
    Origin: ORIGIN,
    "CF-Connecting-IP": "203.0.113.55",
  };
  if (cookie) headers.Cookie = cookie;
  return new Request(`${ORIGIN}/v2/ws?role=client&daemon_id=${daemonId}`, { headers });
}

/** Upgrade attempts that actually reached the durable object. Enrollment also
 * talks to the room, so the raw log is never empty by the time a test runs. */
function wsReached(rooms: FakeRoomNamespace): string[] {
  return rooms.fetchLog.filter((p) => p.startsWith("/v2/ws"));
}

/**
 * Sessions are minted at this instant because `routeWs` resolves them against
 * the wall clock, so a fixture on an arbitrary timeline reads as expired.
 */
const NOW = Date.now();

/** Signs in an owner, a bystander, and binds one enrolled device to the owner. */
async function boundWorld(now = NOW) {
  const d1 = new FakeD1();
  const index = new IndexCore(new Map(), () => Date.now());
  const idxNs = new FakeIndexNamespace(index);
  const rooms = new FakeRoomNamespace((name) => makeRoom(name, index));
  const env = testEnv({ d1, rooms, index: idxNs });

  const ownerCookie = await makeAdmin(env, now);
  const invite = await inviteOf(env, ownerCookie, now + 1);
  const strangerCookie = await makeMember(env, "diana", invite, now + 2);
  const daemonId = await enrollDaemonId(env, "51", now + 3);

  const bind = await handleAccount(
    accountReq("/v2/account/devices", {
      method: "POST",
      cookie: ownerCookie,
      body: { daemon_id: daemonId, claim_proof: await proofFor(d1, "admin", daemonId, now + 4) },
    }),
    env,
    now + 4,
  );
  expect(bind?.status).toBe(201);
  resetLimits();

  return { d1, env, rooms, ownerCookie, strangerCookie, daemonId };
}

describe("websocket upgrade ownership", () => {
  test("the owner reaches the room and the stranger does not", async () => {
    const { env, rooms, ownerCookie, strangerCookie, daemonId } = await boundWorld();

    const stranger = await handleFetch(wsReq(daemonId, strangerCookie), env);
    expect(stranger.status).toBe(403);
    expect(await stranger.json()).toEqual({ ok: false, error: { code: "forbidden" } });
    // Refused in the worker, so the durable object is never even activated.
    expect(wsReached(rooms)).toEqual([]);

    const owner = await handleFetch(wsReq(daemonId, ownerCookie), env);
    expect(owner.status).toBe(101);
    expect(wsReached(rooms).length).toBe(1);
  });

  test("an anonymous caller cannot reach a bound computer", async () => {
    const { env, rooms, daemonId } = await boundWorld();
    const res = await handleFetch(wsReq(daemonId), env);
    expect(res.status).toBe(403);
    expect(wsReached(rooms)).toEqual([]);
  });

  test("an unbound computer is reachable by any signed-in account but not anonymously", async () => {
    const d1 = new FakeD1();
    const index = new IndexCore(new Map(), () => Date.now());
    const rooms = new FakeRoomNamespace((name) => makeRoom(name, index));
    const env = testEnv({ d1, rooms, index: new FakeIndexNamespace(index) });
    const cookie = await makeAdmin(env, NOW);
    const daemonId = await enrollDaemonId(env, "52", NOW + 1);
    resetLimits();

    // Nobody owns this device yet, so any account may pair with it. That is how
    // ownership starts. An anonymous caller is still turned away: a claim has to
    // belong to someone, and the device id alone is not a credential.
    const anon = await handleFetch(wsReq(daemonId), env);
    expect(anon.status).toBe(403);
    expect(wsReached(rooms)).toEqual([]);

    const signedIn = await handleFetch(wsReq(daemonId, cookie), env);
    expect(signedIn.status).toBe(101);
    expect(wsReached(rooms).length).toBe(1);
  });

  test("the upgrade carries the ownership verdict inward", async () => {
    const { env, rooms, ownerCookie, daemonId } = await boundWorld();
    const stub = rooms.get(rooms.idFromName(daemonId));
    let seen: Request | null = null;
    const original = stub.fetch.bind(stub);
    const spy = { fetch: async (r: Request) => { seen = r; return original(r); } };
    const namespace = env.DAEMON_ROOM as unknown as { get: (id: DurableObjectId) => typeof spy };
    const realGet = namespace.get;
    namespace.get = () => spy;

    await handleFetch(wsReq(daemonId, ownerCookie), env);
    namespace.get = realGet;

    expect(seen).not.toBeNull();
    const ownerId = userIdOf((env.DB as FakeD1), "admin");
    expect(seen!.headers.get(ACCOUNT_HEADER)).toBe(ownerId);
    expect(seen!.headers.get(DEVICE_OWNER_HEADER)).toBe(ownerId);
  });

  test("a spoofed ownership header does not survive the worker", async () => {
    const { env, rooms, strangerCookie, daemonId } = await boundWorld();
    const strangerId = userIdOf(env.DB as FakeD1, "diana");

    // The client sets both headers to itself. The worker recomputes them from
    // D1 before forwarding, so the forgery buys nothing.
    const req = new Request(`${ORIGIN}/v2/ws?role=client&daemon_id=${daemonId}`, {
      headers: {
        Upgrade: "websocket",
        "Sec-WebSocket-Protocol": "pairfob.v2",
        Origin: ORIGIN,
        "CF-Connecting-IP": "203.0.113.56",
        Cookie: strangerCookie,
        [ACCOUNT_HEADER]: strangerId,
        [DEVICE_OWNER_HEADER]: strangerId,
      },
    });
    const res = await handleFetch(req, env);
    expect(res.status).toBe(403);
    expect(wsReached(rooms)).toEqual([]);
  });
});

describe("in-room attachment ownership", () => {
  function lastFrame(ws: { sent: Uint8Array[] }): Record<string, unknown> {
    const f = decode(ws.sent[ws.sent.length - 1]);
    return JSON.parse(new TextDecoder().decode(f.payload)) as Record<string, unknown>;
  }

  test("ownerMismatch admits the owner and an unbound device only", () => {
    const base = (account: string, owner: string) => newAttachment("phone", 0, { account, owner });
    expect(ownerMismatch(base("u_a", "u_a"))).toBe(false);
    expect(ownerMismatch(base("u_a", ""))).toBe(false);
    expect(ownerMismatch(base("", ""))).toBe(false);
    expect(ownerMismatch(base("u_b", "u_a"))).toBe(true);
    expect(ownerMismatch(base("", "u_a"))).toBe(true);
    expect(ownerMismatch(newAttachment("daemon", 0, { account: "", owner: "u_a" }))).toBe(false);
  });

  test("SESSION_ATTACH from another account is refused inside the room", async () => {
    const daemonId = "d_" + "ab".repeat(10);
    const h = makeRoom(daemonId);
    const acc = h.accept("phone", new URLSearchParams(), { account: "u_stranger", owner: "u_owner" });
    expect(acc.ok).toBe(true);
    const ws = acc.ws!;

    await handleSessionAttach(
      h.core,
      ws,
      decode(encodeJSON(Typ.SESSION_ATTACH, ZERO_ROUTE, { v: 2, daemon_id: daemonId })),
    );
    expect(lastFrame(ws)).toMatchObject({ code: "forbidden" });
    expect(ws.closed).toBe(true);
    expect(h.core.countKinds()).toMatchObject({ resume: 0, est: 0 });
  });

  test("PAIR_ATTACH from another account is refused inside the room", async () => {
    const daemonId = "d_" + "ac".repeat(10);
    const h = makeRoom(daemonId);
    const acc = h.accept("phone", new URLSearchParams(), { account: "u_stranger", owner: "u_owner" });
    const ws = acc.ws!;

    await handlePairAttach(
      h.core,
      ws,
      decode(encodeJSON(Typ.PAIR_ATTACH, ZERO_ROUTE, { v: 2, pair_ref: "4f".repeat(16) })),
    );
    expect(lastFrame(ws)).toMatchObject({ code: "forbidden" });
    expect(ws.closed).toBe(true);
    expect(h.core.countKinds()).toMatchObject({ pairing: 0 });
  });

  test("the owner's own attachment is not refused by the ownership check", async () => {
    const daemonId = "d_" + "ad".repeat(10);
    const h = makeRoom(daemonId);
    const acc = h.accept("phone", new URLSearchParams(), { account: "u_owner", owner: "u_owner" });
    const ws = acc.ws!;

    await handleSessionAttach(
      h.core,
      ws,
      decode(encodeJSON(Typ.SESSION_ATTACH, ZERO_ROUTE, { v: 2, daemon_id: daemonId })),
    );
    // It still fails, but on the HELLO grace rule rather than ownership.
    expect(lastFrame(ws)).toMatchObject({ code: "unbound" });
  });
});
