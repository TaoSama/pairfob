import { getDeviceOwner, unbindDevice } from "./account-store.ts";
import { DAEMON_ID_RE, PROTOCOL, RECONNECT_TOKEN_RE } from "./constants.ts";
import { sha256Hex } from "./crypto.ts";
import { getDaemon } from "./d1.ts";
import type { Env } from "./env.ts";
import { buildOf, errorJson, hasBrowserOrigin, jsonResponse, noStore, readJSON } from "./http.ts";
import { observeError } from "./metrics.ts";

/**
 * Releases a computer from whatever account holds it, on the authority of the
 * computer itself. An owner who still has their account uses the account route
 * instead; this exists for the cases that one cannot reach — a binding made by
 * the wrong person, or an account that is gone.
 *
 * The reconnect token is the daemon's own secret, so presenting it means having
 * the machine. That is a fair tiebreaker against a remote claim: whoever is
 * sitting at the computer can always take it back, and nobody else can.
 */
export async function handleDeviceRelease(req: Request, env: Env, now = Date.now()): Promise<Response> {
  const build = buildOf(env);
  const store = noStore();
  if (req.method !== "POST") return errorJson(build, 405, "bad_token", store);
  // A page cannot speak for the daemon, and refusing browser origins keeps a
  // site the user happens to visit from driving this with a stolen token.
  if (hasBrowserOrigin(req)) return errorJson(build, 403, "forbidden", store);

  const body = await readJSON(req);
  const daemonId = typeof body?.daemon_id === "string" ? body.daemon_id : "";
  const token = typeof body?.reconnect_token === "string" ? body.reconnect_token : "";
  if (!body || body.v !== PROTOCOL || !DAEMON_ID_RE.test(daemonId) || !RECONNECT_TOKEN_RE.test(token)) {
    observeError(env, "bad_token", daemonId);
    return errorJson(build, 400, "bad_token", store);
  }

  const row = await getDaemon(env.DB, daemonId);
  if (!row || row.kicked_at != null) {
    observeError(env, "bad_token", daemonId);
    return errorJson(build, 400, "bad_token", store);
  }

  // Verified against the room, which is the authority on the reconnect secret.
  // A wrong token is refused there, so this route cannot be used to survey who
  // owns which device.
  if (!(await verifyToken(env, daemonId, await sha256Hex(token), row.grant_id))) {
    observeError(env, "bad_token", daemonId);
    return errorJson(build, 400, "bad_token", store);
  }

  const owner = await getDeviceOwner(env.DB, daemonId);
  const released = owner ? await unbindDevice(env.DB, daemonId, owner.user_id) : false;
  // Reported the same way whether or not a binding existed: having the machine
  // and finding it unbound is the outcome the caller wanted either way.
  return jsonResponse(build, 200, { ok: true, v: PROTOCOL, daemon_id: daemonId, released, at: now }, store);
}

async function verifyToken(
  env: Env,
  daemonId: string,
  reconnectHash: string,
  grantId: string,
): Promise<boolean> {
  try {
    const id = env.DAEMON_ROOM.idFromName(daemonId);
    const res = await env.DAEMON_ROOM.get(id).fetch(
      new Request("https://pairfob.internal/internal/verify-enroll", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ reconnect_hash: reconnectHash, grant_id: grantId }),
      }),
    );
    return res.ok;
  } catch {
    return false;
  }
}
