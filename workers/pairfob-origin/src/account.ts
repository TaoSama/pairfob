import {
  AUTH_LOCKOUT_MS,
  AUTH_LOCKOUT_STRIKES,
  CLAIM_PROOF_RE,
  DAEMON_ID_RE,
  INVITE_GLOBAL_STRIKES,
  LOGIN_LOCKOUT_STRIKES,
  PROTOCOL,
  ROLE_ADMIN,
  ROLE_MEMBER,
  SESSION_TTL_MS,
} from "./constants.ts";
import { hashPassword, randomHex, timingSafeEqual, verifyPassword } from "./crypto.ts";
import {
  bindDevice,
  clearAuthDomain,
  consumeClaimProof,
  countUsers,
  deleteSession,
  getDeviceOwner,
  getInvite,
  getReadyProof,
  getUserByName,
  insertFirstUser,
  insertUser,
  listDevicesByUser,
  lockSubject,
  lockedUntil,
  putInvite,
  releaseFailureBudget,
  reserveFailureBudget,
  suspendInvite,
  unbindDevice,
  type UserRow,
} from "./account-store.ts";
import {
  bootstrapUsername,
  clearedSessionCookie,
  type Identity,
  inviteGlobalSubject,
  isAdmin,
  issueSession,
  mintInviteCode,
  newUserId,
  normalizeDeviceLabel,
  normalizeInviteCode,
  normalizePassword,
  normalizeUsername,
  publicUser,
  resolveIdentity,
  sessionCookie,
  sourceSubject,
} from "./account-auth.ts";
import { getDaemon } from "./d1.ts";
import { handleVault } from "./account-vault.ts";
import type { Env } from "./env.ts";
import {
  buildOf,
  clientIP,
  errorJson,
  errorJsonWithDetail,
  isSameHostOrigin,
  jsonResponse,
  noStore,
  readJSON,
  requireSameHostBrowserOrigin,
} from "./http.ts";
import { allowAuthIP } from "./limits.ts";
import { observeError } from "./metrics.ts";

const PREFIX = "/v2/account";

export async function handleAccount(req: Request, env: Env, now = Date.now()): Promise<Response | null> {
  const url = new URL(req.url);
  const path = url.pathname;
  if (path !== PREFIX && !path.startsWith(PREFIX + "/")) return null;

  const build = buildOf(env);
  const store = noStore();
  if (!env.IP_HASH_PEPPER) return errorJson(build, 500, "internal", store);
  // A read has no effect to forge, and demanding an Origin on it breaks clients
  // that omit the header. Anything that writes keeps the strict same-origin
  // requirement, which is what stops a cookie being replayed from another site.
  const originOk = req.method === "GET" ? isSameHostOrigin(req) : requireSameHostBrowserOrigin(req);
  if (!originOk) return errorJson(build, 403, "forbidden", store);
  if (!allowAuthIP(clientIP(req), now)) {
    observeError(env, "rate_limited");
    return errorJson(build, 429, "rate_limited", store);
  }

  try {
    return await route(path, req, env, build, store, now);
  } catch {
    observeError(env, "internal");
    return errorJson(build, 500, "internal", store);
  }
}

async function route(
  path: string,
  req: Request,
  env: Env,
  build: string,
  store: Record<string, string>,
  now: number,
): Promise<Response> {
  const method = req.method;
  if (path === `${PREFIX}/state` && method === "GET") return state(req, env, build, store, now);
  if (path === `${PREFIX}/bootstrap` && method === "POST") return bootstrap(req, env, build, store, now);
  if (path === `${PREFIX}/login` && method === "POST") return login(req, env, build, store, now);
  if (path === `${PREFIX}/register` && method === "POST") return register(req, env, build, store, now);
  if (path === `${PREFIX}/logout` && method === "POST") return logout(req, env, build, store, now);
  if (path === `${PREFIX}/invite` && method === "GET") return readInvite(req, env, build, store, now);
  if (path === `${PREFIX}/invite/rotate` && method === "POST") {
    return rotateInvite(req, env, build, store, now);
  }
  if (path === `${PREFIX}/devices` && method === "GET") return listDevices(req, env, build, store, now);
  if (path === `${PREFIX}/devices` && method === "POST") return claimDevice(req, env, build, store, now);
  if (path === `${PREFIX}/claim-proof` && method === "GET") return readClaimProof(req, env, build, store, now);
  if (path === `${PREFIX}/vault`) return handleVault(req, env, build, store, now);

  const unbind = new RegExp(`^${PREFIX}/devices/([^/]+)$`).exec(path);
  if (unbind && method === "DELETE") {
    return releaseDevice(decodeURIComponent(unbind[1]), req, env, build, store, now);
  }
  return errorJson(build, 404, "unbound", store);
}

async function state(
  req: Request,
  env: Env,
  build: string,
  store: Record<string, string>,
  now: number,
): Promise<Response> {
  const identity = await resolveIdentity(env.DB, req, now);
  const initialized = identity !== null || (await countUsers(env.DB)) > 0;
  return jsonResponse(
    build,
    200,
    {
      ok: true,
      v: PROTOCOL,
      initialized,
      user: identity ? publicUser(identity.user) : null,
    },
    store,
  );
}

/**
 * The very first account is opened with a dedicated bootstrap token. It is an
 * ordinary member account that additionally owns the invite code; it has no
 * visibility into anyone else's devices.
 */
async function bootstrap(
  req: Request,
  env: Env,
  build: string,
  store: Record<string, string>,
  now: number,
): Promise<Response> {
  if (!env.BOOTSTRAP_SERVICE_TOKEN) return errorJson(build, 503, "internal", store);

  // Answered before the token is examined: once an account exists this route is
  // closed for everyone, so a replayed token cannot even probe the comparison.
  if ((await countUsers(env.DB)) > 0) return errorJson(build, 409, "already_initialized", store);

  const ip = clientIP(req);
  const ipKey = await sourceSubject(env.IP_HASH_PEPPER, "bootstrap", ip);

  const body = await readJSON(req);
  const password = normalizePassword(body?.password);
  const token = typeof body?.service_token === "string" ? body.service_token : "";
  if (!body || !password || !token) return errorJson(build, 400, "bad_token", store);

  if ((await lockedUntil(env.DB, ipKey, now)) > 0) return lockedOut(build, store);
  const reserved = await reserveFailureBudget(env.DB, ipKey, now);
  if (!reserved.granted) return lockedOut(build, store);

  if (!timingSafeEqual(token, env.BOOTSTRAP_SERVICE_TOKEN)) {
    // The reservation held a place in the burst; the ban is decided here, where
    // the token is known to be wrong, and runs a full hour from this moment.
    if (reserved.strikes >= AUTH_LOCKOUT_STRIKES) await lockSubject(env.DB, ipKey, now);
    observeError(env, "forbidden");
    return errorJson(build, 401, "bad_credentials", store);
  }
  await releaseFailureBudget(env.DB, reserved);

  const user: UserRow = {
    user_id: newUserId(),
    username: bootstrapUsername(),
    password_hash: await hashPassword(password),
    role: ROLE_ADMIN,
    created_at: now,
  };
  if (!(await insertFirstUser(env.DB, user))) {
    return errorJson(build, 409, "already_initialized", store);
  }
  await putInvite(env.DB, mintInviteCode(), user.user_id, now);
  await clearAuthDomain(env.DB, ipKey);

  return signedIn(env, build, store, user, now, 201);
}

async function login(
  req: Request,
  env: Env,
  build: string,
  store: Record<string, string>,
  now: number,
): Promise<Response> {
  const ipKey = await sourceSubject(env.IP_HASH_PEPPER, "login", clientIP(req));

  const body = await readJSON(req);
  const username = normalizeUsername(body?.username);
  const password = typeof body?.password === "string" ? body.password.trim() : "";
  if (!body || !username || !password) return errorJson(build, 400, "bad_token", store);

  // Throttled per source only. Counting failures against the username would let
  // anyone lock a known account out of every address it might sign in from.
  // The strike is taken before the password is derived, so a burst of guesses
  // cannot all get past the limit while the first derivation is still running.
  if ((await lockedUntil(env.DB, ipKey, now)) > 0) return lockedOut(build, store);
  const reserved = await reserveFailureBudget(env.DB, ipKey, now, LOGIN_LOCKOUT_STRIKES);
  if (!reserved.granted) return lockedOut(build, store);

  const user = await getUserByName(env.DB, username);
  // An unknown username still pays one derivation against a decoy record, so
  // the response time does not separate "no such account" from "wrong password".
  const ok = await verifyPassword(user ? user.password_hash : await decoyHash(), password);
  if (!user || !ok) {
    if (reserved.strikes >= LOGIN_LOCKOUT_STRIKES) await lockSubject(env.DB, ipKey, now);
    observeError(env, "forbidden");
    return errorJsonWithDetail(
      build,
      401,
      "bad_credentials",
      { remaining: Math.max(0, LOGIN_LOCKOUT_STRIKES - reserved.strikes) },
      store,
    );
  }

  // Only the sign-in domain is forgiven. Clearing the invite domain here is what
  // let a source alternate two wrong codes with one correct password forever.
  await releaseFailureBudget(env.DB, reserved);
  await clearAuthDomain(env.DB, ipKey);
  return signedIn(env, build, store, user, now, 200);
}

/**
 * Three wrong invite codes from one source cost that source an hour.
 *
 * The strike is taken before the stored code is read, not after it is compared.
 * Reserving afterwards means a burst that arrives together is all past the
 * limit check before the first of them writes anything, so the fourth through
 * sixth guesses are free; the budget has to be spent by arriving, and handed
 * back only once the attempt turns out not to be a wrong code.
 */
async function register(
  req: Request,
  env: Env,
  build: string,
  store: Record<string, string>,
  now: number,
): Promise<Response> {
  const ipKey = await sourceSubject(env.IP_HASH_PEPPER, "invite", clientIP(req));

  const body = await readJSON(req);
  const username = normalizeUsername(body?.username);
  const password = normalizePassword(body?.password);
  const invite = normalizeInviteCode(body?.invite_code);
  // A malformed request never reached the code, so it costs nothing: otherwise
  // a client with a typo in its username spends the budget for the real code.
  if (!body || !username || !password || !invite) return errorJson(build, 400, "bad_token", store);

  if ((await lockedUntil(env.DB, ipKey, now)) > 0) return lockedOut(build, store);
  const source = await reserveFailureBudget(env.DB, ipKey, now);
  if (!source.granted) return lockedOut(build, store);

  // Read before the global budget is reserved, so the version this attempt is
  // judged against is the one whose code it is about to be compared with.
  const current = await getInvite(env.DB);
  if (!current) {
    await releaseFailureBudget(env.DB, source);
    return errorJson(build, 409, "not_initialized", store);
  }

  // The global budget covers a guess spread thinly across many sources, which
  // no per-source count can see. It is a separate ceiling with its own limit,
  // tied to this code's version so a rotation starts it over.
  const globalKey = inviteGlobalSubject(current.version);
  const global = await reserveFailureBudget(env.DB, globalKey, now, INVITE_GLOBAL_STRIKES);
  if (!global.granted) {
    await releaseFailureBudget(env.DB, source);
    return errorJson(build, 409, "invite_suspended", store);
  }

  const refund = async () => {
    await releaseFailureBudget(env.DB, source);
    await releaseFailureBudget(env.DB, global);
  };

  if (current.suspended_at > 0) {
    await refund();
    return errorJson(build, 409, "invite_suspended", store);
  }
  if (!timingSafeEqual(invite, current.code)) {
    // Both strikes stay spent. The global one is what suspends the code once a
    // campaign has burned through its ceiling from any number of addresses, and
    // it names the version so a late loser cannot suspend a newer code.
    if (global.strikes >= INVITE_GLOBAL_STRIKES) await suspendInvite(env.DB, now, current.version);
    observeError(env, "forbidden");
    if (source.strikes >= AUTH_LOCKOUT_STRIKES) {
      await lockSubject(env.DB, ipKey, now);
      return lockedOut(build, store);
    }
    return errorJson(build, 401, "bad_invite", store);
  }

  // The code was right, so neither strike was a wrong-credential attempt.
  await refund();

  const user: UserRow = {
    user_id: newUserId(),
    username,
    password_hash: await hashPassword(password),
    role: ROLE_MEMBER,
    created_at: now,
  };
  if (!(await insertUser(env.DB, user))) return errorJson(build, 409, "username_taken", store);

  // Only this source's invite budget is forgiven. Clearing the global counter
  // here would let one successful registration reset a code-guessing campaign.
  await clearAuthDomain(env.DB, ipKey);
  return signedIn(env, build, store, user, now, 201);
}

async function logout(
  req: Request,
  env: Env,
  build: string,
  store: Record<string, string>,
  now: number,
): Promise<Response> {
  const identity = await resolveIdentity(env.DB, req, now);
  if (identity) await deleteSession(env.DB, identity.tokenHash);
  // An absent or stale cookie is still answered with a clearing Set-Cookie so a
  // client can always reach a signed-out state.
  return jsonResponse(build, 200, { ok: true }, { ...store, "Set-Cookie": clearedSessionCookie() });
}

async function readInvite(
  req: Request,
  env: Env,
  build: string,
  store: Record<string, string>,
  now: number,
): Promise<Response> {
  const identity = await requireAdmin(env, req, now);
  if (!identity) return errorJson(build, 403, "forbidden", store);
  const row = await getInvite(env.DB);
  if (!row) return errorJson(build, 409, "not_initialized", store);
  return jsonResponse(build, 200, { ok: true, invite_code: row.code, updated_at: row.updated_at }, store);
}

/**
 * Rotating mints a new code and, with it, a new global budget: the version
 * moves, and the budget is addressed by version, so the exhausted one belongs
 * to a code nobody can present any more. Without that, an administrator who
 * rotated after a campaign found the fresh code refused for the rest of the
 * hour — the suspension was lifted but the ceiling that caused it was not.
 *
 * Source-level bans are untouched. They are a fact about an address that
 * guessed, and rotating the code is not a reason to forgive it.
 */
async function rotateInvite(
  req: Request,
  env: Env,
  build: string,
  store: Record<string, string>,
  now: number,
): Promise<Response> {
  const identity = await requireAdmin(env, req, now);
  if (!identity) return errorJson(build, 403, "forbidden", store);
  const code = mintInviteCode();
  await putInvite(env.DB, code, identity.user.user_id, now);
  const row = await getInvite(env.DB);
  return jsonResponse(
    build,
    200,
    { ok: true, invite_code: code, updated_at: now, version: row?.version ?? 0 },
    store,
  );
}

async function listDevices(
  req: Request,
  env: Env,
  build: string,
  store: Record<string, string>,
  now: number,
): Promise<Response> {
  const identity = await resolveIdentity(env.DB, req, now);
  if (!identity) return errorJson(build, 401, "unauthenticated", store);
  const rows = await listDevicesByUser(env.DB, identity.user.user_id);
  const devices = [];
  for (const row of rows) {
    const daemon = await getDaemon(env.DB, row.daemon_id);
    devices.push({
      daemon_id: row.daemon_id,
      label: row.label,
      bound_at: row.bound_at,
      live: daemon != null && daemon.kicked_at == null,
    });
  }
  return jsonResponse(build, 200, { ok: true, devices }, store);
}

/**
 * Ownership is recorded only against a proof the relay issued to this account
 * when it resolved a pairing code to this daemon. A daemon id on its own is an
 * identifier anyone may learn, so it authorizes nothing. The pairing keys
 * themselves never reach the relay.
 */
async function claimDevice(
  req: Request,
  env: Env,
  build: string,
  store: Record<string, string>,
  now: number,
): Promise<Response> {
  const identity = await resolveIdentity(env.DB, req, now);
  if (!identity) return errorJson(build, 401, "unauthenticated", store);

  const body = await readJSON(req);
  const daemonId = typeof body?.daemon_id === "string" ? body.daemon_id : "";
  const proof = typeof body?.claim_proof === "string" ? body.claim_proof : "";
  if (!body || !DAEMON_ID_RE.test(daemonId)) return errorJson(build, 400, "bad_token", store);
  const label = body.label === undefined || body.label === null ? null : normalizeDeviceLabel(body.label);
  if (body.label !== undefined && body.label !== null && label === null) {
    return errorJson(build, 400, "bad_token", store);
  }

  // Re-sending a binding this account already holds changes nothing, so it does
  // not spend a proof; every other outcome below does.
  const existing = await getDeviceOwner(env.DB, daemonId);
  if (existing && existing.user_id === identity.user.user_id) {
    return jsonResponse(
      build,
      200,
      { ok: true, daemon_id: daemonId, label: existing.label, bound_at: existing.bound_at },
      store,
    );
  }
  if (!CLAIM_PROOF_RE.test(proof)) {
    observeError(env, "forbidden");
    return errorJson(build, 403, "forbidden", store);
  }

  // Consumed before the ownership row is examined further, so a wrong or
  // replayed proof is spent either way and cannot be retried against a device
  // that frees up later.
  if (!(await consumeClaimProof(env.DB, proof, identity.user.user_id, daemonId, now))) {
    observeError(env, "forbidden");
    return errorJson(build, 403, "forbidden", store);
  }
  if (existing) return errorJson(build, 409, "already_bound", store);

  const daemon = await getDaemon(env.DB, daemonId);
  if (!daemon || daemon.kicked_at != null) return errorJson(build, 404, "bad_token", store);

  if (!(await bindDevice(env.DB, {
    daemon_id: daemonId,
    user_id: identity.user.user_id,
    label,
    bound_at: now,
  }))) {
    return errorJson(build, 409, "already_bound", store);
  }
  return jsonResponse(build, 201, { ok: true, daemon_id: daemonId, label, bound_at: now }, store);
}

/**
 * Hands back the claim proof for a pairing the daemon has confirmed. Scoped to
 * the caller's own session, so the armed proof is readable only by the account
 * that started the pairing. Reported as pending rather than missing while the
 * daemon has not confirmed yet, which is what the phone polls on.
 */
async function readClaimProof(
  req: Request,
  env: Env,
  build: string,
  store: Record<string, string>,
  now: number,
): Promise<Response> {
  const identity = await resolveIdentity(env.DB, req, now);
  if (!identity) return errorJson(build, 401, "unauthenticated", store);
  const daemonId = new URL(req.url).searchParams.get("daemon_id") || "";
  if (!DAEMON_ID_RE.test(daemonId)) return errorJson(build, 400, "bad_token", store);

  const row = await getReadyProof(env.DB, identity.user.user_id, daemonId, now);
  if (!row) return jsonResponse(build, 200, { ok: true, ready: false }, store);
  return jsonResponse(
    build,
    200,
    { ok: true, ready: true, claim_proof: row.proof, expires_in: Math.max(0, Math.round((row.expires_at - now) / 1000)) },
    store,
  );
}

async function releaseDevice(
  daemonId: string,
  req: Request,
  env: Env,
  build: string,
  store: Record<string, string>,
  now: number,
): Promise<Response> {
  const identity = await resolveIdentity(env.DB, req, now);
  if (!identity) return errorJson(build, 401, "unauthenticated", store);
  if (!DAEMON_ID_RE.test(daemonId)) return errorJson(build, 400, "bad_token", store);
  if (!(await unbindDevice(env.DB, daemonId, identity.user.user_id))) {
    return errorJson(build, 404, "bad_token", store);
  }
  return jsonResponse(build, 200, { ok: true, daemon_id: daemonId }, store);
}

async function requireAdmin(env: Env, req: Request, now: number): Promise<Identity | null> {
  const identity = await resolveIdentity(env.DB, req, now);
  if (!identity || !isAdmin(identity.user)) return null;
  return identity;
}

async function signedIn(
  env: Env,
  build: string,
  store: Record<string, string>,
  user: UserRow,
  now: number,
  status: number,
): Promise<Response> {
  const session = await issueSession(env.DB, user.user_id, now);
  return jsonResponse(
    build,
    status,
    { ok: true, v: PROTOCOL, user: publicUser(user), expires_in: Math.round(SESSION_TTL_MS / 1000) },
    { ...store, "Set-Cookie": sessionCookie(session.token, SESSION_TTL_MS) },
  );
}

function lockedOut(build: string, store: Record<string, string>): Response {
  return errorJson(build, 429, "locked_out", {
    ...store,
    "Retry-After": String(Math.round(AUTH_LOCKOUT_MS / 1000)),
  });
}

let decoy: Promise<string> | null = null;

/** A record no submitted password can match, reused so the decoy costs one derivation per login. */
function decoyHash(): Promise<string> {
  if (!decoy) decoy = hashPassword(randomHex(32));
  return decoy;
}
