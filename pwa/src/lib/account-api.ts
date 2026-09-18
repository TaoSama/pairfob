import { validDaemonId } from "./identifiers.ts";
import { ProtocolError } from "./protocol/errors.ts";
import { fetchWithTimeout, type FetchLike } from "./request-timeout.ts";

/**
 * Typed client for the account control plane.
 *
 * Every call carries the session cookie and nothing else: the cookie is
 * HttpOnly, so there is no token for this layer to hold, lose, or leak into a
 * log. `same-origin` is stated rather than relied upon as a default, because the
 * write routes reject a request whose Origin is not this host and a silent
 * change of default would turn every write into an opaque 403.
 */

const PREFIX = "/v2/account";

export const INVITE_CODE_RE = /^[A-Z]{4}$/;
export const USERNAME_RE = /^[a-z0-9][a-z0-9._-]{2,31}$/;
export const CLAIM_PROOF_RE = /^cp_[0-9a-f]{32}$/;

export type AccountRole = "admin" | "member";

export type AccountUser = {
  userId: string;
  username: string;
  role: AccountRole;
};

export type AccountState = {
  /** False only before the very first account exists, which is what opens bootstrap. */
  initialized: boolean;
  user: AccountUser | null;
};

export type BoundDevice = {
  daemonId: string;
  label: string | null;
  boundAt: number;
  live: boolean;
};

export type InviteCode = {
  code: string;
  updatedAt: number;
};

/**
 * Whether the relay will yet let this account claim a machine.
 *
 * Not ready is the normal state for most of a pairing: the proof is minted only
 * once the relay has seen the daemon accept this session, so resolving a pairing
 * code is not enough to bind. A poller therefore expects `ready: false` and must
 * not read that as a failure.
 */
export type ClaimProof =
  | { ready: false }
  | { ready: true; proof: string; expiresIn: number };

/** Mirrors `account_vaults`. The relay stores these five fields and reads none of them. */
export type VaultRecord = {
  ciphertext: string;
  nonce: string;
  kdf: string;
  version: number;
  updatedAt: number;
};

export type VaultWrite = {
  ciphertext: string;
  nonce: string;
  kdf: string;
  /**
   * The version this write is replacing; 0 creates the first one. The origin
   * applies the write only if the stored row still matches, so two phones that
   * edit the same vault concurrently cannot silently drop one another's devices.
   */
  version: number;
};

function record(value: unknown): Record<string, unknown> | null {
  return value && typeof value === "object" && !Array.isArray(value) ? (value as Record<string, unknown>) : null;
}

function errorCode(value: unknown): string {
  const body = record(value);
  const error = body ? record(body.error) : null;
  return error && typeof error.code === "string" ? error.code : "";
}

function parseUser(value: unknown): AccountUser | null {
  const user = record(value);
  if (!user) return null;
  const { user_id: userId, username, role } = user;
  if (typeof userId !== "string" || typeof username !== "string") return null;
  if (role !== "admin" && role !== "member") return null;
  return { userId, username, role };
}

function parseDevice(value: unknown): BoundDevice | null {
  const device = record(value);
  if (!device || !validDaemonId(device.daemon_id)) return null;
  if (typeof device.bound_at !== "number" || !Number.isSafeInteger(device.bound_at)) return null;
  const label = device.label;
  if (label !== null && label !== undefined && typeof label !== "string") return null;
  return {
    daemonId: device.daemon_id,
    label: typeof label === "string" ? label : null,
    boundAt: device.bound_at,
    live: device.live === true,
  };
}

function parseVault(value: unknown): VaultRecord | null {
  const vault = record(value);
  if (!vault) return null;
  const { ciphertext, nonce, kdf, version, updated_at: updatedAt } = vault;
  if (typeof ciphertext !== "string" || typeof nonce !== "string" || typeof kdf !== "string") return null;
  if (typeof version !== "number" || !Number.isSafeInteger(version) || version < 1) return null;
  if (typeof updatedAt !== "number" || !Number.isSafeInteger(updatedAt)) return null;
  return { ciphertext, nonce, kdf, version, updatedAt };
}

/**
 * The account routes answer with a code the UI can act on, so the HTTP status is
 * only a fallback for a response that carries no body at all. `locked_out` and
 * `rate_limited` are distinct on purpose: one is the product's three-strikes
 * rule and the other is infrastructure, and a user who waits out the wrong one
 * waits for the wrong length of time.
 */
function statusCode(status: number): string {
  if (status === 401) return "bad_credentials";
  if (status === 403) return "forbidden";
  if (status === 404) return "unbound";
  if (status === 409) return "conflict";
  if (status === 429) return "rate_limited";
  return "internal";
}

async function call(
  path: string,
  init: RequestInit,
  fetchImpl: FetchLike,
  signal?: AbortSignal,
): Promise<{ status: number; body: unknown }> {
  let response: Response;
  try {
    response = await fetchWithTimeout(
      fetchImpl,
      `${PREFIX}${path}`,
      { ...init, cache: "no-store", credentials: "same-origin" },
      { signal },
    );
  } catch (error) {
    if (error instanceof ProtocolError) throw error;
    throw new ProtocolError("bad_relay");
  }
  let body: unknown = null;
  try {
    body = await response.json();
  } catch {
    body = null;
  }
  return { status: response.status, body };
}

async function post(
  path: string,
  payload: unknown,
  fetchImpl: FetchLike,
  signal?: AbortSignal,
): Promise<{ status: number; body: unknown }> {
  return call(
    path,
    { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(payload) },
    fetchImpl,
    signal,
  );
}

/**
 * The error a refused account call should throw.
 *
 * The origin's error object rides along unread. Several routes attach a number
 * the person needs to be told — how many sign-in attempts are left before the
 * hour-long lockout, which vault version won a conflict — and those are lost if
 * only the code survives the throw.
 */
function fail(status: number, body: unknown): ProtocolError {
  const detail = record(record(body)?.error);
  return new ProtocolError(errorCode(body) || statusCode(status), undefined, undefined, detail ?? undefined);
}

function signedIn(status: number, body: unknown): AccountUser {
  const parsed = record(body);
  const user = parsed && parsed.ok === true ? parseUser(parsed.user) : null;
  if (!user) throw fail(status, body);
  return user;
}

/** Answers the first question the pair page has: is there an account here, and am I it? */
export async function readAccountState(
  fetchImpl: FetchLike = fetch,
  signal?: AbortSignal,
): Promise<AccountState> {
  const { status, body } = await call("/state", { method: "GET" }, fetchImpl, signal);
  const parsed = record(body);
  if (!parsed || parsed.ok !== true || typeof parsed.initialized !== "boolean") {
    throw fail(status, body);
  }
  return { initialized: parsed.initialized, user: parseUser(parsed.user) };
}

/**
 * Opens the first account with the relay's service token. Succeeds exactly once
 * per deployment; afterwards the route is closed and reports `already_initialized`.
 */
export async function bootstrapAccount(
  serviceToken: string,
  password: string,
  fetchImpl: FetchLike = fetch,
  signal?: AbortSignal,
): Promise<AccountUser> {
  const { status, body } = await post("/bootstrap", { service_token: serviceToken, password }, fetchImpl, signal);
  return signedIn(status, body);
}

export async function loginAccount(
  username: string,
  password: string,
  fetchImpl: FetchLike = fetch,
  signal?: AbortSignal,
): Promise<AccountUser> {
  const { status, body } = await post("/login", { username, password }, fetchImpl, signal);
  return signedIn(status, body);
}

export async function registerAccount(
  username: string,
  password: string,
  inviteCode: string,
  fetchImpl: FetchLike = fetch,
  signal?: AbortSignal,
): Promise<AccountUser> {
  const payload = { username, password, invite_code: inviteCode };
  const { status, body } = await post("/register", payload, fetchImpl, signal);
  return signedIn(status, body);
}

/** Only the origin can confirm logout, including an already-absent session. */
export async function logoutAccount(fetchImpl: FetchLike = fetch, signal?: AbortSignal): Promise<void> {
  const { status, body } = await post("/logout", {}, fetchImpl, signal);
  if (status !== 200 || record(body)?.ok !== true) throw fail(status, body);
}

export async function readInviteCode(
  fetchImpl: FetchLike = fetch,
  signal?: AbortSignal,
): Promise<InviteCode> {
  const { status, body } = await call("/invite", { method: "GET" }, fetchImpl, signal);
  return parseInvite(status, body);
}

export async function rotateInviteCode(
  fetchImpl: FetchLike = fetch,
  signal?: AbortSignal,
): Promise<InviteCode> {
  const { status, body } = await post("/invite/rotate", {}, fetchImpl, signal);
  return parseInvite(status, body);
}

function parseInvite(status: number, body: unknown): InviteCode {
  const parsed = record(body);
  const code = parsed && parsed.ok === true ? parsed.invite_code : null;
  if (typeof code !== "string" || !INVITE_CODE_RE.test(code)) throw fail(status, body);
  const updatedAt = typeof parsed?.updated_at === "number" ? parsed.updated_at : 0;
  return { code, updatedAt };
}

/** Only ever this account's own devices; the relay has no route that lists anyone else's. */
export async function listBoundDevices(
  fetchImpl: FetchLike = fetch,
  signal?: AbortSignal,
): Promise<BoundDevice[]> {
  const { status, body } = await call("/devices", { method: "GET" }, fetchImpl, signal);
  const parsed = record(body);
  if (!parsed || parsed.ok !== true || !Array.isArray(parsed.devices)) throw fail(status, body);
  return parsed.devices.map(parseDevice).filter((device): device is BoundDevice => device !== null);
}

/**
 * Asks whether the relay has seen the daemon accept this pairing yet.
 *
 * Another account polling the same machine is told `ready: false` rather than
 * being refused, so this cannot be used to discover who is pairing what.
 */
export async function readClaimProof(
  daemonId: string,
  fetchImpl: FetchLike = fetch,
  signal?: AbortSignal,
): Promise<ClaimProof> {
  const path = `/claim-proof?daemon_id=${encodeURIComponent(daemonId)}`;
  const { status, body } = await call(path, { method: "GET" }, fetchImpl, signal);
  const parsed = record(body);
  if (!parsed || parsed.ok !== true) throw fail(status, body);
  if (parsed.ready !== true) return { ready: false };
  const proof = parsed.claim_proof;
  if (typeof proof !== "string" || !CLAIM_PROOF_RE.test(proof)) throw fail(status, body);
  const expiresIn = typeof parsed.expires_in === "number" ? parsed.expires_in : 0;
  return { ready: true, proof, expiresIn };
}

/**
 * Records ownership of a daemon this account has actually paired with.
 *
 * The proof is minted by the relay and only becomes usable once the daemon has
 * accepted the session, which happens after a SPAKE2+ exchange the relay cannot
 * read. Holding a pairing code is therefore not enough to bind a machine, and
 * this client has no path that binds without one.
 *
 * The proof is single-use. A refusal means the pairing must be redone from the
 * start, so nothing here retries.
 */
export async function claimDevice(
  daemonId: string,
  claimProof: string,
  label: string | null,
  fetchImpl: FetchLike = fetch,
  signal?: AbortSignal,
): Promise<BoundDevice> {
  const payload: Record<string, unknown> = { daemon_id: daemonId, claim_proof: claimProof };
  if (label !== null) payload.label = label;
  const { status, body } = await post("/devices", payload, fetchImpl, signal);
  const parsed = record(body);
  if (!parsed || parsed.ok !== true) throw fail(status, body);
  return parseDevice({ ...parsed, live: true }) ?? { daemonId, label, boundAt: 0, live: true };
}

export async function releaseDevice(
  daemonId: string,
  fetchImpl: FetchLike = fetch,
  signal?: AbortSignal,
): Promise<void> {
  const path = `/devices/${encodeURIComponent(daemonId)}`;
  const { status, body } = await call(path, { method: "DELETE" }, fetchImpl, signal);
  const parsed = record(body);
  if (!parsed || parsed.ok !== true) throw fail(status, body);
}

/**
 * Fetches the encrypted vault. A signed-in account that has never written one
 * gets null rather than an error: an empty vault is the normal state of a fresh
 * account, not a failure to report.
 */
export async function readVault(
  fetchImpl: FetchLike = fetch,
  signal?: AbortSignal,
): Promise<VaultRecord | null> {
  const { status, body } = await call("/vault", { method: "GET" }, fetchImpl, signal);
  if (status === 404 && errorCode(body) === "unbound") return null;
  const parsed = record(body);
  if (!parsed || parsed.ok !== true) throw fail(status, body);
  const vault = parseVault(parsed.vault);
  if (!vault) throw fail(status, body);
  return vault;
}

/**
 * A losing compare-and-set on the vault.
 *
 * Carries the version the origin actually holds, because the caller's next step
 * is to re-read at that version, merge, and write again — and it cannot do that
 * from an error code alone.
 */
export class VaultConflictError extends ProtocolError {
  constructor(public readonly currentVersion: number) {
    super("conflict");
    this.name = "VaultConflictError";
  }
}

/**
 * Writes the vault under a compare-and-set on the version, and returns the
 * version now stored.
 *
 * A conflict is surfaced rather than retried here: the caller has to re-read,
 * re-decrypt and merge before it can know what the new contents should be, and a
 * blind retry would overwrite whatever the other phone just added.
 */
export async function writeVault(
  write: VaultWrite,
  fetchImpl: FetchLike = fetch,
  signal?: AbortSignal,
): Promise<number> {
  const payload = {
    ciphertext: write.ciphertext,
    nonce: write.nonce,
    kdf: write.kdf,
    version: write.version,
  };
  const { status, body } = await call(
    "/vault",
    { method: "PUT", headers: { "content-type": "application/json" }, body: JSON.stringify(payload) },
    fetchImpl,
    signal,
  );
  const parsed = record(body);
  if (status === 409 || errorCode(body) === "conflict") {
    const error = parsed ? record(parsed.error) : null;
    const current = typeof error?.version === "number" ? error.version : 0;
    throw new VaultConflictError(current);
  }
  if (!parsed || parsed.ok !== true || typeof parsed.version !== "number") throw fail(status, body);
  return parsed.version;
}
