import {
  ADMIN_USERNAME,
  DEVICE_LABEL_MAX,
  INVITE_ALPHABET,
  INVITE_CODE_LEN,
  INVITE_CODE_RE,
  PASSWORD_MAX,
  PASSWORD_MIN,
  ROLE_ADMIN,
  SESSION_COOKIE,
  SESSION_TTL_MS,
  USERNAME_RE,
} from "./constants.ts";
import { hmacSha256Hex, randomBytes, randomHex, sha256Hex } from "./crypto.ts";
import {
  createSession,
  deleteSession,
  getLiveSession,
  getUserById,
  type UserRow,
} from "./account-store.ts";

export interface Identity {
  user: UserRow;
  tokenHash: string;
}

export function normalizeUsername(value: unknown): string | null {
  if (typeof value !== "string") return null;
  const name = value.trim().toLowerCase();
  return USERNAME_RE.test(name) ? name : null;
}

/**
 * Only the outer whitespace is trimmed: an interior space is a legitimate
 * passphrase character and stripping it would silently change the secret.
 */
export function normalizePassword(value: unknown): string | null {
  if (typeof value !== "string") return null;
  const password = value.trim();
  const bytes = new TextEncoder().encode(password).length;
  if (bytes < PASSWORD_MIN || bytes > PASSWORD_MAX) return null;
  for (const ch of password) {
    const code = ch.codePointAt(0) ?? 0;
    if (code < 0x20 || code === 0x7f) return null;
  }
  return password;
}

export function normalizeInviteCode(value: unknown): string | null {
  if (typeof value !== "string") return null;
  const code = value.trim().toUpperCase();
  return INVITE_CODE_RE.test(code) ? code : null;
}

export function normalizeDeviceLabel(value: unknown): string | null {
  if (typeof value !== "string") return null;
  const label = value.trim().replace(/\s+/g, " ");
  if (!label) return null;
  if (label.length > DEVICE_LABEL_MAX) return null;
  for (const ch of label) {
    const code = ch.codePointAt(0) ?? 0;
    if (code < 0x20 || code === 0x7f) return null;
  }
  return label;
}

export function newUserId(): string {
  return "u_" + randomHex(8);
}

/** Rejection sampling keeps every letter equally likely across the 26-letter alphabet. */
export function mintInviteCode(random: (n: number) => Uint8Array = randomBytes): string {
  const limit = 256 - (256 % INVITE_ALPHABET.length);
  let out = "";
  while (out.length < INVITE_CODE_LEN) {
    for (const byte of random(INVITE_CODE_LEN)) {
      if (byte >= limit) continue;
      out += INVITE_ALPHABET[byte % INVITE_ALPHABET.length];
      if (out.length === INVITE_CODE_LEN) break;
    }
  }
  return out;
}

export function isAdmin(user: UserRow): boolean {
  return user.role === ROLE_ADMIN;
}

export function bootstrapUsername(): string {
  return ADMIN_USERNAME;
}

export function sessionCookie(token: string, maxAgeMs: number): string {
  const maxAge = Math.max(0, Math.floor(maxAgeMs / 1000));
  return `${SESSION_COOKIE}=${token}; Path=/; Max-Age=${maxAge}; HttpOnly; Secure; SameSite=Strict`;
}

export function clearedSessionCookie(): string {
  return `${SESSION_COOKIE}=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Strict`;
}

export function readSessionToken(req: Request): string | null {
  const raw = req.headers.get("Cookie") || "";
  for (const part of raw.split(";")) {
    const eq = part.indexOf("=");
    if (eq < 0) continue;
    if (part.slice(0, eq).trim() !== SESSION_COOKIE) continue;
    const value = part.slice(eq + 1).trim();
    return /^[0-9a-f]{64}$/.test(value) ? value : null;
  }
  return null;
}

export async function issueSession(
  db: D1Database,
  userId: string,
  now: number,
): Promise<{ token: string; expiresAt: number }> {
  const token = randomHex(32);
  const expiresAt = now + SESSION_TTL_MS;
  await createSession(db, {
    token_hash: await sha256Hex(token),
    user_id: userId,
    created_at: now,
    expires_at: expiresAt,
  });
  return { token, expiresAt };
}

/** Resolves the cookie to a live account, dropping sessions whose user is gone. */
export async function resolveIdentity(
  db: D1Database,
  req: Request,
  now: number,
): Promise<Identity | null> {
  const token = readSessionToken(req);
  if (!token) return null;
  const tokenHash = await sha256Hex(token);
  const session = await getLiveSession(db, tokenHash, now);
  if (!session) return null;
  const user = await getUserById(db, session.user_id);
  if (!user) {
    await deleteSession(db, tokenHash);
    return null;
  }
  return { user, tokenHash };
}

/**
 * Failure budgets are kept per credential kind, not per source address.
 *
 * One bucket shared by every route meant signing in successfully cleared the
 * strikes earned by wrong invite codes, so two guesses and a login, repeated,
 * never reached three. A source that guesses codes and a source that mistypes
 * its own password are doing different things and are counted separately.
 */
export type AuthDomain = "invite" | "login" | "bootstrap";

export async function sourceSubject(
  pepper: string,
  domain: AuthDomain,
  ip: string,
): Promise<string> {
  return `${domain}:ip:` + (await hmacSha256Hex(pepper, ip));
}

/**
 * Counts wrong invite codes from every source against one budget. Without it a
 * four-letter code falls to guesses spread thinly across many addresses, and
 * the length is fixed by the product requirement.
 *
 * Scoped to the code's version: the budget protects one particular code, so
 * rotating to a new one starts a new budget rather than inheriting an exhausted
 * one and refusing the fresh code for the rest of the hour.
 */
export function inviteGlobalSubject(version: number): string {
  return `invite:global:v${version}`;
}

export function newClaimProof(): string {
  return "cp_" + randomHex(16);
}

export function publicUser(user: UserRow): Record<string, unknown> {
  return { user_id: user.user_id, username: user.username, role: user.role };
}
