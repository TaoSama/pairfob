import { expect } from "bun:test";
import { handleAccount } from "../account.ts";
import { newClaimProof } from "../account-auth.ts";
import { createClaimProof, readyClaimProof } from "../account-store.ts";
import { CLAIM_PROOF_TTL_MS } from "../constants.ts";
import { handleEnroll } from "../enroll.ts";
import { FakeD1 } from "./fake-d1.ts";
import { testEnv } from "./make-room.ts";

export const ORIGIN = "https://pair.taoai.site";

/** Opens the first account. Deliberately different from OPERATOR_TOKEN. */
export const SERVICE_TOKEN = "dev-bootstrap-service";

/** The relay operator credential, which must buy nothing on the account routes. */
export const OPERATOR_TOKEN = "dev-operator";

export const ADMIN_PASSWORD = "correct horse battery";

export const MEMBER_PASSWORD = "member-password-1";

export type TestEnv = ReturnType<typeof testEnv>;

export interface AccountReqInit {
  method?: string;
  body?: unknown;
  cookie?: string;
  ip?: string;
  origin?: string | null;
}

export function accountReq(path: string, init?: AccountReqInit): Request {
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    "CF-Connecting-IP": init?.ip ?? "203.0.113.7",
  };
  if (init?.origin !== null) headers.Origin = init?.origin ?? ORIGIN;
  if (init?.cookie) headers.Cookie = init.cookie;
  return new Request(ORIGIN + path, {
    method: init?.method ?? "GET",
    headers,
    body: init?.body === undefined ? undefined : JSON.stringify(init.body),
  });
}

export function cookieOf(res: Response): string {
  const raw = res.headers.get("Set-Cookie") ?? "";
  return raw.split(";")[0];
}

export async function bodyOf(res: Response | null): Promise<Record<string, unknown>> {
  return (await res!.json()) as Record<string, unknown>;
}

export async function makeAdmin(env: TestEnv, now = 1_000_000): Promise<string> {
  const res = await handleAccount(
    accountReq("/v2/account/bootstrap", {
      method: "POST",
      body: { service_token: SERVICE_TOKEN, password: ADMIN_PASSWORD },
    }),
    env,
    now,
  );
  expect(res?.status).toBe(201);
  return cookieOf(res!);
}

export async function inviteOf(env: TestEnv, cookie: string, now = 1_000_001): Promise<string> {
  const res = await handleAccount(accountReq("/v2/account/invite", { cookie }), env, now);
  expect(res?.status).toBe(200);
  return String((await bodyOf(res)).invite_code);
}

export async function makeMember(
  env: TestEnv,
  username: string,
  invite: string,
  now: number,
  ip = "203.0.113.8",
): Promise<string> {
  const res = await handleAccount(
    accountReq("/v2/account/register", {
      method: "POST",
      ip,
      body: { username, password: MEMBER_PASSWORD, invite_code: invite },
    }),
    env,
    now,
  );
  expect(res?.status).toBe(201);
  return cookieOf(res!);
}

export function daemonIdOf(seed: string): string {
  return "d_" + seed.repeat(10);
}

export async function enrollDaemonId(env: TestEnv, seed: string, now: number): Promise<string> {
  const res = await handleEnroll(
    new Request(ORIGIN + "/v2/enroll", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "CF-Connecting-IP": "198.51.100." + (seed.charCodeAt(0) % 200),
      },
      body: JSON.stringify({ v: 2, daemon_id: daemonIdOf(seed), reconnect_token: "rt_" + seed.repeat(16) }),
    }),
    env,
    now,
  );
  expect(res.status).toBe(200);
  return String(((await res.json()) as { daemon_id: string }).daemon_id);
}

export function userIdOf(d1: FakeD1, username: string): string {
  for (const u of d1.accounts.users.values()) if (u.username === username) return u.user_id;
  throw new Error("no such user: " + username);
}

/**
 * Stands in for a claim proof the daemon has already confirmed, so a test can
 * exercise the guards around claiming without driving a full pairing exchange.
 * Tests about whether confirmation is *required* must not use this: it arms the
 * proof, which is precisely the step they are supposed to be proving.
 */
export async function proofFor(
  d1: FakeD1,
  username: string,
  daemonId: string,
  now: number,
  ttlMs = CLAIM_PROOF_TTL_MS,
): Promise<string> {
  const proof = newClaimProof();
  const userId = userIdOf(d1, username);
  await createClaimProof(d1, {
    proof,
    user_id: userId,
    daemon_id: daemonId,
    created_at: now,
    expires_at: now + ttlMs,
    ready_at: 0,
    route_id: "",
  });
  await readyClaimProof(d1, userId, daemonId, "00".repeat(16), now);
  return proof;
}
