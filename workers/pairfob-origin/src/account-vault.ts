import { resolveIdentity, type Identity } from "./account-auth.ts";
import {
  BASE64_RE,
  VAULT_KDF_MAX,
  VAULT_MAX_BYTES,
  VAULT_NONCE_MAX,
} from "./constants.ts";
import type { Env } from "./env.ts";
import { errorJson, jsonResponse, readJSON } from "./http.ts";

export const SELECT_VAULT_SQL = "SELECT * FROM account_vaults WHERE user_id = ?";

// Both writes carry the expected version inside the predicate. A read followed
// by a write would let two phones that each saw version 3 both store a version
// 4, and the later write would silently discard the earlier one's secrets.
export const INSERT_VAULT_SQL =
  "INSERT INTO account_vaults (user_id, ciphertext, nonce, kdf, version, updated_at) SELECT ?, ?, ?, ?, ?, ? WHERE NOT EXISTS (SELECT 1 FROM account_vaults WHERE user_id = ?)";

export const UPDATE_VAULT_SQL =
  "UPDATE account_vaults SET ciphertext = ?, nonce = ?, kdf = ?, version = ?, updated_at = ? WHERE user_id = ? AND version = ?";

export interface VaultRow {
  user_id: string;
  ciphertext: string;
  nonce: string;
  kdf: string;
  version: number;
  updated_at: number;
}

interface VaultBody {
  ciphertext: string;
  nonce: string;
  kdf: string;
  version: number;
}

export async function getVault(db: D1Database, userId: string): Promise<VaultRow | null> {
  return db.prepare(SELECT_VAULT_SQL).bind(userId).first<VaultRow>();
}

/** False when a row already exists, including on a PRIMARY KEY race. */
export async function insertVault(db: D1Database, row: VaultRow): Promise<boolean> {
  try {
    const res = await db
      .prepare(INSERT_VAULT_SQL)
      .bind(row.user_id, row.ciphertext, row.nonce, row.kdf, row.version, row.updated_at, row.user_id)
      .run();
    return (res.meta.changes ?? 0) === 1;
  } catch {
    return false;
  }
}

/** False when the stored version moved on, which is the losing side of the CAS. */
export async function updateVault(db: D1Database, row: VaultRow, expected: number): Promise<boolean> {
  const res = await db
    .prepare(UPDATE_VAULT_SQL)
    .bind(row.ciphertext, row.nonce, row.kdf, row.version, row.updated_at, row.user_id, expected)
    .run();
  return (res.meta.changes ?? 0) === 1;
}

/**
 * The blob is written and returned untouched. The relay has no key material for
 * it, so it cannot decrypt, validate or repair the contents, and no field value
 * is ever recorded anywhere: only shape and size are checked.
 */
export async function handleVault(
  req: Request,
  env: Env,
  build: string,
  store: Record<string, string>,
  now: number,
  identity: Identity | null = null,
): Promise<Response> {
  const who = identity ?? (await resolveIdentity(env.DB, req, now));
  if (!who) return errorJson(build, 401, "unauthenticated", store);

  if (req.method === "GET") return readVault(env, build, store, who);
  if (req.method === "PUT") return writeVault(req, env, build, store, now, who);
  return errorJson(build, 405, "bad_token", store);
}

async function readVault(
  env: Env,
  build: string,
  store: Record<string, string>,
  identity: Identity,
): Promise<Response> {
  const row = await getVault(env.DB, identity.user.user_id);
  if (!row) return errorJson(build, 404, "unbound", store);
  return jsonResponse(
    build,
    200,
    {
      ok: true,
      vault: {
        ciphertext: row.ciphertext,
        nonce: row.nonce,
        kdf: row.kdf,
        version: row.version,
        updated_at: row.updated_at,
      },
    },
    store,
  );
}

async function writeVault(
  req: Request,
  env: Env,
  build: string,
  store: Record<string, string>,
  now: number,
  identity: Identity,
): Promise<Response> {
  const raw = await readJSON(req);
  // Size is judged before shape so an oversize payload is answered by its own
  // code instead of being reported as malformed, and so the pattern below is
  // never run across an unbounded string.
  const ciphertext = raw?.ciphertext;
  if (typeof ciphertext === "string" && utf8Length(ciphertext) > VAULT_MAX_BYTES) {
    return errorJson(build, 413, "too_large", store);
  }
  const body = parseVaultBody(raw);
  if (!body) return errorJson(build, 400, "bad_token", store);

  const row: VaultRow = {
    user_id: identity.user.user_id,
    ciphertext: body.ciphertext,
    nonce: body.nonce,
    kdf: body.kdf,
    version: body.version + 1,
    updated_at: now,
  };
  const won =
    body.version === 0
      ? await insertVault(env.DB, row)
      : await updateVault(env.DB, row, body.version);
  if (won) return jsonResponse(build, 200, { ok: true, version: row.version }, store);

  // The loser is told what the row actually holds so the client can merge and
  // retry rather than guess. The version is a counter, not a secret.
  const current = await getVault(env.DB, identity.user.user_id);
  return jsonResponse(
    build,
    409,
    { ok: false, error: { code: "conflict", version: current?.version ?? 0 } },
    store,
  );
}

function parseVaultBody(body: Record<string, unknown> | null): VaultBody | null {
  if (!body) return null;
  const ciphertext = base64Field(body.ciphertext, VAULT_MAX_BYTES);
  const nonce = base64Field(body.nonce, VAULT_NONCE_MAX);
  const kdf = opaqueField(body.kdf, VAULT_KDF_MAX);
  const version = body.version;
  if (ciphertext === null || nonce === null || kdf === null) return null;
  if (typeof version !== "number" || !Number.isInteger(version) || version < 0) return null;
  return { ciphertext, nonce, kdf, version };
}

/**
 * Length is capped here as well so a hostile payload is rejected before the
 * regex walks it; the byte-level ceiling that decides 413 is applied by the
 * caller, on the ciphertext only.
 */
function base64Field(value: unknown, cap: number): string | null {
  if (typeof value !== "string" || !value) return null;
  if (value.length > cap * 2) return null;
  return BASE64_RE.test(value) ? value : null;
}

/** The KDF label is the client's business; the relay only bounds its size. */
function opaqueField(value: unknown, max: number): string | null {
  if (typeof value !== "string" || !value) return null;
  if (value.length > max) return null;
  for (const ch of value) {
    const code = ch.codePointAt(0) ?? 0;
    if (code < 0x20 || code === 0x7f) return null;
  }
  return value;
}

function utf8Length(value: string): number {
  return new TextEncoder().encode(value).length;
}
