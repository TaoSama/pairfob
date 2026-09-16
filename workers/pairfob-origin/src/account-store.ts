import { AUTH_LOCKOUT_MS, AUTH_LOCKOUT_STRIKES } from "./constants.ts";

export const SELECT_USER_BY_NAME_SQL = "SELECT * FROM users WHERE username = ?";

export const SELECT_USER_BY_ID_SQL = "SELECT * FROM users WHERE user_id = ?";

export const COUNT_USERS_SQL = "SELECT COUNT(*) AS n FROM users";

// The guard lives in the statement so two concurrent bootstraps cannot both
// observe an empty table and both mint a first administrator.
export const INSERT_FIRST_USER_SQL =
  "INSERT INTO users (user_id, username, password_hash, role, created_at) SELECT ?, ?, ?, ?, ? WHERE NOT EXISTS (SELECT 1 FROM users)";

export const INSERT_USER_SQL =
  "INSERT INTO users (user_id, username, password_hash, role, created_at) SELECT ?, ?, ?, ?, ? WHERE NOT EXISTS (SELECT 1 FROM users WHERE username = ?)";

export const INSERT_SESSION_SQL =
  "INSERT INTO user_sessions (token_hash, user_id, created_at, expires_at) VALUES (?, ?, ?, ?)";

export const SELECT_SESSION_SQL =
  "SELECT * FROM user_sessions WHERE token_hash = ? AND expires_at > ?";

export const DELETE_SESSION_SQL = "DELETE FROM user_sessions WHERE token_hash = ?";

export const PRUNE_SESSIONS_SQL = "DELETE FROM user_sessions WHERE expires_at <= ?";

export const SELECT_INVITE_SQL = "SELECT * FROM invite_codes WHERE id = 1";

export const UPSERT_INVITE_SQL =
  "INSERT INTO invite_codes (id, code, updated_by, updated_at, suspended_at, version) VALUES (1, ?, ?, ?, 0, 1) ON CONFLICT(id) DO UPDATE SET code = excluded.code, updated_by = excluded.updated_by, updated_at = excluded.updated_at, suspended_at = 0, version = invite_codes.version + 1";

// Version-scoped, so a wrong-code request that started against the previous
// code and finishes after a rotation cannot suspend the code that replaced it.
export const SUSPEND_INVITE_SQL =
  "UPDATE invite_codes SET suspended_at = ? WHERE id = 1 AND suspended_at = 0 AND version = ?";

export const INSERT_AUTH_FAILURE_SQL = "INSERT INTO auth_failures (subject, at) VALUES (?, ?)";

// Takes one strike only while the subject is still under the limit, and decides
// both halves in a single statement. A worker that counts and then inserts
// leaves a window between its two round trips in which every request in a burst
// reads the same count and every one of them proceeds; here the database
// evaluates the count as part of the write, so the losers insert nothing.
export const RESERVE_AUTH_FAILURE_SQL =
  "INSERT INTO auth_failures (subject, at) SELECT ?, ? WHERE (SELECT COUNT(*) FROM auth_failures WHERE subject = ? AND at > ?) < ?";

// Hands back exactly the strike a reservation took, for an attempt that turned
// out not to be a wrong credential at all. Addressed by row id rather than by
// subject and timestamp: the global invite budget is shared by every source, so
// matching on those two would let one caller's refund erase a different
// attacker's strike that happened to land in the same millisecond.
export const RELEASE_AUTH_FAILURE_SQL = "DELETE FROM auth_failures WHERE id = ?";

export const COUNT_AUTH_FAILURES_SQL =
  "SELECT COUNT(*) AS n FROM auth_failures WHERE subject = ? AND at > ?";

export const DELETE_AUTH_FAILURES_SQL = "DELETE FROM auth_failures WHERE subject = ?";

export const PRUNE_AUTH_FAILURES_SQL = "DELETE FROM auth_failures WHERE at <= ?";

// A ban has its own deadline because "three strikes still inside the trailing
// hour" is a different rule from "an hour from the third strike": under the
// first, the oldest strike ages out and the source is free again early.
export const SELECT_AUTH_LOCK_SQL = "SELECT until FROM auth_locks WHERE subject = ? AND until > ?";

// Takes the later of the two deadlines, so a lock already running cannot be
// shortened by a fresh attempt that arrives late in its hour.
export const UPSERT_AUTH_LOCK_SQL =
  "INSERT INTO auth_locks (subject, until) VALUES (?, ?) ON CONFLICT(subject) DO UPDATE SET until = MAX(until, excluded.until)";

export const DELETE_AUTH_LOCK_SQL = "DELETE FROM auth_locks WHERE subject = ?";

export const PRUNE_AUTH_LOCKS_SQL = "DELETE FROM auth_locks WHERE until <= ?";

export const INSERT_CLAIM_PROOF_SQL =
  "INSERT INTO device_claim_proofs (proof, user_id, daemon_id, created_at, expires_at, ready_at, route_id) VALUES (?, ?, ?, ?, ?, 0, ?)";

// Arms this account's pending proof for this daemon and records the session
// route the confirmation arrived on. Only the enrolled daemon can cause this,
// and only for a phone whose session it accepted, so a code-reader who never
// completed the pairing exchange never reaches it.
export const READY_CLAIM_PROOF_SQL =
  "UPDATE device_claim_proofs SET ready_at = ?, route_id = ? WHERE user_id = ? AND daemon_id = ? AND ready_at = 0 AND expires_at > ?";

export const SELECT_READY_PROOF_SQL =
  "SELECT * FROM device_claim_proofs WHERE user_id = ? AND daemon_id = ? AND ready_at > 0 AND expires_at > ? LIMIT 1";

// The proof is deleted by the same statement that checks it, so a replay finds
// no row: the database decides single use, not a read-then-delete in the worker.
// `ready_at > 0` is part of the predicate, so a proof whose pairing the daemon
// never confirmed is indistinguishable from one that does not exist.
export const CONSUME_CLAIM_PROOF_SQL =
  "DELETE FROM device_claim_proofs WHERE proof = ? AND user_id = ? AND daemon_id = ? AND ready_at > 0 AND expires_at > ?";

export const PRUNE_CLAIM_PROOFS_SQL = "DELETE FROM device_claim_proofs WHERE expires_at <= ?";

export const INSERT_DEVICE_OWNER_SQL =
  "INSERT INTO device_owners (daemon_id, user_id, label, bound_at) SELECT ?, ?, ?, ? WHERE NOT EXISTS (SELECT 1 FROM device_owners WHERE daemon_id = ?)";

export const SELECT_DEVICE_OWNER_SQL = "SELECT * FROM device_owners WHERE daemon_id = ?";

export const LIST_DEVICES_BY_USER_SQL =
  "SELECT * FROM device_owners WHERE user_id = ? ORDER BY bound_at ASC LIMIT ?";

export const DELETE_DEVICE_OWNER_SQL =
  "DELETE FROM device_owners WHERE daemon_id = ? AND user_id = ?";

export interface UserRow {
  user_id: string;
  username: string;
  password_hash: string;
  role: string;
  created_at: number;
}

export interface SessionRow {
  token_hash: string;
  user_id: string;
  created_at: number;
  expires_at: number;
}

export interface InviteRow {
  id: number;
  code: string;
  updated_by: string | null;
  updated_at: number;
  suspended_at: number;
  /** Bumped on every rotation; names the global failure budget for this code. */
  version: number;
}

export interface ClaimProofRow {
  proof: string;
  user_id: string;
  daemon_id: string;
  created_at: number;
  expires_at: number;
  /** 0 until the daemon confirms the pairing this proof was minted for. */
  ready_at: number;
  /** The session route the confirmation arrived on. */
  route_id: string;
}

export interface DeviceOwnerRow {
  daemon_id: string;
  user_id: string;
  label: string | null;
  bound_at: number;
}

export async function getUserByName(db: D1Database, username: string): Promise<UserRow | null> {
  return db.prepare(SELECT_USER_BY_NAME_SQL).bind(username).first<UserRow>();
}

export async function getUserById(db: D1Database, userId: string): Promise<UserRow | null> {
  return db.prepare(SELECT_USER_BY_ID_SQL).bind(userId).first<UserRow>();
}

export async function countUsers(db: D1Database): Promise<number> {
  const row = await db.prepare(COUNT_USERS_SQL).first<{ n: number }>();
  return Number(row?.n ?? 0);
}

/** Returns false when another request already claimed the first account. */
export async function insertFirstUser(db: D1Database, row: UserRow): Promise<boolean> {
  try {
    const res = await db
      .prepare(INSERT_FIRST_USER_SQL)
      .bind(row.user_id, row.username, row.password_hash, row.role, row.created_at)
      .run();
    return (res.meta.changes ?? 0) === 1;
  } catch {
    return false;
  }
}

/** Returns false when the username is taken, including on a UNIQUE race. */
export async function insertUser(db: D1Database, row: UserRow): Promise<boolean> {
  try {
    const res = await db
      .prepare(INSERT_USER_SQL)
      .bind(row.user_id, row.username, row.password_hash, row.role, row.created_at, row.username)
      .run();
    return (res.meta.changes ?? 0) === 1;
  } catch {
    return false;
  }
}

export async function createSession(db: D1Database, row: SessionRow): Promise<void> {
  await db.batch([
    db.prepare(INSERT_SESSION_SQL).bind(row.token_hash, row.user_id, row.created_at, row.expires_at),
    db.prepare(PRUNE_SESSIONS_SQL).bind(row.created_at),
  ]);
}

export async function getLiveSession(
  db: D1Database,
  tokenHash: string,
  now: number,
): Promise<SessionRow | null> {
  return db.prepare(SELECT_SESSION_SQL).bind(tokenHash, now).first<SessionRow>();
}

export async function deleteSession(db: D1Database, tokenHash: string): Promise<void> {
  await db.prepare(DELETE_SESSION_SQL).bind(tokenHash).run();
}

export async function getInvite(db: D1Database): Promise<InviteRow | null> {
  return db.prepare(SELECT_INVITE_SQL).first<InviteRow>();
}

export async function putInvite(
  db: D1Database,
  code: string,
  updatedBy: string,
  now: number,
): Promise<void> {
  await db.prepare(UPSERT_INVITE_SQL).bind(code, updatedBy, now).run();
}

/**
 * Returns false when the code was already suspended, or when `version` is no
 * longer the live one. A request that read the old code, spent an hour losing
 * its race and only now reaches its verdict must not take down the code an
 * administrator rotated to in the meantime.
 */
export async function suspendInvite(
  db: D1Database,
  now: number,
  version: number,
): Promise<boolean> {
  const res = await db.prepare(SUSPEND_INVITE_SQL).bind(now, version).run();
  return (res.meta.changes ?? 0) === 1;
}

/**
 * The moment a subject's ban expires, or 0 when it is not banned.
 *
 * Read instead of derived from the strike count: the count answers "how many
 * failures are still inside the trailing hour", which starts dropping as soon
 * as the oldest one ages out. The ban is a fact with a deadline of its own.
 */
export async function lockedUntil(db: D1Database, subject: string, now: number): Promise<number> {
  const row = await db.prepare(SELECT_AUTH_LOCK_SQL).bind(subject, now).first<{ until: number }>();
  return Number(row?.until ?? 0);
}

/** Bans a subject for a full hour measured from this failure. */
export async function lockSubject(db: D1Database, subject: string, now: number): Promise<number> {
  const until = now + AUTH_LOCKOUT_MS;
  await db.batch([
    db.prepare(PRUNE_AUTH_LOCKS_SQL).bind(now),
    db.prepare(UPSERT_AUTH_LOCK_SQL).bind(subject, until),
  ]);
  return until;
}

/**
 * Drops a subject's strikes and any ban. Only for a domain whose credential was
 * just presented correctly, and never for a domain the caller did not satisfy.
 */
export async function clearAuthDomain(db: D1Database, subject: string): Promise<void> {
  await db.batch([
    db.prepare(DELETE_AUTH_FAILURES_SQL).bind(subject),
    db.prepare(DELETE_AUTH_LOCK_SQL).bind(subject),
  ]);
}

/**
 * Records one wrong attempt and reports the resulting count in a single
 * transaction. Checking first and writing afterwards left a window where
 * concurrent attempts each read a count below the limit and all proceeded, so
 * the ledger is written before it is read and the caller acts on the count it
 * caused.
 */
export async function spendFailureBudget(
  db: D1Database,
  subject: string,
  now: number,
): Promise<number> {
  const results = await db.batch([
    db.prepare(INSERT_AUTH_FAILURE_SQL).bind(subject, now),
    db.prepare(PRUNE_AUTH_FAILURES_SQL).bind(now - AUTH_LOCKOUT_MS),
    db.prepare(COUNT_AUTH_FAILURES_SQL).bind(subject, now - AUTH_LOCKOUT_MS),
  ]);
  const rows = (results[2]?.results ?? []) as Array<{ n?: number }>;
  return Number(rows[0]?.n ?? 0);
}

export interface FailureReservation {
  /** False when this subject had already spent its budget for the window. */
  granted: boolean;
  /** The position this attempt took, 1-based. Meaningless when refused. */
  strikes: number;
  /** The row this attempt wrote, for handing the strike back. 0 when refused. */
  id: number;
}

/**
 * Takes one strike up front, before the credential it pays for is examined.
 *
 * The lockout has to bound attempts, and an attempt begins when the request
 * arrives, not when the worker gets round to comparing. Reading the limit and
 * writing the strike as two round trips means a burst that arrives together
 * passes the read together: six concurrent guesses all see an empty ledger, all
 * reach the comparison, and the limit buys nothing. So the limit is evaluated
 * inside the insert and the count is read from the same batch. A refused
 * reservation has written no row, so the ledger never exceeds the limit either.
 *
 * Callers must reserve before they look at the secret, and release only when
 * the attempt turned out not to be a wrong credential.
 */
export async function reserveFailureBudget(
  db: D1Database,
  subject: string,
  now: number,
  limit = AUTH_LOCKOUT_STRIKES,
): Promise<FailureReservation> {
  const since = now - AUTH_LOCKOUT_MS;
  const results = await db.batch([
    db.prepare(PRUNE_AUTH_FAILURES_SQL).bind(since),
    db.prepare(RESERVE_AUTH_FAILURE_SQL).bind(subject, now, subject, since, limit),
    db.prepare(COUNT_AUTH_FAILURES_SQL).bind(subject, since),
  ]);
  const granted = (results[1]?.meta.changes ?? 0) === 1;
  const rows = (results[2]?.results ?? []) as Array<{ n?: number }>;
  return {
    granted,
    strikes: granted ? Number(rows[0]?.n ?? 0) : limit,
    id: granted ? Number(results[1]?.meta.last_row_id ?? 0) : 0,
  };
}

/**
 * Returns a strike taken by `reserveFailureBudget` for an attempt that proved
 * not to be a wrong credential. Only that one row is removed, so a subject that
 * has genuinely guessed wrong keeps every strike it earned, and a refund on the
 * shared global budget cannot take a strike another source is still paying.
 */
export async function releaseFailureBudget(
  db: D1Database,
  reservation: FailureReservation,
): Promise<void> {
  if (!reservation.granted || reservation.id <= 0) return;
  await db.prepare(RELEASE_AUTH_FAILURE_SQL).bind(reservation.id).run();
}

export async function countFailures(db: D1Database, subject: string, now: number): Promise<number> {
  const row = await db
    .prepare(COUNT_AUTH_FAILURES_SQL)
    .bind(subject, now - AUTH_LOCKOUT_MS)
    .first<{ n: number }>();
  return Number(row?.n ?? 0);
}

export async function isLockedOut(
  db: D1Database,
  subjects: readonly string[],
  now: number,
): Promise<boolean> {
  for (const subject of subjects) {
    if ((await countFailures(db, subject, now)) >= AUTH_LOCKOUT_STRIKES) return true;
  }
  return false;
}

export async function createClaimProof(db: D1Database, row: ClaimProofRow): Promise<void> {
  await db.batch([
    db
      .prepare(INSERT_CLAIM_PROOF_SQL)
      .bind(row.proof, row.user_id, row.daemon_id, row.created_at, row.expires_at, row.route_id),
    db.prepare(PRUNE_CLAIM_PROOFS_SQL).bind(row.created_at),
  ]);
}

/**
 * Arms this account's pending proof for this daemon. Called when the daemon
 * confirms a session for the phone, which it does only after the pairing
 * exchange the relay cannot read. Returns how many proofs became claimable.
 */
export async function readyClaimProof(
  db: D1Database,
  userId: string,
  daemonId: string,
  routeId: string,
  now: number,
): Promise<number> {
  const res = await db.prepare(READY_CLAIM_PROOF_SQL).bind(now, routeId, userId, daemonId, now).run();
  return res.meta.changes ?? 0;
}

/** The armed proof this account may still spend on this daemon, if any. */
export async function getReadyProof(
  db: D1Database,
  userId: string,
  daemonId: string,
  now: number,
): Promise<ClaimProofRow | null> {
  return db.prepare(SELECT_READY_PROOF_SQL).bind(userId, daemonId, now).first<ClaimProofRow>();
}

/**
 * True only for a live, armed proof this account was issued for this daemon.
 * The row is removed by the same statement, so a replay, another account's
 * proof, a proof for a different daemon and one the daemon never confirmed all
 * fail identically.
 */
export async function consumeClaimProof(
  db: D1Database,
  proof: string,
  userId: string,
  daemonId: string,
  now: number,
): Promise<boolean> {
  const res = await db.prepare(CONSUME_CLAIM_PROOF_SQL).bind(proof, userId, daemonId, now).run();
  return (res.meta.changes ?? 0) === 1;
}

export async function bindDevice(db: D1Database, row: DeviceOwnerRow): Promise<boolean> {
  try {
    const res = await db
      .prepare(INSERT_DEVICE_OWNER_SQL)
      .bind(row.daemon_id, row.user_id, row.label, row.bound_at, row.daemon_id)
      .run();
    return (res.meta.changes ?? 0) === 1;
  } catch {
    return false;
  }
}

export async function getDeviceOwner(db: D1Database, daemonId: string): Promise<DeviceOwnerRow | null> {
  return db.prepare(SELECT_DEVICE_OWNER_SQL).bind(daemonId).first<DeviceOwnerRow>();
}

export async function listDevicesByUser(
  db: D1Database,
  userId: string,
  limit = 64,
): Promise<DeviceOwnerRow[]> {
  const cap = Math.min(Math.max(1, limit), 256);
  const r = await db.prepare(LIST_DEVICES_BY_USER_SQL).bind(userId, cap).all<DeviceOwnerRow>();
  return r.results ?? [];
}

export async function unbindDevice(db: D1Database, daemonId: string, userId: string): Promise<boolean> {
  const res = await db.prepare(DELETE_DEVICE_OWNER_SQL).bind(daemonId, userId).run();
  return (res.meta.changes ?? 0) === 1;
}

export const BIND_INSTALLATION_DAEMONS_SQL = `
  INSERT OR IGNORE INTO device_owners (daemon_id, user_id, label, bound_at)
  SELECT daemon_id, ?, CASE daemon_id
    WHEN 'd_e64cf84bee9b55c19a87' THEN 'devbox'
    WHEN 'd_a2a31b2efb50c89f4581' THEN 'devsg'
    WHEN 'd_c48b9a1b125dc814b4ce' THEN 'devos'
    WHEN 'd_dbfc16e899be94e4ebfa' THEN 'devbox-prod'
    ELSE daemon_id END, ?
  FROM daemons
  WHERE NOT EXISTS (SELECT 1 FROM device_owners WHERE device_owners.daemon_id = daemons.daemon_id)
`;

export async function bindInstallationDaemons(db: D1Database, userId: string, now: number): Promise<void> {
  try {
    await db.prepare(BIND_INSTALLATION_DAEMONS_SQL).bind(userId, now).run();
  } catch {
    // Ignore error if already bound or database unavailable
  }
}
