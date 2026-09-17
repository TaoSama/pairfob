import {
  CONSUME_CLAIM_PROOF_SQL,
  COUNT_AUTH_FAILURES_SQL,
  COUNT_USERS_SQL,
  DELETE_AUTH_FAILURES_SQL,
  DELETE_AUTH_LOCK_SQL,
  DELETE_DEVICE_OWNER_SQL,
  DELETE_SESSION_SQL,
  INSERT_AUTH_FAILURE_SQL,
  INSERT_CLAIM_PROOF_SQL,
  INSERT_DEVICE_OWNER_SQL,
  INSERT_FIRST_USER_SQL,
  INSERT_SESSION_SQL,
  INSERT_USER_SQL,
  LIST_DEVICES_BY_USER_SQL,
  PRUNE_AUTH_FAILURES_SQL,
  PRUNE_AUTH_LOCKS_SQL,
  PRUNE_CLAIM_PROOFS_SQL,
  PRUNE_SESSIONS_SQL,
  READY_CLAIM_PROOF_SQL,
  RELEASE_AUTH_FAILURE_SQL,
  RESERVE_AUTH_FAILURE_SQL,
  SELECT_AUTH_LOCK_SQL,
  SELECT_DEVICE_OWNER_SQL,
  SELECT_INVITE_SQL,
  SELECT_READY_PROOF_SQL,
  SELECT_SESSION_SQL,
  SELECT_USER_BY_ID_SQL,
  SELECT_USER_BY_NAME_SQL,
  SUSPEND_INVITE_SQL,
  UPSERT_AUTH_LOCK_SQL,
  UPSERT_INVITE_SQL,
  type ClaimProofRow,
  type DeviceOwnerRow,
  type InviteRow,
  type SessionRow,
  type UserRow,
} from "../account-store.ts";
import {
  INSERT_VAULT_SQL,
  SELECT_VAULT_SQL,
  UPDATE_VAULT_SQL,
  type VaultRow,
} from "../account-vault.ts";

/** `id` mirrors the AUTOINCREMENT column the release statement targets. */
export interface FailureRow {
  subject: string;
  at: number;
  id?: number;
}

export interface AccountSnapshot {
  users: Map<string, UserRow>;
  sessions: Map<string, SessionRow>;
  devices: Map<string, DeviceOwnerRow>;
  proofs: Map<string, ClaimProofRow>;
  vaults: Map<string, VaultRow>;
  failures: FailureRow[];
  locks: Map<string, number>;
  invite: InviteRow | null;
  nextFailureId: number;
}

/**
 * The account half of the D1 double. Each handler mirrors one statement in
 * `account-store.ts`, including its guard clauses, so a test that passes here
 * exercises the same refusal the database would produce.
 */
export class AccountTables {
  users = new Map<string, UserRow>();
  sessions = new Map<string, SessionRow>();
  devices = new Map<string, DeviceOwnerRow>();
  proofs = new Map<string, ClaimProofRow>();
  vaults = new Map<string, VaultRow>();
  failures: FailureRow[] = [];
  /** Ban deadlines by subject, separate from the strike ledger. */
  locks = new Map<string, number>();
  invite: InviteRow | null = null;
  nextFailureId = 1;

  /** The rowid the most recent insert produced, mirroring D1's `last_row_id`. */
  lastRowId = 0;

  /**
   * Holds the next invite read open so a test can interleave a rotation into
   * the middle of a registration. Latency alone cannot express this: the point
   * is a request that read one version and finishes against another, which
   * needs the suspension to happen at a named point, not a likely one.
   */
  private invitePause: Promise<void> | null = null;
  private releaseInvitePause: (() => void) | null = null;
  private inviteReached: Promise<void> | null = null;
  private markInviteReached: (() => void) | null = null;

  pauseNextInviteRead(): void {
    this.invitePause = new Promise((resolve) => {
      this.releaseInvitePause = resolve;
    });
    this.inviteReached = new Promise((resolve) => {
      this.markInviteReached = resolve;
    });
  }

  /** Resolves once a reader has actually arrived at the paused invite read. */
  inviteReadReached(): Promise<void> {
    return this.inviteReached ?? Promise.resolve();
  }

  resumeInviteRead(): void {
    this.releaseInvitePause?.();
    this.invitePause = null;
    this.releaseInvitePause = null;
    this.inviteReached = null;
  }

  /**
   * Awaited by the double before it answers a paused invite read. One-shot: the
   * rotation that runs while a reader is held reads the invite too, and holding
   * that one as well would deadlock the test.
   */
  takeInvitePause(): Promise<void> | null {
    const paused = this.invitePause;
    if (!paused) return null;
    this.invitePause = null;
    this.markInviteReached?.();
    this.markInviteReached = null;
    return paused;
  }

  snapshot(): AccountSnapshot {
    return {
      users: cloneMap(this.users),
      sessions: cloneMap(this.sessions),
      devices: cloneMap(this.devices),
      proofs: cloneMap(this.proofs),
      vaults: cloneMap(this.vaults),
      failures: this.failures.map((f) => ({ ...f })),
      locks: new Map(this.locks),
      invite: this.invite ? { ...this.invite } : null,
      nextFailureId: this.nextFailureId,
    };
  }

  restore(snap: AccountSnapshot): void {
    this.users = snap.users;
    this.sessions = snap.sessions;
    this.devices = snap.devices;
    this.proofs = snap.proofs;
    this.vaults = snap.vaults;
    this.failures = snap.failures;
    this.locks = snap.locks;
    this.invite = snap.invite;
    this.nextFailureId = snap.nextFailureId;
  }

  /** Returns the row count, or null when the statement belongs to another table family. */
  run(sql: string, values: unknown[]): number | null {
    if (sql === INSERT_FIRST_USER_SQL) {
      if (this.users.size > 0) return 0;
      return this.putUser(values);
    }
    if (sql === INSERT_USER_SQL) {
      const username = String(values[5]);
      for (const u of this.users.values()) if (u.username === username) return 0;
      return this.putUser(values);
    }
    if (sql === INSERT_SESSION_SQL) {
      const row: SessionRow = {
        token_hash: String(values[0]),
        user_id: String(values[1]),
        created_at: Number(values[2]),
        expires_at: Number(values[3]),
      };
      if (this.sessions.has(row.token_hash)) throw new Error("UNIQUE constraint failed: user_sessions");
      this.sessions.set(row.token_hash, row);
      return 1;
    }
    if (sql === DELETE_SESSION_SQL) {
      return this.sessions.delete(String(values[0])) ? 1 : 0;
    }
    if (sql === PRUNE_SESSIONS_SQL) {
      const cutoff = Number(values[0]);
      let n = 0;
      for (const [k, s] of this.sessions) {
        if (s.expires_at <= cutoff) {
          this.sessions.delete(k);
          n++;
        }
      }
      return n;
    }
    if (sql === UPSERT_INVITE_SQL) {
      this.invite = {
        id: 1,
        code: String(values[0]),
        updated_by: (values[1] as string | null) ?? null,
        updated_at: Number(values[2]),
        suspended_at: 0,
        version: (this.invite?.version ?? 0) + 1,
      };
      return 1;
    }
    if (sql === SUSPEND_INVITE_SQL) {
      if (!this.invite || this.invite.suspended_at !== 0) return 0;
      // Version is part of the predicate, so a request that read an older code
      // cannot suspend the one that replaced it.
      if (this.invite.version !== Number(values[1])) return 0;
      this.invite.suspended_at = Number(values[0]);
      return 1;
    }
    if (sql === UPSERT_AUTH_LOCK_SQL) {
      const subject = String(values[0]);
      const until = Number(values[1]);
      const held = this.locks.get(subject) ?? 0;
      this.locks.set(subject, Math.max(held, until));
      return 1;
    }
    if (sql === DELETE_AUTH_LOCK_SQL) {
      return this.locks.delete(String(values[0])) ? 1 : 0;
    }
    if (sql === PRUNE_AUTH_LOCKS_SQL) {
      const cutoff = Number(values[0]);
      let n = 0;
      for (const [subject, until] of this.locks) {
        if (until <= cutoff) {
          this.locks.delete(subject);
          n++;
        }
      }
      return n;
    }
    if (sql === INSERT_AUTH_FAILURE_SQL) {
      this.failures.push({ subject: String(values[0]), at: Number(values[1]) });
      return 1;
    }
    if (sql === RESERVE_AUTH_FAILURE_SQL) {
      const subject = String(values[0]);
      const at = Number(values[1]);
      const since = Number(values[3]);
      const limit = Number(values[4]);
      // The limit is evaluated as part of the write, exactly as the SELECT
      // subquery does, so a refused reservation leaves no row behind.
      const held = this.failures.filter((f) => f.subject === subject && f.at > since).length;
      if (held >= limit) return 0;
      this.lastRowId = this.nextFailureId++;
      this.failures.push({ subject, at, id: this.lastRowId });
      return 1;
    }
    if (sql === RELEASE_AUTH_FAILURE_SQL) {
      const id = Number(values[0]);
      // Addressed by primary key, so a refund can only ever take back the one
      // row its own reservation wrote.
      const at = this.failures.findIndex((f) => f.id === id);
      if (at < 0) return 0;
      this.failures.splice(at, 1);
      return 1;
    }
    if (sql === DELETE_AUTH_FAILURES_SQL) {
      const subject = String(values[0]);
      const before = this.failures.length;
      this.failures = this.failures.filter((f) => f.subject !== subject);
      return before - this.failures.length;
    }
    if (sql === PRUNE_AUTH_FAILURES_SQL) {
      const cutoff = Number(values[0]);
      const before = this.failures.length;
      this.failures = this.failures.filter((f) => f.at > cutoff);
      return before - this.failures.length;
    }
    if (sql === INSERT_CLAIM_PROOF_SQL) {
      const proof = String(values[0]);
      if (this.proofs.has(proof)) throw new Error("UNIQUE constraint failed: device_claim_proofs");
      this.proofs.set(proof, {
        proof,
        user_id: String(values[1]),
        daemon_id: String(values[2]),
        created_at: Number(values[3]),
        expires_at: Number(values[4]),
        ready_at: 0,
        route_id: String(values[5]),
      });
      return 1;
    }
    if (sql === READY_CLAIM_PROOF_SQL) {
      const at = Number(values[0]);
      const routeId = String(values[1]);
      const userId = String(values[2]);
      const daemonId = String(values[3]);
      const now = Number(values[4]);
      let n = 0;
      for (const row of this.proofs.values()) {
        if (row.user_id !== userId) continue;
        if (row.daemon_id !== daemonId) continue;
        if (row.ready_at !== 0) continue;
        if (row.expires_at <= now) continue;
        row.ready_at = at;
        row.route_id = routeId;
        n++;
      }
      return n;
    }
    if (sql === CONSUME_CLAIM_PROOF_SQL) {
      const row = this.proofs.get(String(values[0]));
      if (!row) return 0;
      if (row.user_id !== String(values[1])) return 0;
      if (row.daemon_id !== String(values[2])) return 0;
      if (row.ready_at <= 0) return 0;
      if (row.expires_at <= Number(values[3])) return 0;
      this.proofs.delete(row.proof);
      return 1;
    }
    if (sql === PRUNE_CLAIM_PROOFS_SQL) {
      const cutoff = Number(values[0]);
      let n = 0;
      for (const [k, p] of this.proofs) {
        if (p.expires_at <= cutoff) {
          this.proofs.delete(k);
          n++;
        }
      }
      return n;
    }
    if (sql === INSERT_DEVICE_OWNER_SQL) {
      const daemonId = String(values[0]);
      if (this.devices.has(daemonId)) return 0;
      this.devices.set(daemonId, {
        daemon_id: daemonId,
        user_id: String(values[1]),
        label: (values[2] as string | null) ?? null,
        bound_at: Number(values[3]),
      });
      return 1;
    }
    if (sql === DELETE_DEVICE_OWNER_SQL) {
      const row = this.devices.get(String(values[0]));
      if (!row || row.user_id !== String(values[1])) return 0;
      this.devices.delete(row.daemon_id);
      return 1;
    }
    if (sql === INSERT_VAULT_SQL) {
      const userId = String(values[0]);
      if (this.vaults.has(String(values[6]))) return 0;
      this.vaults.set(userId, {
        user_id: userId,
        ciphertext: String(values[1]),
        nonce: String(values[2]),
        kdf: String(values[3]),
        version: Number(values[4]),
        updated_at: Number(values[5]),
      });
      return 1;
    }
    if (sql === UPDATE_VAULT_SQL) {
      const row = this.vaults.get(String(values[5]));
      // The version check is part of the write here too, so the double refuses
      // the stale writer exactly where the database would.
      if (!row || row.version !== Number(values[6])) return 0;
      row.ciphertext = String(values[0]);
      row.nonce = String(values[1]);
      row.kdf = String(values[2]);
      row.version = Number(values[3]);
      row.updated_at = Number(values[4]);
      return 1;
    }
    return null;
  }

  first<T>(sql: string, values: unknown[]): { row: T | null } | null {
    if (sql === SELECT_USER_BY_NAME_SQL) {
      const username = String(values[0]);
      for (const u of this.users.values()) if (u.username === username) return { row: u as T };
      return { row: null };
    }
    if (sql === SELECT_USER_BY_ID_SQL) {
      return { row: (this.users.get(String(values[0])) ?? null) as T | null };
    }
    if (sql === COUNT_USERS_SQL) {
      return { row: { n: this.users.size } as T };
    }
    if (sql === SELECT_SESSION_SQL) {
      const row = this.sessions.get(String(values[0]));
      const now = Number(values[1]);
      return { row: row && row.expires_at > now ? (row as T) : null };
    }
    if (sql === SELECT_INVITE_SQL) {
      return { row: (this.invite ?? null) as T | null };
    }
    if (sql === COUNT_AUTH_FAILURES_SQL) {
      const subject = String(values[0]);
      const since = Number(values[1]);
      const n = this.failures.filter((f) => f.subject === subject && f.at > since).length;
      return { row: { n } as T };
    }
    if (sql === SELECT_AUTH_LOCK_SQL) {
      const until = this.locks.get(String(values[0])) ?? 0;
      return { row: until > Number(values[1]) ? ({ until } as T) : null };
    }
    if (sql === SELECT_DEVICE_OWNER_SQL) {
      return { row: (this.devices.get(String(values[0])) ?? null) as T | null };
    }
    if (sql === SELECT_READY_PROOF_SQL) {
      const userId = String(values[0]);
      const daemonId = String(values[1]);
      const now = Number(values[2]);
      for (const row of this.proofs.values()) {
        if (row.user_id !== userId) continue;
        if (row.daemon_id !== daemonId) continue;
        if (row.ready_at <= 0) continue;
        if (row.expires_at <= now) continue;
        return { row: row as T };
      }
      return { row: null };
    }
    if (sql === SELECT_VAULT_SQL) {
      return { row: (this.vaults.get(String(values[0])) ?? null) as T | null };
    }
    return null;
  }

  all<T>(sql: string, values: unknown[]): { results: T[] } | null {
    if (sql === LIST_DEVICES_BY_USER_SQL) {
      const userId = String(values[0]);
      const cap = Number(values[1] ?? 64);
      const rows = Array.from(this.devices.values())
        .filter((d) => d.user_id === userId)
        .sort((a, b) => a.bound_at - b.bound_at)
        .slice(0, cap);
      return { results: rows as T[] };
    }
    return null;
  }

  private putUser(values: unknown[]): number {
    const row: UserRow = {
      user_id: String(values[0]),
      username: String(values[1]),
      password_hash: String(values[2]),
      role: String(values[3]),
      created_at: Number(values[4]),
    };
    this.users.set(row.user_id, row);
    return 1;
  }
}

function cloneMap<T extends object>(input: Map<string, T>): Map<string, T> {
  return new Map(Array.from(input, ([key, value]) => [key, { ...value }]));
}
