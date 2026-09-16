import {
  CAS_ENROLL_SQL,
  CLEAR_ENROLL_NONCE_SQL,
  COMPENSATE_DAEMON_USED_SQL,
  COMPENSATE_USED_SQL,
  DELETE_DAEMON_SQL,
  INSERT_DAEMON_SQL,
  INSERT_SELF_GRANT_ROW_SQL,
  INSERT_SELF_GRANT_SQL,
  KICK_DAEMON_SQL,
  MARK_QUOTA_RELEASED_SQL,
  PRUNE_SELF_GRANTS_SQL,
  RELEASE_KICK_QUOTA_SQL,
  LIST_LIVE_DAEMON_IDS_SQL,
  SELECT_DAEMON_SQL,
  SELECT_GRANT_BY_ID_SQL,
  type DaemonRow,
  type GrantRow,
} from "../d1.ts";
import { AccountTables } from "./fake-accounts.ts";
import { SELECT_INVITE_SQL } from "../account-store.ts";

class Bound implements D1PreparedStatement {
  constructor(
    readonly db: FakeD1,
    readonly sql: string,
    readonly values: unknown[] = [],
  ) {}

  bind(...values: unknown[]): D1PreparedStatement {
    return new Bound(this.db, this.sql, values);
  }

  async run(): Promise<D1Result> {
    this.db.note(this.sql);
    await this.db.gate();
    return this.db.run(this.sql, this.values);
  }

  async first<T = Record<string, unknown>>(): Promise<T | null> {
    this.db.note(this.sql);
    await this.db.gate();
    if (this.sql.replace(/\s+/g, " ").trim() === SELECT_INVITE_SQL) {
      // The row is captured first and the stall happens after, because the
      // request being modelled is one that already read a version and is slow
      // to act on it — not one that reads late and sees the new state.
      const row = this.db.first<T>(this.sql, this.values);
      const paused = this.db.accounts.takeInvitePause();
      if (paused) await paused;
      return row;
    }
    return this.db.first<T>(this.sql, this.values);
  }

  async all<T = Record<string, unknown>>(): Promise<{ results: T[]; success: boolean }> {
    this.db.note(this.sql);
    await this.db.gate();
    return this.db.all<T>(this.sql, this.values);
  }
}

export interface SelfGrantRow {
  grant_id: string;
  ip_hash: string;
  created_at: number;
}

export class FakeD1 implements D1Database {
  grants = new Map<string, GrantRow>();
  daemons = new Map<string, DaemonRow>();
  selfGrants = new Map<string, SelfGrantRow>();
  enrollNonces = new Map<string, string>();
  accounts = new AccountTables();
  failNextInsert = false;

  /** Every statement issued, normalized, in the order the worker asked for it. */
  statements: string[] = [];

  /**
   * Milliseconds a round trip takes. Zero keeps the double on microtasks, which
   * is enough to interleave two requests but not to let a third overtake them.
   * A positive value spreads the window wide enough that every request in
   * flight reaches its first await before any of them comes back, which is the
   * shape production sees when D1 is a network hop away.
   */
  latencyMs = 0;

  prepare(query: string): D1PreparedStatement {
    return new Bound(this, query, []);
  }

  note(sql: string): void {
    this.statements.push(sql.replace(/\s+/g, " ").trim());
  }

  /** How many times a given statement has been issued. */
  count(sql: string): number {
    const want = sql.replace(/\s+/g, " ").trim();
    return this.statements.filter((s) => s === want).length;
  }

  /**
   * Every standalone statement yields before it runs. Real D1 round-trips, so
   * two requests that each read-then-write can interleave between their two
   * awaits; a double that resolves synchronously hides exactly that race.
   */
  async gate(): Promise<void> {
    if (this.latencyMs > 0) {
      await new Promise((resolve) => setTimeout(resolve, this.latencyMs));
      return;
    }
    await Promise.resolve();
    await Promise.resolve();
  }

  /**
   * A batch is one round trip: it yields once, then applies every statement
   * without giving another request a chance to run in between. This is what
   * makes it usable as a transaction.
   */
  async batch<T = Record<string, unknown>>(statements: D1PreparedStatement[]): Promise<D1Result<T>[]> {
    for (const s of statements) this.note((s as Bound).sql);
    await this.gate();
    const grants = cloneMap(this.grants);
    const daemons = cloneMap(this.daemons);
    const selfGrants = cloneMap(this.selfGrants);
    const nonces = new Map(this.enrollNonces);
    const accounts = this.accounts.snapshot();
    try {
      const out: D1Result<T>[] = [];
      for (const s of statements) {
        const b = s as Bound;
        out.push(this.run(b.sql, b.values) as D1Result<T>);
      }
      return out;
    } catch (error) {
      this.grants = grants;
      this.daemons = daemons;
      this.selfGrants = selfGrants;
      this.enrollNonces = nonces;
      this.accounts.restore(accounts);
      throw error;
    }
  }

  run(sql: string, values: unknown[]): D1Result {
    const s = sql.replace(/\s+/g, " ").trim();
    const account = this.accounts.run(s, values);
    if (account !== null) return changes(account, this.accounts.lastRowId);
    if (s === CAS_ENROLL_SQL) {
      const nonce = String(values[0]);
      const now = Number(values[1]);
      const id = String(values[2]);
      const cutoff = Number(values[3]);
      const g = this.grants.get(id);
      if (
        !g || g.revoked_at != null || g.used >= g.max_daemons || this.enrollNonces.has(id) ||
        (g.last_enroll_at != null && g.last_enroll_at > cutoff)
      ) return changes(0);
      g.used += 1;
      g.last_enroll_at = now;
      this.enrollNonces.set(id, nonce);
      return changes(1);
    }
    if (s === CLEAR_ENROLL_NONCE_SQL) {
      const id = String(values[0]);
      const nonce = String(values[1]);
      if (this.enrollNonces.get(id) !== nonce) return changes(0);
      this.enrollNonces.delete(id);
      return changes(1);
    }
    if (s === COMPENSATE_USED_SQL) {
      const id = String(values[0]);
      const g = this.grants.get(id);
      if (!g || g.used <= 0) return changes(0);
      g.used -= 1;
      return changes(1);
    }
    if (s === INSERT_DAEMON_SQL) {
      const grantID = String(values[4]);
      const nonce = String(values[5]);
      if (this.enrollNonces.get(grantID) !== nonce) return changes(0);
      if (this.failNextInsert) {
        this.failNextInsert = false;
        throw new Error("insert fail");
      }
      const row: DaemonRow = {
        daemon_id: String(values[0]),
        grant_id: String(values[1]),
        created_at: Number(values[2]),
        kicked_at: null,
        enroll_ip_hash: String(values[3]),
        quota_released_at: null,
      };
      this.daemons.set(row.daemon_id, row);
      return changes(1);
    }
    if (s === COMPENSATE_DAEMON_USED_SQL) {
      const grantID = String(values[0]);
      const daemonID = String(values[1]);
      const daemon = this.daemons.get(daemonID);
      const grant = this.grants.get(grantID);
      if (!daemon || daemon.grant_id !== String(values[2]) || daemon.quota_released_at != null || !grant || grant.used <= 0) {
        return changes(0);
      }
      grant.used -= 1;
      return changes(1);
    }
    if (s === DELETE_DAEMON_SQL) {
      const ok = this.daemons.delete(String(values[0]));
      return changes(ok ? 1 : 0);
    }
    if (s === INSERT_SELF_GRANT_SQL) {
      const grantID = String(values[0]);
      const ipHash = String(values[1]);
      const createdAt = Number(values[2]);
      const windowStart = Number(values[4]);
      const quota = Number(values[5]);
      let n = 0;
      for (const r of this.selfGrants.values()) {
        if (r.ip_hash === String(values[3]) && r.created_at > windowStart) n++;
      }
      if (n >= quota) return changes(0);
      this.selfGrants.set(grantID, { grant_id: grantID, ip_hash: ipHash, created_at: createdAt });
      return changes(1);
    }
    if (s === INSERT_SELF_GRANT_ROW_SQL) {
      if (!this.selfGrants.has(String(values[5]))) return changes(0);
      this.putGrant({
        grant_id: String(values[0]),
        grant_hash: String(values[1]),
        max_daemons: Number(values[2]),
        used: 0,
        label: (values[3] as string | null) ?? null,
        created_at: Number(values[4]),
        revoked_at: null,
        last_enroll_at: null,
      });
      return changes(1);
    }
    if (s === PRUNE_SELF_GRANTS_SQL) {
      const cutoff = Number(values[0]);
      let n = 0;
      for (const [id, r] of this.selfGrants) {
        if (r.created_at <= cutoff) {
          this.selfGrants.delete(id);
          n++;
        }
      }
      return changes(n);
    }
    if (s === KICK_DAEMON_SQL) {
      const d = this.daemons.get(String(values[1]));
      if (!d || d.kicked_at != null) return changes(0);
      d.kicked_at = Number(values[0]);
      return changes(1);
    }
    if (s === RELEASE_KICK_QUOTA_SQL) {
      const grantID = String(values[0]);
      const daemon = this.daemons.get(String(values[1]));
      const grant = this.grants.get(grantID);
      if (
        !daemon ||
        daemon.grant_id !== String(values[2]) ||
        daemon.kicked_at == null ||
        daemon.quota_released_at != null ||
        !grant ||
        grant.used <= 0
      ) return changes(0);
      grant.used -= 1;
      return changes(1);
    }
    if (s === MARK_QUOTA_RELEASED_SQL) {
      const daemon = this.daemons.get(String(values[1]));
      if (!daemon || daemon.kicked_at == null || daemon.quota_released_at != null) return changes(0);
      daemon.quota_released_at = Number(values[0]);
      return changes(1);
    }
    // A read inside batch() must carry its rows, not just a change count:
    // callers that count in the same transaction read them off the result.
    if (s.startsWith("SELECT")) {
      const read = this.all<Record<string, unknown>>(sql, values);
      return { success: true, results: read.results, meta: { changes: 0, last_row_id: 0 } };
    }
    throw new Error("unhandled SQL: " + s);
  }

  first<T>(sql: string, values: unknown[]): T | null {
    const s = sql.replace(/\s+/g, " ").trim();
    const account = this.accounts.first<T>(s, values);
    if (account !== null) return account.row;
    if (s === SELECT_GRANT_BY_ID_SQL) {
      return (this.grants.get(String(values[0])) ?? null) as T | null;
    }
    if (s === SELECT_DAEMON_SQL) {
      return (this.daemons.get(String(values[0])) ?? null) as T | null;
    }
    throw new Error("unhandled SQL first: " + s);
  }

  all<T>(sql: string, values: unknown[]): { results: T[]; success: boolean } {
    const s = sql.replace(/\s+/g, " ").trim();
    const account = this.accounts.all<T>(s, values);
    if (account !== null) return { results: account.results, success: true };
    if (s === LIST_LIVE_DAEMON_IDS_SQL) {
      const cap = Number(values[0] ?? 32);
      const rows: T[] = [];
      for (const d of this.daemons.values()) {
        if (d.kicked_at != null) continue;
        rows.push({ daemon_id: d.daemon_id } as T);
        if (rows.length >= cap) break;
      }
      return { results: rows, success: true };
    }
    const row = this.first<T>(sql, values);
    return { results: row ? [row] : [], success: true };
  }

  putGrant(row: GrantRow): void {
    this.grants.set(row.grant_id, row);
  }
}

function cloneMap<T extends object>(input: Map<string, T>): Map<string, T> {
  return new Map(Array.from(input, ([key, value]) => [key, { ...value }]));
}

function changes(n: number, lastRowId = 0): D1Result {
  return { success: true, meta: { changes: n, last_row_id: lastRowId } };
}
