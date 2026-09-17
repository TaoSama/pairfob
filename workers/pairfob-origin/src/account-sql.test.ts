import { Database } from "bun:sqlite";
import { expect, test } from "bun:test";
import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import {
  CONSUME_CLAIM_PROOF_SQL,
  COUNT_AUTH_FAILURES_SQL,
  DELETE_AUTH_LOCK_SQL,
  INSERT_AUTH_FAILURE_SQL,
  INSERT_CLAIM_PROOF_SQL,
  INSERT_DEVICE_OWNER_SQL,
  READY_CLAIM_PROOF_SQL,
  RELEASE_AUTH_FAILURE_SQL,
  RESERVE_AUTH_FAILURE_SQL,
  SELECT_AUTH_LOCK_SQL,
  SELECT_READY_PROOF_SQL,
  SUSPEND_INVITE_SQL,
  UPSERT_AUTH_LOCK_SQL,
  UPSERT_INVITE_SQL,
} from "./account-store.ts";

/**
 * The FakeD1 double matches statements by string equality and reimplements
 * their effect in TypeScript, so it proves the worker calls the right query but
 * says nothing about what that query does. These run the guard statements that
 * carry a security property against real SQLite, where the predicate is what
 * decides the outcome.
 */
function migrated(): Database {
  const dir = join(import.meta.dir, "..", "migrations");
  const db = new Database(":memory:");
  for (const f of readdirSync(dir).filter((n) => n.endsWith(".sql")).sort()) {
    db.exec(readFileSync(join(dir, f), "utf8"));
  }
  return db;
}

function changes(db: Database, sql: string, ...values: unknown[]): number {
  return db.query(sql).run(...(values as never[])).changes;
}

test("the device insert refuses a second owner without reading first", () => {
  const db = migrated();
  const args = (user: string) => ["d_one", user, "laptop", 10, "d_one"];
  expect(changes(db, INSERT_DEVICE_OWNER_SQL, ...args("u_a"))).toBe(1);
  // The WHERE NOT EXISTS lives inside the write, so the loser is rejected by
  // the database rather than by a check the worker ran moments earlier.
  expect(changes(db, INSERT_DEVICE_OWNER_SQL, ...args("u_b"))).toBe(0);
  const row = db.query("SELECT user_id FROM device_owners WHERE daemon_id = 'd_one'").get();
  expect(row).toEqual({ user_id: "u_a" });
});

test("consuming a claim proof enforces owner, device, arming and expiry in one statement", () => {
  const db = migrated();
  const put = (proof: string) =>
    changes(db, INSERT_CLAIM_PROOF_SQL, proof, "u_a", "d_one", 0, 1_000, "");
  const arm = (user: string, daemon: string, now: number) =>
    changes(db, READY_CLAIM_PROOF_SQL, now, "rt", user, daemon, now);

  put("cp_1");
  // Unarmed is unusable even for the right account, right device, in time.
  expect(changes(db, CONSUME_CLAIM_PROOF_SQL, "cp_1", "u_a", "d_one", 500)).toBe(0);

  // Arming is scoped the same way, so a confirmation attributed to another
  // account or another daemon cannot reach this row.
  expect(arm("u_b", "d_one", 100)).toBe(0);
  expect(arm("u_a", "d_two", 100)).toBe(0);
  expect(arm("u_a", "d_one", 100)).toBe(1);
  // Already armed, so a second confirmation does not extend or re-point it.
  expect(arm("u_a", "d_one", 200)).toBe(0);

  expect(changes(db, CONSUME_CLAIM_PROOF_SQL, "cp_1", "u_b", "d_one", 500)).toBe(0);
  expect(changes(db, CONSUME_CLAIM_PROOF_SQL, "cp_1", "u_a", "d_two", 500)).toBe(0);
  expect(changes(db, CONSUME_CLAIM_PROOF_SQL, "cp_1", "u_a", "d_one", 1_000)).toBe(0);
  expect(changes(db, CONSUME_CLAIM_PROOF_SQL, "cp_1", "u_a", "d_one", 999)).toBe(1);
  // Gone, so a replay of the accepted call buys nothing.
  expect(changes(db, CONSUME_CLAIM_PROOF_SQL, "cp_1", "u_a", "d_one", 999)).toBe(0);
});

test("an expired proof can no longer be armed", () => {
  const db = migrated();
  changes(db, INSERT_CLAIM_PROOF_SQL, "cp_2", "u_a", "d_one", 0, 1_000, "");
  // A confirmation that arrives after the window closed must not revive it,
  // otherwise a stale pending proof stays claimable indefinitely.
  expect(changes(db, READY_CLAIM_PROOF_SQL, 1_500, "rt", "u_a", "d_one", 1_500)).toBe(0);
  expect(changes(db, CONSUME_CLAIM_PROOF_SQL, "cp_2", "u_a", "d_one", 1_500)).toBe(0);
});

test("the ready lookup returns only an armed, live proof for that account", () => {
  const db = migrated();
  changes(db, INSERT_CLAIM_PROOF_SQL, "cp_3", "u_a", "d_one", 0, 1_000, "");
  const ready = (user: string, daemon: string, now: number) =>
    db.query(SELECT_READY_PROOF_SQL).get(user, daemon, now) as { proof: string } | null;

  expect(ready("u_a", "d_one", 500)).toBeNull();
  changes(db, READY_CLAIM_PROOF_SQL, 100, "rt", "u_a", "d_one", 100);
  expect(ready("u_a", "d_one", 500)?.proof).toBe("cp_3");
  expect(ready("u_b", "d_one", 500)).toBeNull();
  expect(ready("u_a", "d_two", 500)).toBeNull();
  expect(ready("u_a", "d_one", 1_000)).toBeNull();
});

test("the failure count is scoped to one subject and one window", () => {
  const db = migrated();
  changes(db, INSERT_AUTH_FAILURE_SQL, "ip:a", 100);
  changes(db, INSERT_AUTH_FAILURE_SQL, "ip:a", 200);
  changes(db, INSERT_AUTH_FAILURE_SQL, "ip:b", 200);
  const count = (subject: string, after: number) =>
    (db.query(COUNT_AUTH_FAILURES_SQL).get(subject, after) as { n: number }).n;
  expect(count("ip:a", 0)).toBe(2);
  expect(count("ip:a", 150)).toBe(1);
  expect(count("ip:b", 0)).toBe(1);
});

/**
 * The reservation is the whole lockout: if the limit is not decided by the
 * same statement that writes the row, a burst walks straight past it. These
 * run it against real SQLite, where the subquery is what refuses.
 */
test("the reservation refuses the moment the subject is at its limit", () => {
  const db = migrated();
  const reserve = (subject: string, at: number, limit = 3) =>
    changes(db, RESERVE_AUTH_FAILURE_SQL, subject, at, subject, 0, limit);

  expect(reserve("ip:a", 100)).toBe(1);
  expect(reserve("ip:a", 101)).toBe(1);
  expect(reserve("ip:a", 102)).toBe(1);
  // Four in a three-strike budget: the insert itself declines, so the ledger
  // cannot overshoot no matter how many callers arrive together.
  expect(reserve("ip:a", 103)).toBe(0);
  expect(
    (db.query(COUNT_AUTH_FAILURES_SQL).get("ip:a", 0) as { n: number }).n,
  ).toBe(3);

  // Another subject is unaffected, and a larger limit is honoured.
  expect(reserve("ip:b", 104)).toBe(1);
  expect(reserve("ip:a", 105, 4)).toBe(1);
});

test("the reservation window slides, so an old strike stops counting", () => {
  const db = migrated();
  const reserve = (at: number, since: number) =>
    changes(db, RESERVE_AUTH_FAILURE_SQL, "ip:w", at, "ip:w", since, 3);

  for (let i = 0; i < 3; i++) expect(reserve(100 + i, 0)).toBe(1);
  expect(reserve(200, 0)).toBe(0);
  // `at > ?` is exclusive, so a cutoff at the last strike's timestamp drops
  // every earlier one and the budget opens again.
  expect(reserve(200, 102)).toBe(1);
});

test("a release takes back exactly one row, addressed by id", () => {
  const db = migrated();
  const reserve = (subject: string, at: number) => {
    const res = db.query(RESERVE_AUTH_FAILURE_SQL).run(subject, at, subject, 0, 10);
    expect(res.changes).toBe(1);
    return Number(res.lastInsertRowid);
  };

  // Two sources striking the same shared subject in the same millisecond, which
  // is what the global invite budget looks like under a spread-out guess.
  const mine = reserve("invite:global", 100);
  const theirs = reserve("invite:global", 100);
  expect(mine).not.toBe(theirs);

  expect(changes(db, RELEASE_AUTH_FAILURE_SQL, mine)).toBe(1);
  // The other strike survives: a refund cannot reach a row it did not write.
  const left = db.query("SELECT id FROM auth_failures").all() as Array<{ id: number }>;
  expect(left).toEqual([{ id: theirs }]);

  // Releasing the same id twice is a no-op rather than eating the neighbour.
  expect(changes(db, RELEASE_AUTH_FAILURE_SQL, mine)).toBe(0);
});

test("suspending names the version, so a late loser cannot shut a newer code", () => {
  const db = migrated();
  changes(db, UPSERT_INVITE_SQL, "ABCD", "u_a", 1);
  expect(changes(db, SUSPEND_INVITE_SQL, 50, 1)).toBe(1);
  // A second suspend reports no change, which is how the caller avoids
  // re-announcing a suspension that already happened.
  expect(changes(db, SUSPEND_INVITE_SQL, 60, 1)).toBe(0);
  expect((db.query("SELECT suspended_at FROM invite_codes WHERE id = 1").get() as { suspended_at: number }).suspended_at).toBe(50);

  changes(db, UPSERT_INVITE_SQL, "WXYZ", "u_a", 70);
  expect(db.query("SELECT code, suspended_at, version FROM invite_codes WHERE id = 1").get()).toEqual({
    code: "WXYZ",
    suspended_at: 0,
    version: 2,
  });

  // A request that read version 1, lost its race and only now reaches its
  // verdict must not take down the code that replaced it.
  expect(changes(db, SUSPEND_INVITE_SQL, 80, 1)).toBe(0);
  expect((db.query("SELECT suspended_at FROM invite_codes WHERE id = 1").get() as { suspended_at: number }).suspended_at).toBe(0);
  expect(changes(db, SUSPEND_INVITE_SQL, 90, 2)).toBe(1);
});

test("a ban carries its own deadline instead of being read off the strike count", () => {
  const db = migrated();
  const HOUR = 3_600_000;
  const live = (subject: string, now: number) =>
    db.query(SELECT_AUTH_LOCK_SQL).all(subject, now).length;

  changes(db, UPSERT_AUTH_LOCK_SQL, "invite:ip:a", 1_000 + HOUR);
  expect(live("invite:ip:a", 1_000)).toBe(1);
  // Still banned well past the point where the first of three strikes would
  // have aged out of a trailing window.
  expect(live("invite:ip:a", 1_000 + HOUR - 1)).toBe(1);
  expect(live("invite:ip:a", 1_000 + HOUR)).toBe(0);

  // A later attempt extends the ban; an earlier one cannot shorten it.
  changes(db, UPSERT_AUTH_LOCK_SQL, "invite:ip:a", 2_000 + HOUR);
  changes(db, UPSERT_AUTH_LOCK_SQL, "invite:ip:a", 500 + HOUR);
  expect(
    (db.query("SELECT until FROM auth_locks WHERE subject = ?").get("invite:ip:a") as { until: number }).until,
  ).toBe(2_000 + HOUR);

  // Domains are separate subjects, so clearing one leaves the other banned.
  changes(db, UPSERT_AUTH_LOCK_SQL, "login:ip:a", 2_000 + HOUR);
  changes(db, DELETE_AUTH_LOCK_SQL, "login:ip:a");
  expect(live("invite:ip:a", 2_000)).toBe(1);
  expect(live("login:ip:a", 2_000)).toBe(0);
});
