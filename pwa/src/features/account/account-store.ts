import { createDomain } from "../../shared/model/domain-store";
import type { AccountRole, BoundDevice } from "../../lib/account-api";

/**
 * Account domain: who this phone is signed in as, which machines that account
 * owns, and the key material that makes them usable.
 *
 * Two keys, and the difference matters. `wrapKey` comes from the passphrase and
 * only ever opens the wrapped record in the vault's KDF column; `vaultKey` is the
 * random key that actually encrypts the credentials, and it exists here only
 * after a vault has been read and unwrapped. A phone that has signed in but not
 * yet fetched its vault holds the first and not the second.
 *
 * Both are opaque handles rather than published data. They are key material:
 * copying them into a frozen snapshot on every publish would scatter them across
 * the heap, and nothing renders them, so sharing one array by identity is both
 * safer and what the primitive is for.
 *
 * The passphrase is never here. It is consumed once at sign-in to derive the
 * wrapping key and then goes out of scope, so this record holds nothing that
 * could be replayed as a password.
 */
/**
 * What the account plane is currently asking of the person.
 *
 * `off` is the ordinary application: the account page is not in the way. `entry`
 * is the sign-in/registration form, and `devices` is the list of machines this
 * account owns, which is where a phone lands after signing in and where it picks
 * or adds one. It defaults to `off` so a deployment that never reached the
 * account plane composes exactly as it did before.
 */
export type AccountGate = "off" | "entry";

export type AccountRecord = {
  /** Null until `/state` answers, so the entry form does not flash before then. */
  initialized: boolean | null;
  userId: string | null;
  username: string | null;
  role: AccountRole | null;
  /** Machines the relay says this account owns. Never anyone else's. */
  devices: BoundDevice[];
  /** The version the vault was last read or written at; 0 means none stored yet. */
  vaultVersion: number;
  /** The cost-and-wrapped-key record the stored vault was written under, verbatim. */
  vaultKdf: string | null;
  /**
   * A vault exists on the origin and this phone could not open it.
   *
   * This is not the same as "no key yet", and conflating the two is how a phone
   * destroys an account. A sealed vault must never be written: minting a fresh
   * key and writing at the version just read is a successful compare-and-set
   * that replaces a blob whose plaintext nobody holds any more.
   */
  vaultSealed: boolean;
  /** True while a sign-in, registration or vault sync is in flight. */
  busy: boolean;
  /** Which account surface the page is showing, if any. */
  gate: AccountGate;
  /** The last account failure's protocol code, shown by the form until the next attempt. */
  errorCode: string | null;
  /**
   * Attempts left before the refusal that just happened becomes a lockout, or
   * null when the origin did not say. Only ever as fresh as `errorCode`: the two
   * are written together so the form cannot pair a count with a later failure.
   */
  errorRemaining: number | null;
  /** The person asked for the invite form rather than the sign-in one. */
  wantsRegister: boolean;
  /**
   * How the last vault sync ended, and a counter that advances on every attempt.
   *
   * A boolean could only say "failed", which left a successful sync publishing
   * nothing at all: the person pressed 立即同步 and the screen was byte-identical
   * either way. The outcome names the three answers worth telling apart, and
   * `syncSeq` makes a repeat of the same answer a real change so pressing the
   * button twice is visibly acknowledged both times.
   *
   * `code` carries the protocol code behind a failure, so an expired session or
   * a losing compare-and-set is not reported as the one thing that cannot help.
   */
  syncOutcome: SyncOutcome;
  syncCode: string | null;
  syncSeq: number;
  wrapKey: Uint8Array | null;
  vaultKey: Uint8Array | null;
};

/**
 * The result of a vault sync, as the account page has to render it.
 *
 * `sealed` is deliberately not folded into `failed`: nothing broke, the origin
 * holds a vault this phone has no key for, and the action that resolves it is a
 * passphrase rather than a retry.
 */
export type SyncOutcome = "idle" | "ok" | "sealed" | "failed";

const accountDomain = createDomain<AccountRecord, "wrapKey" | "vaultKey">("account", {
  initialized: null,
  userId: null,
  username: null,
  role: null,
  devices: [],
  vaultVersion: 0,
  vaultKdf: null,
  vaultSealed: false,
  busy: false,
  gate: "off",
  errorCode: null,
  errorRemaining: null,
  wantsRegister: false,
  syncOutcome: "idle",
  syncCode: null,
  syncSeq: 0,
  wrapKey: null,
  vaultKey: null,
}, { opaque: ["wrapKey", "vaultKey"] });

export const accountStore = accountDomain.store;
const { read, write } = accountDomain.controller;

export type SignedInAccount = {
  userId: string;
  username: string;
  role: AccountRole;
};

/** Record the answer to "is there an account here" without claiming anyone is signed in. */
export function setAccountInitialized(initialized: boolean): void {
  if (read().initialized === initialized) return;
  write((record) => {
    record.initialized = initialized;
  });
}

/**
 * Adopt a signed-in identity and the key derived from its passphrase.
 *
 * Only the wrapping key is known at this point: the vault key is inside a record
 * this phone has not fetched yet. The device list is deliberately not carried in
 * either — it comes from the relay on the next read, and seeding it from a
 * previous session would show a phone machines the account may no longer own.
 */
export function setAccountSession(account: SignedInAccount, wrapKey: Uint8Array): void {
  write((record) => {
    record.initialized = true;
    record.userId = account.userId;
    record.username = account.username;
    record.role = account.role;
    record.devices = [];
    record.vaultVersion = 0;
    record.vaultKdf = null;
    record.vaultSealed = false;
    record.wrapKey = wrapKey;
    record.vaultKey = null;
    // Arriving at an identity retires the form's state with it: a refusal the
    // person has now got past must not follow them onto the device list, and a
    // half-finished switch to the invite form is not what the next sign-out
    // should reopen on.
    record.errorCode = null;
    record.errorRemaining = null;
    record.wantsRegister = false;
    record.syncOutcome = "idle";
    record.syncCode = null;
  });
}

/**
 * Drop everything the session owned.
 *
 * `initialized` survives: the deployment still has an account after someone signs
 * out of it, and forgetting that would offer the bootstrap form to the next
 * person who opens the page.
 *
 * Both keys go, which is the point of the ceremony rather than a detail of it.
 * Signing out on a shared phone has to leave the next person unable to open the
 * vault, so the unwrapped vault key is dropped here and only a fresh passphrase
 * can produce another one.
 */
export function clearAccountSession(): void {
  write((record) => {
    record.userId = null;
    record.username = null;
    record.role = null;
    record.devices = [];
    record.vaultVersion = 0;
    record.vaultKdf = null;
    record.vaultSealed = false;
    record.busy = false;
    record.wrapKey = null;
    record.vaultKey = null;
    record.errorCode = null;
    record.errorRemaining = null;
    record.wantsRegister = false;
    record.syncOutcome = "idle";
    record.syncCode = null;
    if (record.gate !== "off") record.gate = "entry";
  });
}

/**
 * Adopt an identity the origin has recognised without any key material.
 *
 * This is the returning browser: the session cookie outlived the page, so the
 * origin knows who this is, but nothing here can open the vault — the wrapping
 * key only ever comes from a passphrase, and no passphrase was typed. The device
 * list is reachable and says the machines are locked, which is the honest state
 * and the one that offers a way out.
 *
 * Keys are cleared rather than left alone. Reaching this for a *different* user
 * than the session previously held must not leave the previous account's vault
 * key in place for the next publish to encrypt under.
 */
export function adoptAccountIdentity(account: SignedInAccount): void {
  write((record) => {
    const changed = record.userId !== account.userId;
    record.initialized = true;
    record.userId = account.userId;
    record.username = account.username;
    record.role = account.role;
    if (changed) {
      record.devices = [];
      record.vaultVersion = 0;
      record.vaultKdf = null;
      record.vaultSealed = false;
      record.wrapKey = null;
      record.vaultKey = null;
    }
  });
}

/** Show an account surface, or hand the page back to the rest of the application. */
export function setAccountGate(gate: AccountGate): void {
  if (read().gate === gate) return;
  write((record) => {
    record.gate = gate;
  });
}

/**
 * The failure the form should be explaining, or null once a new attempt starts.
 *
 * `remaining` defaults to none, so a caller that only knows the code clears a
 * count left by the previous refusal rather than letting it outlive the attempt
 * it described.
 */
export function setAccountError(errorCode: string | null, remaining: number | null = null): void {
  const current = read();
  if (current.errorCode === errorCode && current.errorRemaining === remaining) return;
  write((record) => {
    record.errorCode = errorCode;
    record.errorRemaining = remaining;
  });
}

export function setAccountWantsRegister(wantsRegister: boolean): void {
  if (read().wantsRegister === wantsRegister) return;
  write((record) => {
    record.wantsRegister = wantsRegister;
    // The two forms refuse for different reasons and a stale one would be read
    // as a verdict on the form now showing.
    record.errorCode = null;
    record.errorRemaining = null;
  });
}

/**
 * Publish how a sync ended.
 *
 * There is no early return on an unchanged outcome: two failures in a row are
 * two answers to two presses, and swallowing the second would reproduce the
 * silence this state exists to remove. `syncSeq` is what makes them distinct to
 * a subscriber comparing snapshots.
 */
export function setAccountSyncOutcome(outcome: SyncOutcome, code: string | null = null): void {
  write((record) => {
    record.syncOutcome = outcome;
    record.syncCode = outcome === "failed" ? code : null;
    record.syncSeq += 1;
  });
}

export function accountGate(): AccountGate {
  return read().gate;
}

export function setAccountDevices(devices: BoundDevice[]): void {
  write((record) => {
    record.devices = devices.map((device) => ({ ...device }));
  });
}

/**
 * Record what the origin holds and whether this phone can open it.
 *
 * `sealed` is not a detail of the display. It is the interlock that stops a
 * write: the version alone cannot distinguish "no vault yet, safe to create"
 * from "a vault exists whose key is unavailable", and those two states take
 * opposite actions on the next publish.
 */
export function setAccountVaultState(version: number, kdf: string | null, sealed: boolean): void {
  write((record) => {
    record.vaultVersion = version;
    record.vaultKdf = kdf;
    record.vaultSealed = sealed;
  });
}

/** True when a stored vault exists that this session has not been able to open. */
export function accountVaultSealed(): boolean {
  return read().vaultSealed;
}

export function setAccountBusy(busy: boolean): void {
  if (read().busy === busy) return;
  write((record) => {
    record.busy = busy;
  });
}

/** Remember the unwrapped vault key for the rest of this session. */
export function setAccountVaultKey(vaultKey: Uint8Array | null): void {
  write((record) => {
    record.vaultKey = vaultKey;
    // Holding the key is the definition of no longer being sealed, so the two
    // cannot drift: a later publish reads the flag, not the caller's intent.
    if (vaultKey) record.vaultSealed = false;
  });
}

/** Action-time readers. Keys are returned by identity; they are handles, not data. */
export function accountWrapKey(): Uint8Array | null {
  return read().wrapKey;
}

export function accountVaultKey(): Uint8Array | null {
  return read().vaultKey;
}

export function accountUserId(): string | null {
  return read().userId;
}

export function accountVaultVersion(): number {
  return read().vaultVersion;
}

export function accountVaultKdf(): string | null {
  return read().vaultKdf;
}

export function signedInAccount(): SignedInAccount | null {
  const record = read();
  if (!record.userId || !record.username || !record.role) return null;
  return { userId: record.userId, username: record.username, role: record.role };
}

export function ownedDaemonIds(): string[] {
  return read().devices.map((device) => device.daemonId);
}

/** Reinstate a wrapping key read back from storage, without touching identity. */
export function adoptWrapKey(wrapKey: Uint8Array): void {
  write((record) => {
    record.wrapKey = wrapKey;
  });
}
