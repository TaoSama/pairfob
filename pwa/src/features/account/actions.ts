import {
  bootstrapAccount,
  claimDevice,
  listBoundDevices,
  loginAccount,
  logoutAccount,
  readAccountState,
  readClaimProof,
  readVault,
  registerAccount,
  VaultConflictError,
  writeVault,
  type AccountUser,
  type BoundDevice,
} from "../../lib/account-api";
import {
  currentKdfParams,
  decodeKdf,
  decryptVault,
  deriveSession,
  encodeKdf,
  encryptVault,
  mergeCredentials,
  newKdfDescriptor,
  openVaultKey,
  recoverVaultKey,
  scopeToOwnedDevices,
  type KdfDescriptor,
} from "../../lib/account-vault";
import type { StoredCredential } from "../../lib/credentials";
import {
  accountVaultKdf,
  accountVaultKey,
  accountVaultSealed,
  accountVaultVersion,
  accountWrapKey,
  adoptAccountIdentity,
  clearAccountSession,
  setAccountBusy,
  setAccountDevices,
  setAccountInitialized,
  setAccountSession,
  setAccountVaultKey,
  setAccountVaultState,
  signedInAccount,
} from "./account-store";
import type { AccountSubmission } from "./model";

/**
 * The account control plane, wired to the domain.
 *
 * Two secrets come out of one passphrase here and go to two different places:
 * the authenticator travels to the origin as the account password, the wrapping
 * key stays in this module's caller and never crosses the network. Every call
 * below preserves that split — the origin is asked to authenticate, never to
 * decrypt.
 *
 * The credentials are not encrypted under the passphrase-derived key. They are
 * encrypted under a random vault key that the KDF record carries in wrapped
 * form, so changing a passphrase rewraps one small record instead of rewriting
 * every credential.
 *
 * The number of round trips matters on a phone: `deriveSession` runs Argon2id,
 * which is the slowest thing on this path by an order of magnitude, so it runs
 * exactly once per sign-in and its output is handed to the store rather than
 * recomputed for the vault.
 */

/** The salt is per-account and per-site, so the host is part of the derivation. */
function currentHost(): string {
  return typeof location === "undefined" ? "" : location.host;
}

/**
 * How long to wait for the daemon to accept. The exchange is a person walking to
 * a computer and confirming, so the window is generous and the interval is slow
 * enough not to hold a phone's radio open.
 */
const CLAIM_POLL_INTERVAL_MS = 1_000;
const CLAIM_POLL_ATTEMPTS = 120;

/**
 * A vault written under an unknown cost record cannot be opened by guessing, so
 * a phone that cannot parse the record treats the vault as sealed. It does not
 * start a fresh one: the stored row is still there, and replacing it would
 * discard credentials on the strength of a string this build failed to read.
 */
function descriptorFor(kdf: string | null) {
  if (!kdf) return null;
  try {
    return decodeKdf(kdf);
  } catch {
    return null;
  }
}

/**
 * Ask the origin who this browser is.
 *
 * A cookie that outlived the page is a real session and is adopted as one, which
 * is what lets a returning phone reach its device list without signing in again.
 * It brings no key material with it: the vault stays shut until a passphrase
 * produces the wrapping key, and the list says so rather than looking empty.
 */
export async function refreshAccountState(): Promise<void> {
  const state = await readAccountState();
  setAccountInitialized(state.initialized);
  if (!state.user) {
    clearAccountSession();
    return;
  }
  adoptAccountIdentity({
    userId: state.user.userId,
    username: state.user.username,
    role: state.user.role,
  });
}

/**
 * Sign in, register or open the first account, then recover the vault.
 *
 * The passphrase is taken as an argument and never stored: the two values
 * derived from it are all the rest of the session needs.
 */
export async function submitAccount(submission: AccountSubmission): Promise<AccountUser> {
  setAccountBusy(true);
  try {
    const host = currentHost();
    const username = submission.kind === "bootstrap" ? "admin" : submission.username;
    const session = await deriveSession(username, submission.password, host);
    const user = await authenticate(submission, session.authSecret);
    setAccountSession({ userId: user.userId, username: user.username, role: user.role }, session.wrapKey);
    return user;
  } finally {
    setAccountBusy(false);
  }
}

function authenticate(submission: AccountSubmission, authSecret: string): Promise<AccountUser> {
  switch (submission.kind) {
    case "bootstrap":
      return bootstrapAccount(submission.serviceToken, authSecret);
    case "login":
      return loginAccount(submission.username, authSecret);
    case "register":
      return registerAccount(submission.username, authSecret, submission.inviteCode);
  }
}

export async function signOutAccount(): Promise<void> {
  await logoutAccount();
  clearAccountSession();
}

/**
 * Pull the account's machines and the credentials that make them usable.
 *
 * A second phone reaches this with nothing but what its owner typed, which is
 * what turns "log in" into "the computers are already there". The stored record
 * is honoured rather than today's default, so a vault written before a cost
 * change still opens: its wrapped key is unwrapped under the cost it names.
 *
 * A vault that exists and does not open is recorded as sealed, and that flag is
 * the whole point of this function's error handling. Unreadable is not empty:
 * the local list is still returned so the phone stays usable, but the account
 * is now barred from writing until a passphrase produces the real key.
 */
export async function syncAccountDevices(
  password: string | null,
  local: readonly StoredCredential[] = [],
): Promise<StoredCredential[]> {
  const account = signedInAccount();
  if (!account) return [];
  const devices: BoundDevice[] = await listBoundDevices();
  setAccountDevices(devices);
  const owned = devices.map((device) => device.daemonId);
  const mine = () => scopeToOwnedDevices([...local], owned);

  const stored = await readVault();
  if (!stored) {
    // A 404 is the origin stating there is no row, which is the one case where
    // creating one is safe. Everything below this line has seen a real vault.
    setAccountVaultState(0, null, false);
    return mine();
  }

  const key = await vaultKeyFor(stored.kdf, account.username, password);
  if (!key) {
    // Unknown cost record, no wrapping key, or a passphrase that fails the
    // unwrap tag. The version and kdf are recorded so a later write compares
    // against reality, and sealed bars that write from happening at all.
    setAccountVaultState(stored.version, stored.kdf, true);
    return mine();
  }

  let snapshot;
  try {
    snapshot = decryptVault(key, stored, account.userId, stored.version);
  } catch {
    // The key unwrapped but the blob did not open: truncated ciphertext, a
    // version the AAD does not agree with, or a record this build cannot read.
    // Re-keying over it would turn a recoverable read failure into permanent
    // data loss, so the vault stays sealed and the key is not adopted.
    setAccountVaultState(stored.version, stored.kdf, true);
    return mine();
  }

  setAccountVaultState(stored.version, stored.kdf, false);
  setAccountVaultKey(key);
  const merged = mergeCredentials([...local], snapshot.credentials);
  return scopeToOwnedDevices(merged, owned);
}

/**
 * Unwrap the stored vault key.
 *
 * The wrapping key already in the domain works whenever the record names the
 * cost this session derived at. A record written under a different cost needs a
 * second Argon2id run, and therefore the passphrase the caller still holds; with
 * neither available the vault stays closed rather than being opened with a
 * guessed key.
 */
async function vaultKeyFor(
  kdf: string,
  username: string,
  password: string | null,
): Promise<Uint8Array | null> {
  const descriptor = descriptorFor(kdf);
  if (!descriptor) return null;
  const cached = accountVaultKey();
  if (cached) return cached;
  if (sameCost(descriptor)) {
    const wrapKey = accountWrapKey();
    // A wrong passphrase fails the unwrap tag rather than yielding a bad key.
    if (wrapKey) return tryUnwrap(wrapKey, descriptor, username);
  }
  if (!password) return null;
  try {
    return await recoverVaultKey(username, password, currentHost(), descriptor);
  } catch {
    return null;
  }
}

function sameCost(descriptor: KdfDescriptor): boolean {
  const current = currentKdfParams();
  return descriptor.params.parallelism === current.parallelism
    && descriptor.params.iterations === current.iterations
    && descriptor.params.memorySize === current.memorySize;
}

function tryUnwrap(wrapKey: Uint8Array, descriptor: KdfDescriptor, username: string): Uint8Array | null {
  try {
    return openVaultKey(wrapKey, descriptor, username);
  } catch {
    return null;
  }
}

/**
 * Refuses a write that would destroy a vault this phone cannot read.
 *
 * Distinct from a protocol failure because nothing was sent: the origin is
 * intact, the stored ciphertext is untouched, and the way out is a passphrase,
 * not a retry.
 */
export class VaultSealedError extends Error {
  readonly code = "vault_sealed";
  constructor() {
    super("vault_sealed");
    this.name = "VaultSealedError";
  }
}

/**
 * Publish the account's credential list, resolving a concurrent edit rather than
 * overwriting it.
 *
 * The first write on a fresh account mints the random vault key and wraps it
 * into the record; every later write reuses the key already unwrapped, so the
 * wrapped record stays stable and a phone that merges a conflict does not
 * re-key the vault underneath the other writer.
 *
 * Minting is allowed in exactly one situation: the origin answered that no vault
 * row exists. Any other missing key means a stored blob is unreadable here, and
 * a fresh key written at the version just read is a compare-and-set that
 * succeeds and permanently destroys credentials — so that case raises
 * `VaultSealedError` without sending anything.
 *
 * Two phones bound to one account can each add a machine between reads. A blind
 * retry would drop whichever write lost the race, so a conflict re-reads at the
 * version the origin reports, merges, and writes once more. One retry is enough:
 * a second conflict means something is writing continuously, and looping would
 * spend the phone's battery rather than converge.
 */
export async function publishCredentials(credentials: readonly StoredCredential[]): Promise<number> {
  const account = signedInAccount();
  if (!account) return 0;
  if (accountVaultSealed()) throw new VaultSealedError();

  const existing = accountVaultKey();
  const storedKdf = accountVaultKdf();
  let key = existing;
  let kdf = storedKdf;
  // A key held without the record that wraps it, or a record whose key this
  // session never unwrapped, are both unreadable states rather than empty ones.
  // Only "no vault at all" may mint, and only the origin can say that.
  const fresh = !key || !kdf;
  if (fresh) {
    if (existing || storedKdf || accountVaultVersion() !== 0) throw new VaultSealedError();
    const wrapKey = accountWrapKey();
    if (!wrapKey) return 0;
    const minted = newKdfDescriptor(wrapKey, account.username);
    key = minted.vaultKey;
    kdf = encodeKdf(minted.descriptor);
  }
  const vaultKey = key as Uint8Array;
  const record = kdf as string;

  // A minted key is adopted only once the origin has accepted the record that
  // wraps it. Publishing it to the domain first would leave a phone that lost
  // the race holding a key matching nothing stored, and the next publish would
  // write it over the winner's vault.
  const attempt = async (version: number, contents: readonly StoredCredential[]): Promise<number> => {
    const sealed = encryptVault(vaultKey, [...contents], account.userId, version + 1);
    const saved = await writeVault({ ...sealed, kdf: record, version });
    setAccountVaultKey(vaultKey);
    setAccountVaultState(saved, record, false);
    return saved;
  };

  try {
    return await attempt(accountVaultVersion(), credentials);
  } catch (error) {
    if (!(error instanceof VaultConflictError)) throw error;
    const stored = await readVault();
    if (!stored) return attempt(0, credentials);

    // The winner's record decides the key. This phone may have just minted one
    // for what it believed was an empty account; adopting it here instead would
    // re-key the vault under the other writer and make their blob unreadable.
    // If their record cannot be opened, this phone is sealed out of the vault —
    // recorded as such so the next publish refuses before reaching the origin.
    const descriptor = descriptorFor(stored.kdf);
    const wrapKey = accountWrapKey();
    const theirKey = descriptor && wrapKey ? tryUnwrap(wrapKey, descriptor, account.username) : null;
    if (!theirKey) {
      setAccountVaultState(stored.version, stored.kdf, true);
      throw new VaultSealedError();
    }

    let theirs;
    try {
      theirs = decryptVault(theirKey, stored, account.userId, stored.version);
    } catch {
      setAccountVaultState(stored.version, stored.kdf, true);
      throw new VaultSealedError();
    }
    setAccountVaultKey(theirKey);

    const merged = mergeCredentials([...credentials], theirs.credentials);
    const sealed = encryptVault(theirKey, merged, account.userId, stored.version + 1);
    const saved = await writeVault({ ...sealed, kdf: stored.kdf, version: stored.version });
    setAccountVaultState(saved, stored.kdf, false);
    return saved;
  }
}

/**
 * Wait for the relay to confirm the daemon accepted this pairing, then bind.
 *
 * The proof does not exist when a pairing code resolves — it is minted only once
 * the relay observes the daemon accepting this session. Polling is therefore the
 * protocol, not a workaround: `ready: false` is the expected answer for most of a
 * pairing and must not be treated as a failure.
 *
 * The proof is single-use and this never retries a refusal. A rejected claim
 * means the pairing has to be redone, and re-sending a spent proof would turn a
 * recoverable "pair again" into a loop of 403s.
 */
export async function awaitClaimProof(
  daemonId: string,
  options: { attempts?: number; wait?: (ms: number) => Promise<void>; signal?: AbortSignal } = {},
): Promise<string | null> {
  const attempts = options.attempts ?? CLAIM_POLL_ATTEMPTS;
  const wait = options.wait ?? ((ms: number) => new Promise<void>((resolve) => setTimeout(resolve, ms)));
  for (let attempt = 0; attempt < attempts; attempt += 1) {
    if (options.signal?.aborted) return null;
    const proof = await readClaimProof(daemonId, fetch, options.signal);
    if (proof.ready) return proof.proof;
    if (attempt + 1 < attempts) await wait(CLAIM_POLL_INTERVAL_MS);
  }
  return null;
}

/**
 * Record ownership of a machine this phone has actually paired with.
 *
 * The device list is refreshed from the relay afterwards rather than appended to
 * locally: the relay is the authority on ownership, and a local append would show
 * a bind the origin may have refused.
 */
export async function bindDevice(
  daemonId: string,
  claimProof: string,
  label: string | null,
): Promise<BoundDevice[]> {
  await claimDevice(daemonId, claimProof, label);
  const devices = await listBoundDevices();
  setAccountDevices(devices);
  return devices;
}
