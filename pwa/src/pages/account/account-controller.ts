import {
  decodeCredential,
  deleteCredential,
  encodeCredential,
  forgetWrapKey,
  loadCatalog,
  readWrapKey,
  rememberWrapKey,
  saveCredential,
  type StoredCredential,
} from "../../lib/credentials";
import { ProtocolError } from "../../lib/protocol/errors";
import { pickResumeCredential } from "../../lib/computer-catalog";
import { beginAddComputer, resumeComputer } from "../../features/computers/actions";
import { setComputers, setCredential } from "../../features/computers/catalog-store";
import { clearLiveConnection, closeComputerSession, reloadComputers } from "../../features/connection/controller";
import { phase as currentPhase } from "../../features/connection/connection-store";
import { deleteSessionSnapshot } from "../../features/connection/snapshot-storage";
import {
  accountVaultSealed,
  accountWrapKey,
  adoptWrapKey,
  ownedDaemonIds,
  setAccountError,
  setAccountGate,
  setAccountSyncFailed,
  setAccountWantsRegister,
  signedInAccount,
} from "../../features/account/account-store";
import {
  bindDevice,
  awaitClaimProof,
  publishCredentials,
  refreshAccountState,
  signOutAccount,
  submitAccount,
  syncAccountDevices,
} from "../../features/account/actions";
import type { AccountSubmission } from "../../features/account/model";
import { commitView } from "../../app/host";

/**
 * The account page's adapter onto the rest of the application.
 *
 * This lives under `pages/` rather than beside the feature on purpose. The
 * account feature is a closed layer: its actions speak to the origin and to
 * their own domain and reach nothing else, which is what lets them be tested
 * without a running application and audited as self-contained. Everything that
 * has to cross that line — the credential database, the computer catalogue, the
 * commit pipeline — is assembled here, on the page side of the boundary, where
 * reaching into `features/`, `app/` and `lib/` is what a page is for.
 *
 * The passphrase is an argument on this seam and never a field. It is needed
 * twice in one flow (once to authenticate, once to open a vault written under a
 * cost this session did not derive at) and then goes out of scope; parking it in
 * the domain to save a parameter would leave a replayable password in a snapshot
 * that survives the form.
 */

/**
 * Decide, during boot, whether this browser has to answer for itself.
 *
 * Unlike `openAccountGate` this does not raise the gate before asking. Boot runs
 * on every load including deployments whose origin has no account plane at all,
 * and showing a sign-in form that can never be satisfied would lock those
 * installations out of their own machines. So the gate goes up only once the
 * origin has actually answered; an unreachable or absent account route leaves
 * the application composing exactly as it did before.
 *
 * This is an availability decision, not a security one. Nothing here grants
 * access: the relay checks ownership on every device, vault and session call,
 * and a browser that skips the gate still cannot read an account's vault.
 */
export async function resumeAccountAtBoot(): Promise<void> {
  try {
    await refreshAccountState();
  } catch {
    return;
  }
  const account = signedInAccount();
  if (account) {
    // The wrapping key outlives the page so this reload can open the vault
    // without the passphrase. Restoring it before the sync is what makes the
    // machines synced from another device usable here rather than merely named.
    try {
      const wrapKey = await readWrapKey();
      if (wrapKey) adoptWrapKey(wrapKey);
    } catch {
      // A key that cannot be read is a sealed vault, which syncAccountVault
      // already reports; it is not a reason to abandon the sync.
    }
    await syncAccountVault(null);
  } else {
    setAccountGate("entry");
    commitView();
  }
}

/** Ask the origin who this phone is, then show the surface that answer implies. */
export async function openAccountGate(): Promise<void> {
  setAccountGate("entry");
  commitView();
  try {
    await refreshAccountState();
  } catch (error) {
    setAccountError(codeOf(error));
    commitView();
    return;
  }
  const account = signedInAccount();
  if (!account) setAccountGate("entry");
  commitView();
  // A cookie that outlived the page is a real session, so a returning phone goes
  // straight back to its machines; the sync decides which one and puts the
  // account surface away.
  if (account) await syncAccountVault(null);
}

/**
 * Authenticate, then pull down what the account owns.
 *
 * The two halves are reported differently on purpose. A refused password is the
 * person's to fix and keeps them on the form; a sync that fails afterwards is
 * not, and dropping them back to the form would throw away a session the origin
 * has already granted.
 */
export async function submitAccountEntry(submission: AccountSubmission): Promise<boolean> {
  setAccountError(null);
  commitView();
  try {
    await submitAccount(submission);
  } catch (error) {
    setAccountError(codeOf(error));
    commitView();
    return false;
  }
  // Keep the wrapping key this sign-in derived, so the next reload opens the
  // vault without asking for the passphrase again.
  const wrapKey = accountWrapKey();
  if (wrapKey) {
    try {
      await rememberWrapKey(wrapKey);
    } catch {
      // A key that cannot be stored only costs this phone a passphrase prompt
      // on its next reload; the session it just established still stands.
    }
  }
  commitView();
  await syncAccountVault(submission.password);
  return true;
}

/**
 * Reconcile this phone's credentials with the account's vault, in both
 * directions.
 *
 * This is what makes a second phone useful: it merges what the vault holds into
 * the local database, and publishes anything local the vault has not seen. The
 * publish is not skipped when the vault already exists — a phone that paired a
 * machine while signed out is exactly the case worth carrying up.
 *
 * A failure here leaves the local database untouched and says so on the list.
 * Half-writing a merge would be worse than not syncing.
 *
 * A sealed vault is not a failure and is not published to. The machines are
 * listed, what this phone already had still works, and the account waits for a
 * passphrase rather than having its stored credentials replaced.
 */
export async function syncAccountVault(password: string | null): Promise<void> {
  if (!signedInAccount()) return;
  setAccountSyncFailed(false);
  try {
    const local = await localCredentials();
    const merged = await syncAccountDevices(password, local);
    await adoptCredentials(merged, local);
    // The merge is published rather than compared first: this layer cannot see
    // what the vault held before `syncAccountDevices` opened it, and a phone
    // that paired a machine while signed out is exactly the case worth carrying
    // up. The write is a compare-and-set, so an unchanged list costs one round
    // trip and cannot clobber a concurrent edit.
    if (merged.length && !accountVaultSealed()) await publishCredentials(merged);
  } catch {
    setAccountSyncFailed(true);
  }
  const catalog = await loadCatalog(location.origin);
  // A signed-in phone goes straight back to the machine it used last. With no
  // credential to resume there is nothing to list, so it lands on pairing
  // rather than on a page whose only content would be a button to leave it.
  setAccountGate("off");
  const pick = pickResumeCredential(catalog.credentials, catalog.lastUsedDaemonId);
  if (pick) {
    if (currentPhase() !== "live" && currentPhase() !== "resuming") void resumeComputer(pick);
  } else {
    beginAddComputer();
  }
  commitView();
}

/**
 * This phone's credentials in vault form.
 *
 * `encodeCredential` is the same encoder the database writes through, so what
 * goes into the vault is byte-identical to what came out of it — including the
 * two keys, which is the whole point: a record stripped of its PSK would sync a
 * machine the other phone could see and not use.
 */
async function localCredentials(): Promise<StoredCredential[]> {
  const catalog = await loadCatalog(location.origin);
  return catalog.credentials.map(encodeCredential);
}

/**
 * Write the merged list into the credential database and republish the catalogue.
 *
 * Only genuinely new records are written: a phone that already holds a machine
 * does not need its row rewritten on every sign-in, and a redundant write would
 * churn IndexedDB on the slowest device in the fleet.
 */
async function adoptCredentials(
  merged: readonly StoredCredential[],
  _local: readonly StoredCredential[],
): Promise<void> {
  const catalog = await loadCatalog(location.origin);
  const inDb = new Set(catalog.credentials.map((item) => item.daemonId));
  let adopted = 0;
  for (const stored of merged) {
    if (inDb.has(stored.daemon_id)) continue;
    try {
      await saveCredential(decodeCredential(stored));
      adopted += 1;
    } catch {
      // A record this build cannot decode is skipped rather than aborting the
      // rest of the merge: one unreadable row must not cost the account every
      // other machine it owns.
    }
  }
  if (adopted) await reloadComputers();
}
/**
 * Bind a machine this phone has just paired with to the signed-in account.
 *
 * The proof only exists once the relay has watched the daemon accept, so this
 * waits for it rather than assuming a resolved pairing code is enough. A phone
 * that is not signed in simply keeps the machine locally — pairing has never
 * required an account and must not start to.
 *
 * The bind stands even when the vault cannot be written. Ownership lives on the
 * relay, so a sealed vault costs this machine its place in the encrypted list —
 * reported as a sync failure — and not the binding itself.
 */
export async function claimPairedDevice(daemonId: string, label: string | null): Promise<boolean> {
  if (!signedInAccount()) return false;
  let bound = false;
  try {
    const proof = await awaitClaimProof(daemonId);
    if (!proof) return false;
    await bindDevice(daemonId, proof, label);
    bound = true;
    if (!accountVaultSealed()) await publishCredentials(await localCredentials());
    commitView();
    return true;
  } catch {
    setAccountSyncFailed(true);
    commitView();
    return bound;
  }
}

/**
 * Leave the account on this phone.
 *
 * Signing out drops the keys, and then drops the machines those keys were the
 * only way to use. Leaving the credential rows behind would hand the next person
 * on a shared phone a working connection to computers they do not own, which is
 * the exact thing binding devices to an account is for. Machines paired outside
 * any account are not the account's to remove and stay.
 */
export async function signOutOfAccount(): Promise<boolean> {
  const owned = new Set(ownedDaemonIds());
  try {
    await signOutAccount();
  } catch (error) {
    setAccountError(codeOf(error));
    commitView();
    return false;
  }

  // Retire both the active transport and the account's parked pool entries.
  // These lifecycle APIs close relay/P2P and invalidate pending session reads.
  clearLiveConnection();
  // The stored key goes with the session it belonged to: leaving it behind would
  // let the next person on this phone reopen the vault of an account they have
  // just been signed out of. It is dropped with the rest of the local state, so
  // a refused sign-out keeps it exactly as it keeps the credentials.
  await forgetWrapKey();
  for (const daemonId of owned) closeComputerSession(daemonId);
  setCredential(null);
  setComputers([]);
  const cleanup = await Promise.allSettled([...owned].flatMap((daemonId) => [
    deleteCredential(daemonId),
    deleteSessionSnapshot(daemonId),
  ]));
  const failure = cleanup.find((result): result is PromiseRejectedResult => result.status === "rejected");
  // Do not reload rows that failed deletion into the signed-out catalogue.
  if (failure) {
    setAccountError(codeOf(failure.reason));
    setAccountGate("entry");
    commitView();
    return false;
  }
  try {
    await reloadComputers();
  } catch (error) {
    setAccountError(codeOf(error));
    setAccountGate("entry");
    commitView();
    return false;
  }
  setAccountError(null);
  setAccountGate("entry");
  commitView();
  return true;
}

/** Sign out and land on the sign-in form, ready for someone else's credentials. */
export async function switchAccount(): Promise<boolean> {
  const signedOut = await signOutOfAccount();
  if (!signedOut) return false;
  setAccountWantsRegister(false);
  setAccountError(null);
  commitView();
  return true;
}

/** Hand the page back to the rest of the application. */
export function leaveAccountGate(): void {
  setAccountGate("off");
  commitView();
}

export function chooseRegisterForm(wantsRegister: boolean): void {
  setAccountWantsRegister(wantsRegister);
  commitView();
}

function codeOf(error: unknown): string {
  return error instanceof ProtocolError ? error.code : "unknown";
}
