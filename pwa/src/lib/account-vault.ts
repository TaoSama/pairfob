import {
  deriveAccountKeys,
  newVaultKey,
  openVault,
  sealVault,
  unwrapVaultKey,
  VAULT_KDF,
  VAULT_KDF_PARAMS,
  wrapVaultKey,
  type SealedBytes,
  type VaultContent,
  type VaultKdfParams,
  type WrappedVault,
} from "./vault-crypto.ts";
import { validateStoredCredential, type StoredCredential } from "./credentials.ts";

/**
 * The vault's `kdf` column, encoded.
 *
 * The column carries the cost parameters and the wrapped vault key, because a
 * phone must know both before it can open anything and the relay will not
 * interpret either. A vault written under an older cost keeps opening: the
 * record states how it was made rather than assuming today's default.
 *
 * The relay bounds this column at 128 characters, which is why the encoding is
 * a delimited string rather than JSON — the wrapped key and its nonce are 96
 * base64 characters between them, and JSON punctuation would not fit around
 * them. A test pins the encoded length against that ceiling.
 */
export type KdfDescriptor = {
  name: string;
  params: VaultKdfParams;
  /** The vault key, sealed under the passphrase-derived wrapping key. */
  wrapped: string;
  wrapNonce: string;
};

const FIELD_SEP = ".";
const FIELDS = 6;

export function encodeKdf(descriptor: KdfDescriptor): string {
  const { parallelism, iterations, memorySize } = descriptor.params;
  return [
    descriptor.name,
    iterations,
    memorySize,
    parallelism,
    descriptor.wrapped,
    descriptor.wrapNonce,
  ].join(FIELD_SEP);
}

export function decodeKdf(value: string): KdfDescriptor {
  const parts = value.split(FIELD_SEP);
  if (parts.length !== FIELDS) throw new Error("kdf shape");
  const [name, t, m, p, wrapped, wrapNonce] = parts;
  if (!name || !wrapped || !wrapNonce) throw new Error("kdf shape");
  const iterations = count(t);
  const memorySize = count(m);
  const parallelism = count(p);
  if (iterations === null || memorySize === null || parallelism === null) {
    throw new Error("kdf params");
  }
  return { name, params: { parallelism, iterations, memorySize }, wrapped, wrapNonce };
}

/** Strict: a value like "3x" or "" must not silently become a cost of 3 or NaN. */
function count(value: string): number | null {
  if (!/^[0-9]+$/.test(value)) return null;
  const parsed = Number(value);
  return Number.isSafeInteger(parsed) && parsed > 0 ? parsed : null;
}

/** A descriptor for a brand-new vault: today's cost, a fresh random key. */
export function newKdfDescriptor(wrapKey: Uint8Array, username: string): {
  descriptor: KdfDescriptor;
  vaultKey: Uint8Array;
} {
  const vaultKey = newVaultKey();
  const record = wrapVaultKey(wrapKey, vaultKey, username);
  return { descriptor: { name: VAULT_KDF, ...toDescriptor(record) }, vaultKey };
}

function toDescriptor(record: WrappedVault): Omit<KdfDescriptor, "name"> {
  return { params: record.params, wrapped: record.wrapped, wrapNonce: record.wrapNonce };
}

/** Rewrap an existing vault key under a new passphrase; the ciphertext is untouched. */
export function rewrapDescriptor(
  wrapKey: Uint8Array,
  vaultKey: Uint8Array,
  username: string,
): KdfDescriptor {
  return { name: VAULT_KDF, ...toDescriptor(wrapVaultKey(wrapKey, vaultKey, username)) };
}

export function currentKdfParams(): VaultKdfParams {
  return { ...VAULT_KDF_PARAMS };
}

/**
 * Everything a signed-in phone needs to read and rewrite its own vault.
 *
 * The passphrase is not among them. It is consumed once at sign-in to produce
 * these two values and then goes out of scope, so a later write does not need to
 * ask for it again and nothing holds it for the lifetime of the session.
 *
 * `wrapKey` opens the vault key; it is not itself the key the blob is encrypted
 * under. Keeping the distinction means a passphrase change rewraps one small
 * record instead of re-encrypting every credential.
 */
export type AccountSession = {
  userId: string;
  username: string;
  /** Sent to the origin in place of the passphrase. */
  authSecret: string;
  wrapKey: Uint8Array;
};

export async function deriveSession(
  username: string,
  password: string,
  host: string,
  params: VaultKdfParams = VAULT_KDF_PARAMS,
): Promise<Omit<AccountSession, "userId">> {
  const keys = await deriveAccountKeys(username, password, host, params);
  return { username, authSecret: keys.authSecret, wrapKey: keys.wrapKey };
}

/**
 * Recover the key a second phone needs to decrypt an existing vault.
 *
 * The derivation is repeated under the parameters the record carries rather than
 * today's defaults, which is what lets a phone open a vault written before a
 * cost change. A wrong passphrase fails the unwrap's AEAD tag, so it is reported
 * here rather than as a corrupt vault further down.
 */
export async function recoverVaultKey(
  username: string,
  password: string,
  host: string,
  descriptor: KdfDescriptor,
): Promise<Uint8Array> {
  const keys = await deriveAccountKeys(username, password, host, descriptor.params);
  return unwrapVaultKey(keys.wrapKey, descriptor, username);
}

/** Unwrap with a key already derived this session, skipping a second Argon2id pass. */
export function openVaultKey(
  wrapKey: Uint8Array,
  descriptor: KdfDescriptor,
  username: string,
): Uint8Array {
  return unwrapVaultKey(wrapKey, descriptor, username);
}

export type VaultSnapshot = {
  credentials: StoredCredential[];
  version: number;
};

export const EMPTY_VAULT: VaultSnapshot = { credentials: [], version: 0 };

/**
 * Decrypt a stored vault into credentials this build is willing to use.
 *
 * Each record is revalidated after decryption. Authenticity is already settled
 * by the AEAD, so this is not a trust check — it is a compatibility one: a
 * credential written by a newer build, or one whose fingerprint no longer
 * matches its key, would fail at connect time anyway, and dropping it here means
 * the device list never offers a machine the phone cannot actually reach.
 */
export function decryptVault(
  vaultKey: Uint8Array,
  sealed: SealedBytes,
  userId: string,
  version: number,
): VaultSnapshot {
  const content = openVault(vaultKey, sealed, userId, version);
  const credentials: StoredCredential[] = [];
  for (const entry of content.credentials) {
    const valid = validateStoredCredential(entry);
    if (valid) credentials.push(valid);
  }
  return { credentials, version };
}

export function encryptVault(
  vaultKey: Uint8Array,
  credentials: StoredCredential[],
  userId: string,
  version: number,
): SealedBytes {
  const content: VaultContent = { v: 1, credentials };
  return sealVault(vaultKey, content, userId, version);
}

/**
 * Merge what this phone holds with what the vault holds.
 *
 * Keyed by daemon id, newest `created_at` wins. Two phones that pair the same
 * machine produce two credentials for one daemon, and the daemon only honours
 * the most recent enrolment, so preferring the newer record is what keeps the
 * merged list usable rather than merely complete.
 */
export function mergeCredentials(
  local: StoredCredential[],
  remote: StoredCredential[],
): StoredCredential[] {
  const byDaemon = new Map<string, StoredCredential>();
  for (const credential of [...remote, ...local]) {
    const existing = byDaemon.get(credential.daemon_id);
    if (!existing || credential.created_at > existing.created_at) {
      byDaemon.set(credential.daemon_id, credential);
    }
  }
  return [...byDaemon.values()].sort((a, b) => b.created_at - a.created_at);
}

/** The relay knows which daemons an account owns; the vault is what makes them usable. */
export function scopeToOwnedDevices(
  credentials: StoredCredential[],
  ownedDaemonIds: readonly string[],
): StoredCredential[] {
  const owned = new Set(ownedDaemonIds);
  return credentials.filter((credential) => owned.has(credential.daemon_id));
}
