import { xchacha20poly1305 } from "@noble/ciphers/chacha.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { argon2id } from "hash-wasm";
import { base64Decode, base64Encode, bytesToHex, concat, lenPref, u64be } from "./protocol/bytes.ts";
import { pairfobHKDF } from "./protocol/kdf.ts";
import type { StoredCredential } from "./credentials.ts";

/**
 * Account key material for a vault the server stores but cannot read.
 *
 * The passphrase is stretched once and then split into two values that are
 * useless to each other: `authSecret` travels to the origin as the account
 * password, `vaultKey` never leaves the browser. A full compromise of the origin
 * therefore yields the stretched authenticator and a pile of ciphertext, and
 * still cannot read a device credential.
 *
 * The salt is a deterministic function of the username and the host, so a
 * second phone can derive the same keys with nothing but what its owner typed —
 * no extra round trip, and no lookup that would tell a stranger whether an
 * account exists. It is a salt, not a secret: its job is to keep one rainbow
 * table from covering two sites or two accounts.
 *
 * The vault key is random and stored wrapped under `wrapKey`, not derived from
 * the passphrase. Deriving it would tie the blob to the passphrase forever: a
 * password change would have to re-encrypt every record, and two vault versions
 * encrypted under two passphrases could not coexist during that rewrite. With a
 * wrapped key a password change rewraps 48 bytes and leaves the ciphertext
 * untouched. The wrapped key rides in the relay's opaque KDF field, which is
 * bounded at 128 characters — the encoding below is sized to fit inside it.
 */

const SALT_INFO = "pairfob-v1/account-salt";
const AUTH_INFO = "pairfob-v1/account-auth";
const WRAP_INFO = "pairfob-v1/account-wrap";
const CONTENT_INFO = "pairfob-v1/vault-content";
const BLOB_AAD = "pairfob-v1/vault-blob";
const WRAP_AAD = "pairfob-v1/vault-key";

const SALT_BYTES = 16;
const KEY_BYTES = 32;
const NONCE_BYTES = 24;
const MASTER_BYTES = 32;

/** Named so a future cost increase is a new identifier, not a silent rehash. */
export const VAULT_KDF = "argon2id-v1";

/**
 * Matches the pairing record's cost. A phone can afford this once per sign-in,
 * and it is the only thing standing between a stolen vault and a weak passphrase.
 */
export const VAULT_KDF_PARAMS = { parallelism: 1, iterations: 3, memorySize: 65536 } as const;

export type VaultKdfParams = {
  parallelism: number;
  iterations: number;
  memorySize: number;
};

export type AccountKeys = {
  /** Sent to the origin as the account password. Hex, so it survives any transport. */
  authSecret: string;
  /** Wraps the random vault key. Never transmitted, never persisted. */
  wrapKey: Uint8Array;
};

export type SealedBytes = {
  ciphertext: string;
  nonce: string;
};

export type VaultContent = {
  v: 1;
  credentials: StoredCredential[];
};

function utf8(value: string): Uint8Array {
  return new TextEncoder().encode(value);
}

function randomBytes(length: number): Uint8Array {
  const bytes = new Uint8Array(length);
  crypto.getRandomValues(bytes);
  return bytes;
}

/**
 * Deterministic per account and per site.
 *
 * Length-prefixed so a username ending in the host's first characters cannot
 * collide with a different pair that concatenates to the same string.
 */
export function accountSalt(username: string, host: string): Uint8Array {
  const digest = sha256(concat(utf8(SALT_INFO), lenPref(utf8(username)), lenPref(utf8(host))));
  return new Uint8Array(digest.subarray(0, SALT_BYTES));
}

/**
 * Stretch the passphrase, then split it.
 *
 * HKDF with distinct info strings gives two independent keys from one Argon2id
 * output: learning the authenticator the origin stores reveals nothing about the
 * wrapping key, because neither is derivable from the other without the master.
 */
export async function deriveAccountKeys(
  username: string,
  password: string,
  host: string,
  params: VaultKdfParams = VAULT_KDF_PARAMS,
): Promise<AccountKeys> {
  const master = await argon2id({
    password,
    salt: accountSalt(username, host),
    parallelism: params.parallelism,
    iterations: params.iterations,
    memorySize: params.memorySize,
    hashLength: MASTER_BYTES,
    outputType: "binary",
  });
  return {
    authSecret: bytesToHex(pairfobHKDF(master, null, utf8(AUTH_INFO), KEY_BYTES)),
    wrapKey: pairfobHKDF(master, null, utf8(WRAP_INFO), KEY_BYTES),
  };
}

/** A fresh vault key. Random, so it outlives any one passphrase. */
export function newVaultKey(): Uint8Array {
  return randomBytes(KEY_BYTES);
}

/**
 * The wrapped vault key, as it rides in the relay's opaque KDF field.
 *
 * The cost parameters travel with it because a phone must know how hard to
 * stretch the passphrase *before* it can unwrap anything, and the relay will
 * not interpret this field for us. Raising the cost later therefore does not
 * strand an existing vault: the record states the cost it was written at.
 */
export type WrappedVault = {
  params: VaultKdfParams;
  wrapped: string;
  wrapNonce: string;
};

function wrapAad(username: string): Uint8Array {
  return concat(utf8(WRAP_AAD), lenPref(utf8(username)));
}

/** Wrap a vault key under the passphrase-derived key. */
export function wrapVaultKey(
  wrapKey: Uint8Array,
  vaultKey: Uint8Array,
  username: string,
  params: VaultKdfParams = VAULT_KDF_PARAMS,
): WrappedVault {
  const sealed = seal(wrapKey, vaultKey, wrapAad(username));
  return { params, wrapped: sealed.ciphertext, wrapNonce: sealed.nonce };
}

/**
 * Recover the vault key. A wrong passphrase fails the AEAD tag here rather than
 * producing a key that decrypts the blob into garbage.
 */
export function unwrapVaultKey(
  wrapKey: Uint8Array,
  record: WrappedVault,
  username: string,
): Uint8Array {
  const key = open(wrapKey, { ciphertext: record.wrapped, nonce: record.wrapNonce }, wrapAad(username));
  if (key.length !== KEY_BYTES) throw new Error("vault key length");
  return key;
}

/**
 * Binding the version into the AAD is what makes a rollback detectable: an
 * origin that serves an old blob alongside the current version cannot make it
 * open, so a stale device list fails loudly instead of resurrecting a credential
 * its owner already revoked.
 */
function blobAad(userId: string, version: number): Uint8Array {
  return concat(utf8(BLOB_AAD), lenPref(utf8(userId)), u64be(version));
}

/**
 * Standard base64, because that is what the relay's field validation accepts.
 * The choice is the transport's, not the cipher's.
 */
function seal(key: Uint8Array, plaintext: Uint8Array, aad: Uint8Array): SealedBytes {
  const nonce = randomBytes(NONCE_BYTES);
  return {
    ciphertext: base64Encode(xchacha20poly1305(key, nonce, aad).encrypt(plaintext)),
    nonce: base64Encode(nonce),
  };
}

function open(key: Uint8Array, sealed: SealedBytes, aad: Uint8Array): Uint8Array {
  const nonce = base64Decode(sealed.nonce);
  if (nonce.length !== NONCE_BYTES) throw new Error("vault nonce length");
  return xchacha20poly1305(key, nonce, aad).decrypt(base64Decode(sealed.ciphertext));
}

/** One step removed from the account key, so the blob's key is never the derived key itself. */
function contentKey(vaultKey: Uint8Array): Uint8Array {
  return pairfobHKDF(vaultKey, null, utf8(CONTENT_INFO), KEY_BYTES);
}

export function sealVault(
  vaultKey: Uint8Array,
  content: VaultContent,
  userId: string,
  version: number,
): SealedBytes {
  const plaintext = utf8(JSON.stringify(content));
  return seal(contentKey(vaultKey), plaintext, blobAad(userId, version));
}

/**
 * Decrypt and shape-check. A blob that opens but does not parse is a bug or a
 * build skew, never a credential: returning a half-built catalog would hand the
 * caller a device it cannot actually reach.
 */
export function openVault(
  vaultKey: Uint8Array,
  sealed: SealedBytes,
  userId: string,
  version: number,
): VaultContent {
  const plaintext = open(contentKey(vaultKey), sealed, blobAad(userId, version));
  const parsed: unknown = JSON.parse(new TextDecoder().decode(plaintext));
  if (!parsed || typeof parsed !== "object") throw new Error("vault content shape");
  const record = parsed as Partial<VaultContent>;
  if (record.v !== 1 || !Array.isArray(record.credentials)) throw new Error("vault content shape");
  return { v: 1, credentials: record.credentials };
}
