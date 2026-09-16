import { describe, expect, test } from "bun:test";
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
  rewrapDescriptor,
  scopeToOwnedDevices,
} from "./account-vault.ts";
import { deriveAccountKeys, newVaultKey, VAULT_KDF } from "./vault-crypto.ts";
import { encodeCredential, type StoredCredential } from "./credentials.ts";
import { b64url } from "./protocol/bytes.ts";
import { fingerprint16 } from "./protocol/hello.ts";

const FAST = { parallelism: 1, iterations: 1, memorySize: 1024 };
const USER = "u_0123456789abcdef";
const HOST = "pair.example";
const PASSPHRASE = "correct horse battery";

function keyBytes(seed: number): Uint8Array {
  return new Uint8Array(32).fill(seed);
}

/** A fixed key, so the content tests are about the vault rather than the derivation. */
const VAULT_KEY = keyBytes(0x5a);

/** A credential that survives `validateStoredCredential`, so tests exercise the real filter. */
function credential(daemonSuffix: string, createdAt: number, label = "desk"): StoredCredential {
  const daemonPk = keyBytes(daemonSuffix.charCodeAt(0));
  return encodeCredential({
    daemonId: `d_${daemonSuffix.repeat(20).slice(0, 20)}`,
    deviceId: "dev_" + "A".repeat(16),
    psk: keyBytes(7),
    daemonPk,
    relayOrigin: "https://pair.example",
    fp: fingerprint16(daemonPk),
    label,
    createdAt,
  });
}

/** The record a phone would find stored, for an account whose key is `vaultKey`. */
async function storedRecord(
  vaultKey: Uint8Array,
  username = "admin",
  password = PASSPHRASE,
  params = FAST,
): Promise<string> {
  const { wrapKey } = await deriveAccountKeys(username, password, HOST, params);
  return encodeKdf(rewrapDescriptorAt(wrapKey, vaultKey, username, params));
}

/** `rewrapDescriptor` at a chosen cost, which the production helper fixes to today's. */
function rewrapDescriptorAt(
  wrapKey: Uint8Array,
  vaultKey: Uint8Array,
  username: string,
  params: typeof FAST,
) {
  const descriptor = rewrapDescriptor(wrapKey, vaultKey, username);
  return { ...descriptor, params };
}

describe("kdf record", () => {
  test("the cost and wrapped key round-trip through the stored column", async () => {
    const { wrapKey } = await deriveAccountKeys("admin", PASSPHRASE, HOST, FAST);
    const { descriptor, vaultKey } = newKdfDescriptor(wrapKey, "admin");
    const decoded = decodeKdf(encodeKdf(descriptor));
    expect(decoded.name).toBe(VAULT_KDF);
    expect(decoded.params).toEqual(currentKdfParams());
    expect([...openVaultKey(wrapKey, decoded, "admin")]).toEqual([...vaultKey]);
  });

  test("the encoded record fits the column the relay accepts", async () => {
    // The relay caps this field at 128 characters, and an over-long record fails
    // the write outright rather than degrading, so the budget is asserted rather
    // than assumed — the wrapped key and nonce alone are 96 characters.
    const { wrapKey } = await deriveAccountKeys("admin", PASSPHRASE, HOST, FAST);
    const { descriptor } = newKdfDescriptor(wrapKey, "admin");
    expect(encodeKdf(descriptor).length).toBeLessThanOrEqual(128);
  });

  test("a record with missing or nonsensical parameters is refused", () => {
    // Defaulting a missing cost would unwrap with the wrong key and present as a
    // wrong passphrase, sending the user to reset an account that was fine.
    expect(() => decodeKdf("")).toThrow("kdf shape");
    expect(() => decodeKdf("argon2id-v1.3.65536.1")).toThrow("kdf shape");
    expect(() => decodeKdf("argon2id-v1.3.65536.1.AAAA")).toThrow("kdf shape");
    expect(() => decodeKdf("argon2id-v1.0.65536.1.AAAA.BBBB")).toThrow("kdf params");
    expect(() => decodeKdf("argon2id-v1.3x.65536.1.AAAA.BBBB")).toThrow("kdf params");
    expect(() => decodeKdf("argon2id-v1..65536.1.AAAA.BBBB")).toThrow("kdf params");
  });

  test("a second phone recovers the vault key from the record and the passphrase alone", async () => {
    // This is the whole acceptance criterion: nothing is carried between phones
    // but what the user types and what the relay already stores.
    const vaultKey = newVaultKey();
    const stored = await storedRecord(vaultKey);

    const recovered = await recoverVaultKey("admin", PASSPHRASE, HOST, decodeKdf(stored));
    expect([...recovered]).toEqual([...vaultKey]);
  });

  test("a second phone opens the vault the first one wrote", async () => {
    const vaultKey = newVaultKey();
    const sealed = encryptVault(vaultKey, [credential("a", 10), credential("b", 20)], USER, 3);
    const stored = await storedRecord(vaultKey);

    const second = await recoverVaultKey("admin", PASSPHRASE, HOST, decodeKdf(stored));
    const snapshot = decryptVault(second, sealed, USER, 3);
    expect(snapshot.credentials.map((c) => c.daemon_id)).toEqual(["d_aaaaaaaaaaaaaaaaaaaa", "d_bbbbbbbbbbbbbbbbbbbb"]);
  });

  test("a wrong passphrase is refused at the unwrap, not left to corrupt the vault", async () => {
    const stored = await storedRecord(newVaultKey());
    await expect(recoverVaultKey("admin", "wrong passphrase", HOST, decodeKdf(stored))).rejects.toThrow();
  });

  test("another account's passphrase does not reach this vault", async () => {
    // The username is bound into both the salt and the wrap AAD, so one account's
    // derivation cannot stand in for another's even with the same passphrase.
    const stored = await storedRecord(newVaultKey());
    await expect(recoverVaultKey("bob", PASSPHRASE, HOST, decodeKdf(stored))).rejects.toThrow();
  });

  test("the vault is recovered under the cost the record names, not today's default", async () => {
    // A future cost increase must not lock users out of vaults written before it.
    const legacy = { parallelism: 1, iterations: 2, memorySize: 2048 };
    const vaultKey = newVaultKey();
    const stored = await storedRecord(vaultKey, "admin", PASSPHRASE, legacy);
    const recovered = await recoverVaultKey("admin", PASSPHRASE, HOST, decodeKdf(stored));
    expect([...recovered]).toEqual([...vaultKey]);
  });

  test("a passphrase change rewraps the key without touching the ciphertext", async () => {
    // The point of wrapping: the blob written under the old passphrase stays
    // readable, so a password change is one small write rather than a re-upload.
    const vaultKey = newVaultKey();
    const sealed = encryptVault(vaultKey, [credential("a", 10)], USER, 1);
    const fresh = await deriveAccountKeys("admin", "an entirely new passphrase", HOST, FAST);

    const rewrapped = encodeKdf(rewrapDescriptorAt(fresh.wrapKey, vaultKey, "admin", FAST));
    const recovered = await recoverVaultKey("admin", "an entirely new passphrase", HOST, decodeKdf(rewrapped));
    expect(decryptVault(recovered, sealed, USER, 1).credentials).toHaveLength(1);
    await expect(recoverVaultKey("admin", PASSPHRASE, HOST, decodeKdf(rewrapped))).rejects.toThrow();
  });
});

describe("session derivation", () => {
  test("the passphrase yields an authenticator to send and a key to keep", async () => {
    const session = await deriveSession("admin", PASSPHRASE, HOST, FAST);
    expect(session.username).toBe("admin");
    expect(session.authSecret).toMatch(/^[0-9a-f]{64}$/);
    expect(session.wrapKey).toHaveLength(32);
  });

  test("the transmitted authenticator is accepted by the origin's password rules", async () => {
    // 64 hex characters sit inside the 8..128 byte window the Worker enforces and
    // contain no control characters, so the existing password path needs no
    // special case. The Worker sees this value as an ordinary password.
    const session = await deriveSession("admin", PASSPHRASE, HOST, FAST);
    expect(session.authSecret.length).toBeGreaterThanOrEqual(8);
    expect(session.authSecret.length).toBeLessThanOrEqual(128);
    expect(/[ -]/.test(session.authSecret)).toBeFalse();
  });

  test("what is sent to the origin is neither the passphrase nor a vault key", async () => {
    // If one were derivable from the other, storing the authenticator would be
    // equivalent to storing the key that opens the vault.
    const session = await deriveSession("admin", PASSPHRASE, HOST, FAST);
    expect(session.authSecret).not.toBe(Buffer.from(session.wrapKey).toString("hex"));
    expect(session.authSecret).not.toContain(PASSPHRASE);
  });
});

describe("vault contents", () => {
  test("credentials survive a seal and open at the same version", () => {
    const sealed = encryptVault(VAULT_KEY, [credential("a", 10), credential("b", 20)], USER, 2);
    const snapshot = decryptVault(VAULT_KEY, sealed, USER, 2);
    expect(snapshot.credentials).toHaveLength(2);
    expect(snapshot.version).toBe(2);
  });

  test("a decrypted record this build cannot use is dropped, not surfaced as a device", () => {
    // It would appear in the list and then fail at connect time, which reads as
    // a broken machine rather than an incompatible record.
    const good = credential("a", 10);
    const broken = { ...credential("b", 20), fp: "0".repeat(16) };
    const sealed = encryptVault(VAULT_KEY, [good, broken], USER, 1);
    const snapshot = decryptVault(VAULT_KEY, sealed, USER, 1);
    expect(snapshot.credentials.map((c) => c.daemon_id)).toEqual([good.daemon_id]);
  });

  test("an empty vault decrypts to an empty list", () => {
    expect(decryptVault(VAULT_KEY, encryptVault(VAULT_KEY, [], USER, 1), USER, 1).credentials).toEqual([]);
  });

  test("the psk is inside the ciphertext and nowhere in the transmitted fields", () => {
    // The relay stores these two strings verbatim; neither may contain key material.
    const stored = credential("a", 10);
    const sealed = encryptVault(VAULT_KEY, [stored], USER, 1);
    expect(sealed.ciphertext).not.toContain(stored.device_psk);
    expect(sealed.nonce).not.toContain(stored.device_psk);
    expect(sealed.ciphertext).not.toContain(b64url(keyBytes(7)));
  });
});

describe("merging two phones", () => {
  test("a device only the vault knows about is adopted locally", () => {
    const remote = [credential("a", 10)];
    expect(mergeCredentials([], remote).map((c) => c.daemon_id)).toEqual([remote[0].daemon_id]);
  });

  test("a device only this phone knows about is kept for the next upload", () => {
    const local = [credential("b", 10)];
    expect(mergeCredentials(local, []).map((c) => c.daemon_id)).toEqual([local[0].daemon_id]);
  });

  test("the same machine paired twice keeps the newer enrolment", () => {
    // The daemon honours only the most recent enrolment, so the older record is
    // not merely redundant — it no longer works.
    const older = credential("a", 10, "old");
    const newer = credential("a", 99, "new");
    const merged = mergeCredentials([older], [newer]);
    expect(merged).toHaveLength(1);
    expect(merged[0].label).toBe("new");

    const reversed = mergeCredentials([newer], [older]);
    expect(reversed[0].label).toBe("new");
  });

  test("the merged list is ordered newest first", () => {
    const merged = mergeCredentials([credential("a", 10)], [credential("b", 30), credential("c", 20)]);
    expect(merged.map((c) => c.created_at)).toEqual([30, 20, 10]);
  });
});

describe("account scoping", () => {
  test("only devices the relay says this account owns are offered", () => {
    // Another user's credential must never appear, even if it somehow reached
    // this phone's storage.
    const mine = credential("a", 10);
    const theirs = credential("b", 20);
    const scoped = scopeToOwnedDevices([mine, theirs], [mine.daemon_id]);
    expect(scoped.map((c) => c.daemon_id)).toEqual([mine.daemon_id]);
  });

  test("an account that owns nothing sees nothing", () => {
    expect(scopeToOwnedDevices([credential("a", 10)], [])).toEqual([]);
  });

  test("ownership the relay reports without a matching credential adds no entry", () => {
    // A device bound on another phone before this one synced is a name without
    // keys; it cannot be connected to and must not pretend otherwise.
    const mine = credential("a", 10);
    const scoped = scopeToOwnedDevices([mine], [mine.daemon_id, "d_ffffffffffffffffffff"]);
    expect(scoped).toHaveLength(1);
  });
});
