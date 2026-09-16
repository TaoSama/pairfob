import { describe, expect, test } from "bun:test";
import {
  accountSalt,
  deriveAccountKeys,
  newVaultKey,
  openVault,
  sealVault,
  unwrapVaultKey,
  VAULT_KDF_PARAMS,
  wrapVaultKey,
  type VaultContent,
} from "./vault-crypto";

// Argon2id at the production cost is too slow to run dozens of times in a unit
// suite. The split and the salt are what these tests are about, and both are
// independent of the cost, so the derivation tests turn it down and the one test
// that cares about the real parameters asserts on them directly.
const FAST = { parallelism: 1, iterations: 1, memorySize: 1024 };

const USER = "u_0123456789abcdef";
const BASE64 = /^[A-Za-z0-9+/]+={0,2}$/;

// A fixed key for the content tests: they are about the AEAD, not the KDF, and
// paying Argon2id for each of them buys nothing.
const VAULT_KEY = new Uint8Array(32).fill(0x5a);

function content(labels: string[]): VaultContent {
  return {
    v: 1,
    credentials: labels.map((label) => ({
      daemon_id: "d".repeat(32),
      device_id: "v".repeat(32),
      device_psk: "psk",
      daemon_pk: "pk",
      relay_origin: "https://pair.example",
      fp: "fp",
      label,
      created_at: 1,
    })) as VaultContent["credentials"],
  };
}

async function keys(password = "correct horse battery", username = "admin", host = "pair.example") {
  return deriveAccountKeys(username, password, host, FAST);
}

describe("account key derivation", () => {
  test("the same passphrase and account rederive the same keys on another device", async () => {
    const first = await keys();
    const second = await keys();
    expect(second.authSecret).toBe(first.authSecret);
    expect([...second.wrapKey]).toEqual([...first.wrapKey]);
  });

  test("the transmitted authenticator and the retained wrapping key are different secrets", async () => {
    const derived = await keys();
    // An origin that stores the authenticator learns nothing about the key that
    // unwraps the vault; this is the whole point of the split.
    expect(derived.authSecret).not.toBe(Buffer.from(derived.wrapKey).toString("hex"));
    expect(derived.authSecret).toMatch(/^[0-9a-f]{64}$/);
    expect(derived.wrapKey).toHaveLength(32);
  });

  test("a different passphrase, account or host derives unrelated keys", async () => {
    const base = await keys();
    const others = [
      await keys("correct horse batteries"),
      await keys("correct horse battery", "admin2"),
      await keys("correct horse battery", "admin", "pair.other"),
    ];
    for (const other of others) {
      expect(other.authSecret).not.toBe(base.authSecret);
      expect([...other.wrapKey]).not.toEqual([...base.wrapKey]);
    }
  });

  test("the salt is length-prefixed so a username cannot borrow the host's prefix", () => {
    // "ab"+"cd" and "abc"+"d" concatenate identically; the salt must not.
    expect([...accountSalt("ab", "cd")]).not.toEqual([...accountSalt("abc", "d")]);
    expect(accountSalt("admin", "pair.example")).toHaveLength(16);
  });

  test("the shipped cost matches the pairing record's", () => {
    expect(VAULT_KDF_PARAMS).toEqual({ parallelism: 1, iterations: 3, memorySize: 65536 });
  });
});

describe("vault key wrapping", () => {
  test("a wrapped key comes back out under the same passphrase", async () => {
    const { wrapKey } = await keys();
    const vaultKey = newVaultKey();
    const record = wrapVaultKey(wrapKey, vaultKey, "admin", FAST);
    expect([...unwrapVaultKey(wrapKey, record, "admin")]).toEqual([...vaultKey]);
  });

  test("the vault key is random, not a function of the passphrase", async () => {
    // Two accounts opened with the same passphrase must not share a vault key,
    // and neither must two vaults of one account: this is what lets a passphrase
    // change rewrap instead of re-encrypting.
    const { wrapKey } = await keys();
    const first = newVaultKey();
    const second = newVaultKey();
    expect([...second]).not.toEqual([...first]);
    expect([...first]).not.toEqual([...wrapKey]);
  });

  test("a wrong passphrase fails the unwrap instead of yielding a usable key", async () => {
    const mine = await keys();
    const other = await keys("wrong passphrase");
    const record = wrapVaultKey(mine.wrapKey, newVaultKey(), "admin", FAST);
    expect(() => unwrapVaultKey(other.wrapKey, record, "admin")).toThrow();
  });

  test("a record cannot be replayed under another username", async () => {
    const { wrapKey } = await keys();
    const record = wrapVaultKey(wrapKey, newVaultKey(), "admin", FAST);
    expect(() => unwrapVaultKey(wrapKey, record, "intruder")).toThrow();
  });

  test("a new passphrase rewraps the same vault key, leaving the blob readable", async () => {
    const old = await keys();
    const fresh = await keys("a whole new passphrase");
    const vaultKey = newVaultKey();
    const sealed = sealVault(vaultKey, content(["desk"]), USER, 1);

    // What a password change actually does: unwrap under the old key, wrap under
    // the new one. The ciphertext is never touched.
    const before = wrapVaultKey(old.wrapKey, vaultKey, "admin", FAST);
    const after = wrapVaultKey(fresh.wrapKey, unwrapVaultKey(old.wrapKey, before, "admin"), "admin", FAST);

    const recovered = unwrapVaultKey(fresh.wrapKey, after, "admin");
    expect(openVault(recovered, sealed, USER, 1).credentials).toHaveLength(1);
    expect(() => unwrapVaultKey(old.wrapKey, after, "admin")).toThrow();
  });

  test("the wrapped fields are the base64 the relay accepts", async () => {
    const { wrapKey } = await keys();
    const record = wrapVaultKey(wrapKey, newVaultKey(), "admin", FAST);
    expect(record.wrapped).toMatch(BASE64);
    expect(record.wrapNonce).toMatch(BASE64);
  });
});

describe("vault content", () => {
  test("a sealed catalog round-trips", () => {
    const sealed = sealVault(VAULT_KEY, content(["desk", "laptop"]), USER, 4);
    const opened = openVault(VAULT_KEY, sealed, USER, 4);
    expect(opened.credentials.map((c) => c.label)).toEqual(["desk", "laptop"]);
  });

  test("the encoded fields are the base64 the relay accepts", () => {
    // The relay validates both columns against standard base64 and rejects the
    // write otherwise, so a url-safe alphabet here would fail every upload.
    const sealed = sealVault(VAULT_KEY, content(["desk"]), USER, 1);
    expect(sealed.ciphertext).toMatch(BASE64);
    expect(sealed.nonce).toMatch(BASE64);
  });

  test("another vault key cannot open the blob", () => {
    const sealed = sealVault(VAULT_KEY, content(["desk"]), USER, 1);
    expect(() => openVault(newVaultKey(), sealed, USER, 1)).toThrow();
  });

  test("a blob served back at the wrong version does not open", () => {
    // A rollback attack: the origin returns version 4's blob while claiming 5.
    const sealed = sealVault(VAULT_KEY, content(["desk"]), USER, 4);
    expect(() => openVault(VAULT_KEY, sealed, USER, 5)).toThrow();
  });

  test("another account's blob does not open under this user id", () => {
    const sealed = sealVault(VAULT_KEY, content(["desk"]), USER, 1);
    expect(() => openVault(VAULT_KEY, sealed, "u_fedcba9876543210", 1)).toThrow();
  });

  test("two seals of one catalog differ, so the stored value leaks no repetition", () => {
    const first = sealVault(VAULT_KEY, content(["desk"]), USER, 1);
    const second = sealVault(VAULT_KEY, content(["desk"]), USER, 1);
    expect(second.nonce).not.toBe(first.nonce);
    expect(second.ciphertext).not.toBe(first.ciphertext);
  });

  test("a tampered blob is rejected rather than returning garbage", () => {
    const sealed = sealVault(VAULT_KEY, content(["desk"]), USER, 1);
    const flipped = {
      ...sealed,
      ciphertext: sealed.ciphertext.slice(0, -2) + (sealed.ciphertext.endsWith("AA") ? "BB" : "AA"),
    };
    expect(() => openVault(VAULT_KEY, flipped, USER, 1)).toThrow();
  });

  test("a blob that decrypts but carries an unknown shape is refused", () => {
    const sealed = sealVault(VAULT_KEY, { v: 2, credentials: [] } as unknown as VaultContent, USER, 1);
    expect(() => openVault(VAULT_KEY, sealed, USER, 1)).toThrow("vault content shape");
  });

  test("an empty catalog is a legitimate vault, not an error", () => {
    const sealed = sealVault(VAULT_KEY, content([]), USER, 1);
    expect(openVault(VAULT_KEY, sealed, USER, 1).credentials).toEqual([]);
  });
});
