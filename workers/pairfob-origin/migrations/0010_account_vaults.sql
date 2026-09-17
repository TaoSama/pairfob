-- Credentials sync between phones through the relay, so the relay must hold
-- them as an opaque blob: the client encrypts under a key derived from the
-- account password, and nothing here is ever interpreted server-side.
CREATE TABLE account_vaults (
  user_id    TEXT PRIMARY KEY,
  ciphertext TEXT NOT NULL,
  nonce      TEXT NOT NULL,
  kdf        TEXT NOT NULL,
  version    INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
);
