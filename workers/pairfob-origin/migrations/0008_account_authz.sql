-- Ownership claims must be backed by a proof the relay minted for one account
-- after a pairing actually resolved to a daemon. A daemon id alone is an
-- identifier, not an authorization.
CREATE TABLE device_claim_proofs (
  proof      TEXT PRIMARY KEY,
  user_id    TEXT NOT NULL,
  daemon_id  TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL
);

CREATE INDEX device_claim_proofs_expiry ON device_claim_proofs (expires_at);

-- Set when the global wrong-code budget is exhausted. The code stays usable
-- for nobody until an admin rotates it, which clears the suspension.
ALTER TABLE invite_codes ADD COLUMN suspended_at INTEGER NOT NULL DEFAULT 0;

-- The username dimension of the lockout ledger is withdrawn: banning by
-- username let a third party lock a legitimate account out from any source.
DELETE FROM auth_failures WHERE subject LIKE 'user:%';
