-- Resolving a pairing code proves only that the code was seen, and a code is
-- displayed on a screen. Ownership now needs a second fact the relay can
-- actually witness: the enrolled daemon accepting a session for this phone,
-- which happens only after the SPAKE2+ exchange the relay cannot read.
--
-- A proof is therefore minted pending at intent time and becomes claimable
-- only when the daemon confirms. `route_id` is what ties the two together.
ALTER TABLE device_claim_proofs ADD COLUMN ready_at INTEGER NOT NULL DEFAULT 0;
ALTER TABLE device_claim_proofs ADD COLUMN route_id TEXT NOT NULL DEFAULT '';

CREATE INDEX device_claim_proofs_route ON device_claim_proofs (daemon_id, route_id);

-- Proofs minted under the old rule were claimable on code resolution alone.
DELETE FROM device_claim_proofs;
