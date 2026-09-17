-- Three failures inside the trailing hour is not the same rule as "an hour from
-- the third failure". Counting over a moving window lets the earliest strike
-- slide out and frees the source before its hour is up, so the ban needs its
-- own deadline rather than being inferred from the strike count.
--
-- The strike ledger keeps its old job: bounding attempts that are still in
-- flight, before anyone knows whether the credential is wrong. A row there is a
-- reservation, not a verdict. Only a comparison that actually failed writes
-- here, which is what keeps a burst of correct requests from banning anyone.
CREATE TABLE auth_locks (
  subject TEXT PRIMARY KEY,
  until   INTEGER NOT NULL
);

CREATE INDEX auth_locks_until ON auth_locks (until);

-- An invite code and the global budget that protects it are one unit. Rotating
-- to a new code while the old code's exhausted budget still applies leaves the
-- new code refused for the rest of the hour, so the budget is addressed by
-- version and a rotation moves to a fresh one.
ALTER TABLE invite_codes ADD COLUMN version INTEGER NOT NULL DEFAULT 1;

-- Source budgets were shared between signing in, registering and bootstrapping,
-- so a successful sign-in cleared the strikes earned by wrong invite codes.
-- The domains are separate subjects now and the old undomained rows would be
-- read by none of them.
DELETE FROM auth_failures WHERE subject LIKE 'ip:%';
