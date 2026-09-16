package daemon

// unit coverage for the gate throttle. The e2e tests in
// gate_e2e_test.go prove a wrong passphrase does not burn the gate; what is not
// covered there is the thing that replaced burning as the brute-force bound.
// A cooldown that is computed but never enforced would pass every one of those
// tests while leaving the gate open to an unlimited dictionary run, so the
// backoff curve, the window, and the refuse-before-Argon2id guard are pinned
// here directly rather than inferred from end-to-end behaviour.

import (
	"testing"
	"time"
)

// TestGateCooldownCurve pins the backoff schedule. The free attempts exist so a
// mistyped passphrase costs nothing, and the ceiling exists so the gate can
// never be pushed into a permanent lockout by a sustained attack.
func TestGateCooldownCurve(t *testing.T) {
	for _, tc := range []struct {
		failures int
		want     time.Duration
	}{
		{0, 0},
		{1, 0},
		{gateFreeAttempts, 0},
		{gateFreeAttempts + 1, gateCooldownBase},
		{gateFreeAttempts + 2, 2 * gateCooldownBase},
		{gateFreeAttempts + 3, 4 * gateCooldownBase},
		// The doubling saturates at the ceiling instead of overflowing.
		{gateFreeAttempts + 20, gateCooldownMax},
		{gateFreeAttempts + 64, gateCooldownMax},
		{gateFreeAttempts + 1000, gateCooldownMax},
	} {
		if got := gateCooldown(tc.failures); got != tc.want {
			t.Errorf("gateCooldown(%d) = %s, want %s", tc.failures, got, tc.want)
		}
	}
}

// TestGateThrottleBlocksAfterFreeAttempts walks the ledger the way a guesser
// would and asserts the gate actually stops answering.
func TestGateThrottleBlocksAfterFreeAttempts(t *testing.T) {
	e := &Engine{}
	now := time.Now()

	// gateFreeAttempts failures are tolerated, so the backoff arms on the next
	// one: attempts 1..gateFreeAttempts+1 are all answered.
	for i := range gateFreeAttempts + 1 {
		if !e.allowGateAttemptLocked(now) {
			t.Fatalf("attempt %d refused while still inside the free budget", i+1)
		}
		e.noteGateFailureLocked(now)
	}
	if e.allowGateAttemptLocked(now) {
		t.Fatal("gate still answering after the free budget was spent")
	}

	// Serving the cooldown re-opens the gate for exactly one more proof.
	now = now.Add(gateCooldownBase)
	if !e.allowGateAttemptLocked(now) {
		t.Fatal("gate still blocked after its cooldown elapsed")
	}
	e.noteGateFailureLocked(now)
	if e.allowGateAttemptLocked(now) {
		t.Fatal("a failure during the retry did not re-arm the cooldown")
	}
	// ...and the next wait is longer than the one just served.
	if !e.allowGateAttemptLocked(now.Add(2 * gateCooldownBase)) {
		t.Fatal("second cooldown outlasted the doubled backoff")
	}
}

// TestGateThrottleRefusalDoesNotExtendBlock is the property that keeps the
// throttle from becoming its own denial of service: an attacker who keeps
// hammering during a cooldown must not push the owner's unlock further away.
func TestGateThrottleRefusalDoesNotExtendBlock(t *testing.T) {
	e := &Engine{}
	start := time.Now()
	for range gateFreeAttempts + 1 {
		e.noteGateFailureLocked(start)
	}
	blockedUntil := e.gateCooldownUntil
	if !blockedUntil.After(start) {
		t.Fatal("no cooldown was armed")
	}

	// Flood the gate while it is refusing. allowGateAttemptLocked is the only
	// path a blocked attempt takes, and it must not record anything.
	for step := time.Duration(0); step < gateCooldownBase; step += gateCooldownBase / 8 {
		if e.allowGateAttemptLocked(start.Add(step)) {
			t.Fatalf("gate answered %s into its cooldown", step)
		}
	}
	if !e.gateCooldownUntil.Equal(blockedUntil) {
		t.Fatalf("refused attempts moved the unlock time from %s to %s", blockedUntil, e.gateCooldownUntil)
	}
}

// TestGateThrottleWindowExpires proves the ledger is a sliding window rather
// than a permanent record: an operator who fails a few times, walks away, and
// comes back an hour later must find the gate as responsive as a fresh one.
func TestGateThrottleWindowExpires(t *testing.T) {
	e := &Engine{}
	start := time.Now()
	for range gateFreeAttempts + 1 {
		e.noteGateFailureLocked(start)
	}
	if e.allowGateAttemptLocked(start) {
		t.Fatal("gate did not block after exceeding the free budget")
	}

	later := start.Add(gateWindow + time.Second)
	if !e.allowGateAttemptLocked(later) {
		t.Fatal("stale failures outside the window still blocked the gate")
	}
	if len(e.gateFailures) != 0 {
		t.Fatalf("expired failures were not pruned: %d left", len(e.gateFailures))
	}
	// A cleared ledger must also restore the full free budget, not leave the
	// backoff primed to fire on the next single mistake.
	for i := range gateFreeAttempts + 1 {
		if !e.allowGateAttemptLocked(later) {
			t.Fatalf("post-window attempt %d refused; free budget was not restored", i+1)
		}
		e.noteGateFailureLocked(later)
	}
}

// TestGateThrottleIgnoresOneUseCodes guards the blast radius of the throttle.
// The shared ledger is keyed to the daemon, not the slot, so a bug that counted
// one-use pairing failures into it would let a stranger burning QR codes slow
// down the operator's passphrase login.
func TestGateThrottleIgnoresOneUseCodes(t *testing.T) {
	e := &Engine{DaemonID: "d_0123456789abcdef0123"}
	pair := &pairingSlot{
		ref: "0123456789abcdef0123456789abcdef", code: "ABCDEFGH",
		admitCh: make(chan struct{}), readyCh: make(chan struct{}),
	}
	e.pair = pair

	// Two failures: below the burn threshold, so the slot survives and the only
	// observable effect should be on the slot's own counter.
	for range 2 {
		if ref := e.pairFailureLocked(pair, "bad_confirm"); ref != "" {
			t.Fatal("one-use slot burned before its third failure")
		}
	}
	if len(e.gateFailures) != 0 {
		t.Fatalf("one-use failures entered the gate ledger: %d", len(e.gateFailures))
	}
	if !e.allowGateAttemptLocked(time.Now()) {
		t.Fatal("one-use failures throttled the passphrase gate")
	}

	// The third failure must still burn a one-use code.
	if ref := e.pairFailureLocked(pair, "bad_confirm"); ref == "" {
		t.Fatal("one-use slot survived three failures; a guesser could hammer it")
	}
}

// TestGatePersistentFailureFeedsThrottle is the converse: a persistent slot must
// never burn, however many proofs it rejects.
//
// The ledger is deliberately not asserted here. Attempts are charged where the
// guess is actually spent -- at SpakeShareP, once the daemon has answered with
// confirm_v (pairing.go:589) -- and refunded only when a confirm verifies
// (pairing.go:640). Billing on the failure path instead would let a guesser
// check confirm_v offline and hang up without ever being counted. That the
// charge is reached over the real frame path is proven in gate_attack_test.go;
// what belongs here is only the no-burn guarantee.
func TestGatePersistentFailureFeedsThrottle(t *testing.T) {
	e := &Engine{DaemonID: "d_0123456789abcdef0123"}
	pair := &pairingSlot{
		ref: "0123456789abcdef0123456789abcdef", persistent: true,
		admitCh: make(chan struct{}), readyCh: make(chan struct{}),
	}
	e.pair = pair

	for i := range gateFreeAttempts + 2 {
		if ref := e.pairFailureLocked(pair, "bad_confirm"); ref != "" {
			t.Fatalf("failure %d burned the persistent gate (ref %q)", i+1, ref)
		}
		if pair.closed {
			t.Fatalf("failure %d closed the persistent gate", i+1)
		}
	}
}

// TestGateRefundIsBoundedAndClearsCooldown covers the refund's edge cases. The
// refund runs on the success path, where an off-by-one is invisible in normal
// use but hands out free guesses: an underflow on an empty ledger, or a stale
// cooldown left armed after the last charge is returned, would each let a
// guesser buy attempts back.
func TestGateRefundIsBoundedAndClearsCooldown(t *testing.T) {
	e := &Engine{}

	// A refund with nothing outstanding must be a no-op, not an underflow.
	e.refundGateAttemptLocked()
	if len(e.gateFailures) != 0 {
		t.Fatalf("refund on an empty ledger produced %d entries", len(e.gateFailures))
	}

	now := time.Now()
	for range gateFreeAttempts + 1 {
		e.noteGateFailureLocked(now)
	}
	if e.allowGateAttemptLocked(now) {
		t.Fatal("cooldown was not armed by the charges")
	}

	// Returning the charge that armed the cooldown must also disarm it,
	// otherwise the owner stays locked out after a successful login.
	e.refundGateAttemptLocked()
	if !e.allowGateAttemptLocked(now) {
		t.Fatal("refund left the cooldown armed; a valid confirm would still be blocked")
	}

	// Each refund returns exactly one charge, never the whole ledger.
	if got := len(e.gateFailures); got != gateFreeAttempts {
		t.Fatalf("refund returned more than one charge: ledger %d, want %d", got, gateFreeAttempts)
	}
}
