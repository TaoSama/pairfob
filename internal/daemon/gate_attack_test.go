package daemon

import (
	"testing"
	"time"

	"pairfob/internal/crypto/canon"
	"pairfob/internal/crypto/spake2plus"
	"pairfob/internal/state"
)

//
// gate_throttle_test.go pins the throttle's logic by calling it directly, and
// gate_e2e_test.go drives real phones through the gate. Neither one proves the
// two are connected, and that gap hid a real defect.
//
// An honest phone derives its own SPAKE2+ record, finds the daemon's confirm_v
// does not match, and hangs up before sending a SpakeConfirmP. The daemon never
// evaluates a proof and records nothing. Measured on this tree, driving three
// wrong passphrases through a real phone leaves len(eng.gateFailures) == 0, and
// deleting the whole persistent branch of pairFailureLocked still lets
// TestGateRejectsWrongPasswordWithoutBurning pass. It is a client-abort test
// wearing a brute-force test's name.
//
// An attacker has no reason to abort. A dictionary run sends a SpakeConfirmP
// per candidate and reads the answer, which is the only path that reaches the
// failure ledger. So the adversary is modelled directly here: mockPhone sends
// whatever confirm bytes it is handed.

// gateAttackEngine opens a persistent gate on a real store and returns the
// engine, its router, the record a phone derives from the passphrase, and the
// gate's stable pair_ref.
func gateAttackEngine(t *testing.T, password string) (*Engine, *pairRouter, spake2plus.Record, string) {
	t.Helper()
	eng, router := newPairingEngine(t)
	store, err := state.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	eng.Store = store
	// AutoAdmit is the development escape hatch. The gate has to authorize on
	// the strength of the passphrase proof alone.
	eng.AutoAdmit = false
	if _, err := eng.SetGatePassword(password); err != nil {
		t.Fatal("set gate password:", err)
	}
	status, err := eng.OpenPasswordGate()
	if err != nil {
		t.Fatal("open gate:", err)
	}
	gate, found, err := eng.LoadGate()
	if err != nil || !found {
		t.Fatalf("load gate: found=%v err=%v", found, err)
	}
	record, err := gateSpakeRecord(gate)
	if err != nil {
		t.Fatal("gate record:", err)
	}
	return eng, router, record, status.Ref
}

// guessAndHangUp models the cheaper and strictly stronger attack: attach, send
// a share, read confirm_v, and disconnect. In SPAKE2+ the online guess is fully
// spent at that point — confirm_v is checkable offline against the candidate
// passphrase — so an attacker gains nothing by sending a confirm the daemon
// would reject. A throttle billed on the confirm path alone therefore counts
// none of these attempts.
//
// Measured on this tree before the fix: 25 of 25 such guesses were answered and
// the ledger recorded 0. This test is what keeps the charge at SpakeShareP.
func guessAndHangUp(t *testing.T, eng *Engine, router *pairRouter, rec spake2plus.Record, ref string, tag byte) (answered bool) {
	t.Helper()
	ph := newMockPhone("hangup", eng, tag, rec, ref)
	ph.attach()
	ph.sendShare()
	err := ph.recvShareV(router)
	time.Sleep(10 * time.Millisecond)
	return err == nil
}

// TestGateThrottleBillsGuessesThatNeverConfirm pins the defect directly. An
// attacker who never sends a confirm must still be throttled, or the gate
// answers an unbounded dictionary run while every other gate test passes.
func TestGateThrottleBillsGuessesThatNeverConfirm(t *testing.T) {
	eng, router, rec, ref := gateAttackEngine(t, "the-real-passphrase")

	const attempts = 20
	answered := 0
	for i := range attempts {
		if guessAndHangUp(t, eng, router, rec, ref, byte(0x90+i)) {
			answered++
		}
	}

	eng.mu.Lock()
	failures := len(eng.gateFailures)
	blocked := !eng.allowGateAttemptLocked(time.Now())
	eng.mu.Unlock()

	if failures == 0 {
		t.Fatalf("%d abort-after-confirm_v guesses recorded nothing: the online guess is free and the dictionary run is unbounded", attempts)
	}
	if !blocked {
		t.Fatalf("cooldown never armed after %d guesses (%d answered, %d billed)", attempts, answered, failures)
	}
	// The free budget plus the proofs that slip through while the backoff is
	// still short is the whole allowance; anything near `attempts` means the
	// throttle is not actually bounding the run.
	if answered > gateFreeAttempts+3 {
		t.Fatalf("daemon answered %d of %d guesses; throttle is not bounding the run", answered, attempts)
	}
}

// guessWithBadConfirm runs one attacker attempt: attach, exchange shares, then
// submit a deliberately wrong confirm_p. Reaching SpakeShareV is not required
// for the attempt to count as issued: once the cooldown arms, the daemon
// refuses before producing one, which is the behaviour under test.
func guessWithBadConfirm(t *testing.T, eng *Engine, router *pairRouter, rec spake2plus.Record, ref string, tag byte) {
	t.Helper()
	ph := newMockPhone("guess", eng, tag, rec, ref)
	ph.attach()
	ph.sendShare()
	if err := ph.recvShareV(router); err != nil {
		return
	}
	ph.fwd(map[string]any{
		"v": 1, "op": "SpakeConfirmP",
		"confirm_p": canon.B64URL(make([]byte, 32)),
	})
	time.Sleep(20 * time.Millisecond)
}

// TestGateThrottleReachedByAttackerGuesses is the wiring test: it asserts a
// real guess over the real frame path lands in the ledger the unit tests pin.
// If this fails while gate_throttle_test.go passes, the throttle is correct and
// unreachable, and the gate answers an unlimited dictionary run.
func TestGateThrottleReachedByAttackerGuesses(t *testing.T) {
	eng, router, rec, ref := gateAttackEngine(t, "the-real-passphrase")

	for i := range gateFreeAttempts {
		guessWithBadConfirm(t, eng, router, rec, ref, byte(0x10+i))
	}

	eng.mu.Lock()
	failures := len(eng.gateFailures)
	alive := eng.pair != nil && !eng.pair.closed && eng.pair.persistent
	eng.mu.Unlock()

	if failures == 0 {
		t.Fatal("daemon recorded no failures for attacker guesses over the real frame path: the throttle is unreachable and a dictionary run is unbounded")
	}
	if !alive {
		t.Fatal("attacker guesses destroyed the persistent gate: a stranger could lock the owner out")
	}
}

// TestGateThrottleRefusesGuessOverFramePath completes the chain: enough real
// guesses must make the daemon actually stop answering. Counting failures
// without refusing anything would bound nothing.
func TestGateThrottleRefusesGuessOverFramePath(t *testing.T) {
	eng, router, rec, ref := gateAttackEngine(t, "the-real-passphrase")

	for i := range gateFreeAttempts + 2 {
		guessWithBadConfirm(t, eng, router, rec, ref, byte(0x30+i))
	}

	eng.mu.Lock()
	failures := len(eng.gateFailures)
	allowed := eng.allowGateAttemptLocked(time.Now())
	eng.mu.Unlock()

	if failures <= gateFreeAttempts {
		t.Fatalf("only %d failures recorded over the frame path for %d guesses; the throttle cannot arm", failures, gateFreeAttempts+2)
	}
	if allowed {
		t.Fatal("cooldown never armed despite real guesses exceeding the free budget")
	}
}

// TestGateThrottleLiftsForOwnerOverFramePath guards the other half of the
// tradeoff end to end. A throttle that never lifts is the lockout the no-burn
// design set out to avoid, so the owner must get back in once the window
// passes -- proven here by a full successful pairing, not by inspecting state.
func TestGateThrottleLiftsForOwnerOverFramePath(t *testing.T) {
	const password = "the-real-passphrase"
	eng, router, rec, ref := gateAttackEngine(t, password)

	for i := range gateFreeAttempts + 2 {
		guessWithBadConfirm(t, eng, router, rec, ref, byte(0x50+i))
	}
	eng.mu.Lock()
	blocked := !eng.allowGateAttemptLocked(time.Now())
	// Age the ledger out rather than sleeping a whole window in a unit test.
	for i := range eng.gateFailures {
		eng.gateFailures[i] = eng.gateFailures[i].Add(-gateWindow - time.Second)
	}
	eng.gateCooldownUntil = time.Time{}
	eng.mu.Unlock()
	if !blocked {
		t.Fatal("cooldown did not engage after the free budget was spent")
	}

	// The owner's correct passphrase derives the same record the gate stored,
	// so a full handshake must now succeed.
	owner := newMockPhone("owner", eng, 0x7f, rec, ref)
	if err := owner.pair(router); err != nil {
		t.Fatal("owner rejected after the throttle window elapsed:", err)
	}
	if owner.deviceID == "" || len(owner.psk) != 32 {
		t.Fatalf("owner paired without a usable credential: device=%q psk=%d", owner.deviceID, len(owner.psk))
	}
	if !eng.HasDevice(owner.deviceID) {
		t.Fatal("owner's device was not persisted")
	}
}
