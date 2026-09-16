package daemon

import (
	"testing"
	"time"
)

// TestGateSurvivesSlotExpiry is the test for the failure the TTL would
// otherwise cause. OpenPasswordGate publishes a slot with pairingTTL() on it,
// and the timer calls expirePairing, which burns the slot like any other. If
// nothing republished the gate, a daemon left idle past the TTL would stop
// accepting the passphrase: the operator would set a passphrase, walk away,
// come back minutes later, and find that the phone has nothing to attach to —
// with no error anywhere to explain it.
//
// The TTL is shortened here because the real one is three minutes. PairingTTL
// below 60s falls back to the default (pairing.go:134), so the timer is driven
// directly instead: this exercises the same expirePairing path the production
// timer fires, without a three-minute test.
func TestGateSurvivesSlotExpiry(t *testing.T) {
	eng, hub, stopD, stopE := gateSetup(t)
	defer close(stopD)
	defer close(stopE)

	const password = "outlives-the-slot-ttl"
	if _, err := eng.SetGatePassword(password); err != nil {
		t.Fatal(err)
	}
	opened, err := eng.OpenPasswordGate()
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(150 * time.Millisecond)

	eng.mu.Lock()
	slot := eng.pair
	eng.mu.Unlock()
	if slot == nil {
		t.Fatal("gate did not publish a slot")
	}

	// Fire the expiry exactly as the TTL timer would.
	eng.expirePairing(slot)

	// The reopen is asynchronous on purpose (gate.go:239), so wait for a live
	// persistent slot rather than reading once and racing it.
	ref, ok := waitForLiveGate(t, eng)
	if !ok {
		t.Fatal("gate did not reopen after its slot expired; the passphrase would stop working after the TTL")
	}
	if ref != opened.Ref {
		t.Fatalf("pair_ref changed across expiry: %q then %q; every phone taught the old ref would be locked out", opened.Ref, ref)
	}

	// The point of all of it: a phone must still be able to pair.
	ph, err := gatePhone(t, hub, ref, password)
	if err != nil {
		t.Fatal("passphrase rejected after the slot expired", err)
	}
	time.Sleep(80 * time.Millisecond)
	if !eng.HasDevice(ph.DeviceID) {
		t.Fatal("device paired after expiry was not persisted")
	}
}

// TestGateDoesNotReopenAfterClear guards the other direction. Revoking the
// passphrase must actually revoke it; a reopen racing the clear would leave a
// slot serving a gate the operator just deleted.
func TestGateDoesNotReopenAfterClear(t *testing.T) {
	eng, _, stopD, stopE := gateSetup(t)
	defer close(stopD)
	defer close(stopE)

	if _, err := eng.SetGatePassword("cleared-while-open-ok"); err != nil {
		t.Fatal(err)
	}
	if _, err := eng.OpenPasswordGate(); err != nil {
		t.Fatal(err)
	}
	time.Sleep(150 * time.Millisecond)

	if err := eng.ClearGatePassword(); err != nil {
		t.Fatal(err)
	}
	// Give any in-flight reopen time to land before asserting it did not.
	time.Sleep(300 * time.Millisecond)

	eng.mu.Lock()
	alive := eng.pair != nil && !eng.pair.closed
	eng.mu.Unlock()
	if alive {
		t.Fatal("a pairing slot is still serving a passphrase that was cleared")
	}
	if _, found, err := eng.LoadGate(); err != nil || found {
		t.Fatalf("cleared gate came back: found=%v err=%v", found, err)
	}
}

// waitForLiveGate polls for a published persistent slot and returns its ref.
func waitForLiveGate(t *testing.T, eng *Engine) (string, bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		eng.mu.Lock()
		pair := eng.pair
		live := pair != nil && !pair.closed && pair.persistent
		ref := ""
		if live {
			ref = pair.ref
		}
		eng.mu.Unlock()
		if live {
			return ref, true
		}
		time.Sleep(25 * time.Millisecond)
	}
	return "", false
}
