package daemon

import (
	"testing"
	"time"

	"pairfob/internal/envelope"
)

// TestGateSurvivesRelayDrivenExpiry covers the expiry path that does not run on
// the daemon's own clock. The relay ages out a pairing slot on its own alarm and
// reports it as an ERROR frame (workers .../room/alarms.ts), which reaches the
// daemon through handleRelayError rather than through expirePairing.
//
// The distinction is the whole point of the test. A one-use code is finished
// when the relay says so, but a passphrase gate is not: the operator set a
// passphrase and walked away, so the slot has to come back. Without the reopen
// the gate goes dark a few minutes after startup, and the failure is invisible
// locally -- the daemon keeps running, `gate status` still prints the stored
// passphrase, and only a phone discovers there is nothing to attach to.
func TestGateSurvivesRelayDrivenExpiry(t *testing.T) {
	eng, hub, stopD, stopE := gateSetup(t)
	defer close(stopD)
	defer close(stopE)

	const password = "relay-expiry-passphrase"
	if _, err := eng.SetGatePassword(password); err != nil {
		t.Fatal("set gate password", err)
	}
	opened, err := eng.OpenPasswordGate()
	if err != nil {
		t.Fatal("open gate", err)
	}
	time.Sleep(150 * time.Millisecond)

	// Exactly what the relay sends when its alarm retires the slot: a
	// connection-scoped ERROR with the zero route id and the gate's pair_ref.
	eng.handleRelayError(envelope.JSON(envelope.TypERROR, [16]byte{}, map[string]any{
		"v": 2, "code": "pairing_expired", "pair_ref": opened.Ref,
		"message": "pairing slot expired",
	}))

	deadline := time.Now().Add(2 * time.Second)
	gateRef := ""
	for time.Now().Before(deadline) {
		eng.mu.Lock()
		if eng.pair != nil && eng.pair.persistent && !eng.pair.closed {
			gateRef = eng.pair.ref
		}
		eng.mu.Unlock()
		if gateRef != "" {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if gateRef == "" {
		t.Fatal("relay-driven expiry left no gate; the passphrase stops working minutes after startup")
	}
	if gateRef != opened.Ref {
		t.Fatalf("gate ref changed across reopen: %q then %q", opened.Ref, gateRef)
	}

	// The reopened slot has to be usable, not merely present: a phone that
	// types the same passphrase must still pair.
	ph, err := gatePhone(t, hub, gateRef, password)
	if err != nil {
		t.Fatal("pair after relay-driven expiry", err)
	}
	time.Sleep(80 * time.Millisecond)
	if !eng.HasDevice(ph.DeviceID) {
		t.Fatal("device paired after relay-driven expiry was not persisted")
	}
}
