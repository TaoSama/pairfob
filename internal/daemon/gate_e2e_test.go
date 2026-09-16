package daemon

import (
	"testing"
	"time"

	"pairfob/internal/envelope"
	"pairfob/internal/mux"
	"pairfob/internal/phone"
	"pairfob/internal/runtime"
	"pairfob/internal/state"
)

// gateSetup mirrors setup() but keeps AutoAdmit off and attaches a real store,
// so what the gate tests exercise is the passphrase path itself rather than the
// development auto-admit escape hatch.
func gateSetup(t *testing.T) (*Engine, *mux.Hub, chan struct{}, chan struct{}) {
	t.Helper()
	store, err := state.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	hub := mux.NewHub("pf_gate")
	engA, hubD := mux.NewPipePair(32)
	eng := NewEngine(hub, engA, runtime.NewFake())
	eng.Store = store
	stopD := pump(t, hubD, func(f envelope.Frame) { hub.HandleDaemon(hubD, f) })
	if err := eng.Register("pf_gate"); err != nil {
		t.Fatal(err)
	}
	stopE := make(chan struct{})
	go eng.RecvLoop(stopE)
	return eng, hub, stopD, stopE
}

// gatePhone runs one full phone-side pairing against the gate using password
// as the PAKE input, returning the client so the caller can inspect the
// credential it was issued.
//
// A rejected phone hangs up, and modelling that is load-bearing rather than
// tidiness: the relay holds the pairing slot's bind until the client
// disconnects (internal/mux/pairing.go:207 pair_busy, released by
// unbindLocked). Leaving failed attempts connected would wedge the slot for the
// rest of the test and report a relay-level pair_busy as if the passphrase
// itself had been rejected.
func gatePhone(t *testing.T, hub *mux.Hub, ref, password string) (*phone.Client, error) {
	t.Helper()
	phA, hubC := mux.NewPipePair(32)
	stop := pump(t, hubC, func(f envelope.Frame) { hub.HandleClient(hubC, f) })
	ph := &phone.Client{Conn: phA}
	err := ph.PairWithPassword(ref, password, "")
	if err != nil {
		close(stop)
		hub.DropConn(hubC)
	} else {
		t.Cleanup(func() { close(stop) })
	}
	return ph, err
}

// TestGateAdmitsTwoPhonesWithOnePassword is the acceptance test for the whole
// feature: the operator sets one passphrase, and two separate phones each type
// it and get in. It is deliberately sequential because the relay admits only
// one PairingWS at a time (workers .../room/pairing.ts pair_busy, and
// internal/mux/pairing.go's found.bind guard), so "several phones" in practice
// means several phones one after another, not simultaneously.
//
// The two things that would silently break the product are asserted here:
// the second phone must still be able to pair (the gate must survive the first
// success), and the two phones must receive different credentials (the shared
// passphrase must never become shared key material).
func TestGateAdmitsTwoPhonesWithOnePassword(t *testing.T) {
	eng, hub, stopD, stopE := gateSetup(t)
	defer close(stopD)
	defer close(stopE)

	const password = "correct-horse-battery-staple"
	if _, err := eng.SetGatePassword(password); err != nil {
		t.Fatal("set gate password", err)
	}
	first, err := eng.OpenPasswordGate()
	if err != nil {
		t.Fatal("open gate", err)
	}
	time.Sleep(150 * time.Millisecond)

	phoneA, err := gatePhone(t, hub, first.Ref, password)
	if err != nil {
		t.Fatal("first phone pair", err)
	}
	time.Sleep(80 * time.Millisecond)
	if !eng.HasDevice(phoneA.DeviceID) {
		t.Fatal("first device was not persisted")
	}

	// No reopen here on purpose. The operator set one passphrase and walked
	// away; the second phone has to work with nobody at the keyboard, which is
	// the whole point of a persistent gate. The daemon republishes the slot
	// itself after each completed pairing.
	time.Sleep(400 * time.Millisecond)

	eng.mu.Lock()
	gateRef := ""
	if eng.pair != nil && eng.pair.persistent && !eng.pair.closed {
		gateRef = eng.pair.ref
	}
	eng.mu.Unlock()
	if gateRef == "" {
		t.Fatal("gate was not republished after the first pairing; only one phone could ever log in")
	}
	if gateRef != first.Ref {
		t.Fatalf("gate ref changed after reopen: %q then %q", first.Ref, gateRef)
	}

	phoneB, err := gatePhone(t, hub, gateRef, password)
	if err != nil {
		t.Fatal("second phone pair", err)
	}
	time.Sleep(80 * time.Millisecond)
	if !eng.HasDevice(phoneB.DeviceID) {
		t.Fatal("second device was not persisted")
	}

	if phoneA.DeviceID == phoneB.DeviceID {
		t.Fatalf("both phones received the same device_id %q", phoneA.DeviceID)
	}
	if string(phoneA.PSK) == string(phoneB.PSK) {
		t.Fatal("both phones received the same PSK; the passphrase leaked into key material")
	}
	if len(phoneB.PSK) != 32 {
		t.Fatalf("second phone PSK length = %d, want 32", len(phoneB.PSK))
	}
}

// TestGateResumeWorksAfterPasswordPairing closes the loop the product actually
// needs: after typing the passphrase once, the phone reconnects through the
// resume path with no passphrase at all.
func TestGateResumeWorksAfterPasswordPairing(t *testing.T) {
	eng, hub, stopD, stopE := gateSetup(t)
	defer close(stopD)
	defer close(stopE)

	const password = "another-long-passphrase"
	if _, err := eng.SetGatePassword(password); err != nil {
		t.Fatal(err)
	}
	status, err := eng.OpenPasswordGate()
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(150 * time.Millisecond)

	ph, err := gatePhone(t, hub, status.Ref, password)
	if err != nil {
		t.Fatal("pair", err)
	}
	time.Sleep(80 * time.Millisecond)

	resumeA, hubC := mux.NewPipePair(32)
	stopC := pump(t, hubC, func(f envelope.Frame) { hub.HandleClient(hubC, f) })
	defer close(stopC)
	resumed := &phone.Client{Conn: resumeA, DeviceID: ph.DeviceID, PSK: ph.PSK, DaemonPK: ph.DaemonPK}
	if err := resumed.Resume(eng.DaemonID); err != nil {
		t.Fatal("resume after password pairing", err)
	}
	time.Sleep(30 * time.Millisecond)
	if _, err := resumed.RPC("Ping", map[string]any{"t_ms": 7}); err != nil {
		t.Fatal("ping over resumed session", err)
	}
}

// TestGateRejectsWrongPasswordWithoutBurning covers the denial-of-service risk
// that a persistent gate introduces. A one-use code is destroyed after three
// bad proofs, which is correct for a code but fatal for a gate: a stranger
// guessing wrong would lock out the legitimate owner. Three failures must leave
// the gate usable.
func TestGateRejectsWrongPasswordWithoutBurning(t *testing.T) {
	eng, hub, stopD, stopE := gateSetup(t)
	defer close(stopD)
	defer close(stopE)

	const password = "the-real-passphrase"
	if _, err := eng.SetGatePassword(password); err != nil {
		t.Fatal(err)
	}
	status, err := eng.OpenPasswordGate()
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(150 * time.Millisecond)

	for attempt := range 3 {
		if _, err := gatePhone(t, hub, status.Ref, "wrong-passphrase-here"); err == nil {
			t.Fatalf("attempt %d: wrong passphrase was accepted", attempt+1)
		}
		time.Sleep(60 * time.Millisecond)
	}

	eng.mu.Lock()
	alive := eng.pair != nil && !eng.pair.closed && eng.pair.persistent
	eng.mu.Unlock()
	if !alive {
		t.Fatal("three wrong guesses destroyed the persistent gate; anyone could lock the owner out")
	}

	// The legitimate owner must still get in on the very next try.
	reopened, err := eng.OpenPasswordGate()
	if err != nil {
		t.Fatal("reopen after failures", err)
	}
	time.Sleep(150 * time.Millisecond)
	ph, err := gatePhone(t, hub, reopened.Ref, password)
	if err != nil {
		t.Fatal("correct passphrase rejected after earlier failures", err)
	}
	time.Sleep(80 * time.Millisecond)
	if !eng.HasDevice(ph.DeviceID) {
		t.Fatal("device from correct passphrase was not persisted")
	}
}

// TestGateSurvivesDaemonRestart proves the stored verifier is what makes the
// passphrase durable. A fresh Engine reading the same state directory must
// derive an identical record, or every phone would be locked out by a restart.
func TestGateSurvivesDaemonRestart(t *testing.T) {
	dir := t.TempDir()
	store, err := state.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	const password = "survives-a-restart-fine"

	engA, _ := mux.NewPipePair(4)
	first := NewEngine(nil, engA, runtime.NewFake())
	first.Store = store
	first.DaemonID = "d_0123456789abcdef0123"
	saved, err := first.SetGatePassword(password)
	if err != nil {
		t.Fatal(err)
	}

	reopened, err := state.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	engB, _ := mux.NewPipePair(4)
	second := NewEngine(nil, engB, runtime.NewFake())
	second.Store = reopened
	second.DaemonID = first.DaemonID

	loaded, found, err := second.LoadGate()
	if err != nil || !found {
		t.Fatalf("gate not readable after restart: found=%t err=%v", found, err)
	}
	if loaded.PairRefHex != saved.PairRefHex {
		t.Fatalf("pair_ref drifted across restart: %q then %q", saved.PairRefHex, loaded.PairRefHex)
	}
	// Re-deriving from the passphrase under the stored ref must reproduce the
	// persisted verifier exactly; otherwise the phone's proof would not match.
	rederived := second.gateRecord(password, loaded.PairRefHex)
	if rederived.W0.Text(16) != loaded.RecordW0Hex || rederived.W1.Text(16) != loaded.RecordW1Hex {
		t.Fatal("verifier re-derived after restart does not match the stored record")
	}
}
