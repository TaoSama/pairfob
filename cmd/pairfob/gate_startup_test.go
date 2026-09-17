package main

import (
	"strings"
	"testing"

	"pairfob/internal/daemon"
	"pairfob/internal/mux"
	"pairfob/internal/runtime"
	"pairfob/internal/state"
)

func startupEngine(t *testing.T, dir string) *daemon.Engine {
	t.Helper()
	store, err := state.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	a, _ := mux.NewPipePair(8)
	eng := daemon.NewEngine(nil, a, runtime.NewFake())
	eng.Store = store
	eng.DaemonID = "d_0123456789abcdef0123"
	return eng
}

// TestStartupOpensStoredGateWithoutTheEnvVar is the behaviour that makes the
// passphrase worth persisting. Once `pairfob gate set` has run, every later
// start must come up with the gate already published, so opening the page on a
// phone and typing the passphrase is enough. Requiring PAIRFOB_PAIR_PASSWORD to
// be re-exported on each start would mean the stored gate does nothing.
func TestStartupOpensStoredGateWithoutTheEnvVar(t *testing.T) {
	dir := t.TempDir()

	configure := startupEngine(t, dir)
	gate, err := configure.SetGatePassword("set-once-then-restart")
	if err != nil {
		t.Fatal(err)
	}

	// A fresh engine over the same state directory stands in for a restart.
	restarted := startupEngine(t, dir)
	if err := startPairingGate(restarted, "", ""); err != nil {
		t.Fatal(err)
	}
	st := restarted.PairingStatus()
	if st.Ref != gate.PairRefHex {
		t.Fatalf("restart did not republish the stored gate: active ref %q, gate ref %q", st.Ref, gate.PairRefHex)
	}
	// A gate offer must never carry a code; the phone supplies the passphrase.
	if st.Code != "" {
		t.Fatalf("gate offer leaked a pairing code %q", st.Code)
	}
}

// With no gate on disk and no env var, startup must fall through to the normal
// one-use pairing announcement rather than failing or opening nothing.
func TestStartupWithoutGateFallsBackToPairing(t *testing.T) {
	eng := startupEngine(t, t.TempDir())
	if err := startPairingGate(eng, "", ""); err != nil {
		t.Fatal(err)
	}
	if _, found, err := eng.LoadGate(); err != nil || found {
		t.Fatalf("a gate appeared from nowhere: found=%v err=%v", found, err)
	}
	if ref := eng.PairingStatus().Ref; ref != "" {
		t.Fatalf("no passphrase is set, so no gate should be published; got ref %q", ref)
	}
}

// The env var must both store and publish, so a container started with
// PAIRFOB_PAIR_PASSWORD is immediately pairable.
func TestStartupEnvPasswordStoresAndOpens(t *testing.T) {
	eng := startupEngine(t, t.TempDir())
	if err := startPairingGate(eng, "", "from-the-environment"); err != nil {
		t.Fatal(err)
	}
	gate, found, err := eng.LoadGate()
	if err != nil || !found {
		t.Fatalf("env passphrase was not persisted: found=%v err=%v", found, err)
	}
	if ref := eng.PairingStatus().Ref; ref != gate.PairRefHex {
		t.Fatalf("env passphrase stored but not published: %q vs %q", ref, gate.PairRefHex)
	}
}

// The env var rotates an existing gate's record but must keep its pair_ref:
// the ref is part of the Argon2id salt, so changing it would invalidate the
// verifier for every phone that already knows the passphrase.
func TestStartupEnvPasswordKeepsPairRef(t *testing.T) {
	dir := t.TempDir()
	first := startupEngine(t, dir)
	original, err := first.SetGatePassword("the-first-passphrase")
	if err != nil {
		t.Fatal(err)
	}

	second := startupEngine(t, dir)
	if err := startPairingGate(second, "", "a-different-passphrase"); err != nil {
		t.Fatal(err)
	}
	rotated, found, err := second.LoadGate()
	if err != nil || !found {
		t.Fatalf("rotated gate missing: found=%v err=%v", found, err)
	}
	if rotated.PairRefHex != original.PairRefHex {
		t.Fatalf("pair_ref rotated with the passphrase: %q then %q", original.PairRefHex, rotated.PairRefHex)
	}
	if rotated.RecordW0Hex == original.RecordW0Hex {
		t.Fatal("a new passphrase produced the same verifier")
	}
}

// A passphrase the daemon rejects must stop startup rather than leave the
// daemon running with pairing silently unconfigured.
func TestStartupRejectsBadEnvPassword(t *testing.T) {
	eng := startupEngine(t, t.TempDir())
	err := startPairingGate(eng, "", "short")
	if err == nil {
		t.Fatal("daemon started with an invalid pairing passphrase")
	}
	if !strings.Contains(err.Error(), "pairing password") {
		t.Fatalf("unexpected error: %v", err)
	}
}
