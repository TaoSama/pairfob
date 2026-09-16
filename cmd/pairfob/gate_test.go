package main

import (
	"bytes"
	"strings"
	"testing"

	"pairfob/internal/daemon"
	"pairfob/internal/mux"
	"pairfob/internal/runtime"
	"pairfob/internal/state"
)

// gateAdminSocket starts a live admin service over an engine with a real store,
// which is what makes gate.set reach the persistence path rather than a fake.
func gateAdminSocket(t *testing.T) (*daemon.Engine, string) {
	t.Helper()
	store, err := state.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	a, _ := mux.NewPipePair(8)
	eng := daemon.NewEngine(nil, a, runtime.NewFake())
	eng.Store = store
	eng.DaemonID = "d_0123456789abcdef0123"
	return eng, startLiveAdmin(t, eng)
}

// TestGateSetRejectsPassphraseAsArgument is the reason the command exists in
// this shape. A passphrase on argv is readable by every process on the box via
// ps and is written into the shell history file, so the CLI must refuse it
// rather than quietly accept a convenient form.
func TestGateSetRejectsPassphraseAsArgument(t *testing.T) {
	_, sock := gateAdminSocket(t)
	err := runCommand([]string{"gate", "set", "hunter2-hunter2"}, sock)
	if err == nil {
		t.Fatal("passphrase passed as an argument was accepted")
	}
	if !strings.Contains(err.Error(), "cannot be passed as an argument") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestGateSetFromStdinPersistsAndOpensTheGate(t *testing.T) {
	eng, sock := gateAdminSocket(t)
	var out bytes.Buffer
	in := strings.NewReader("correct-horse-battery\n")
	if err := gateSetCommand([]string{"--password-stdin"}, sock, in, &out); err != nil {
		t.Fatal(err)
	}
	gate, found, err := eng.LoadGate()
	if err != nil || !found {
		t.Fatalf("gate not persisted: found=%v err=%v", found, err)
	}
	if gate.Mode != state.GateModePassword || gate.PairRefHex == "" {
		t.Fatalf("unexpected gate %+v", gate)
	}
	// Setting a passphrase on a running daemon must publish it too, or the
	// operator would have to restart before any phone could use it.
	if st := eng.PairingStatus(); st.Ref != gate.PairRefHex {
		t.Fatalf("gate was stored but not published: active ref %q, gate ref %q", st.Ref, gate.PairRefHex)
	}
}

// The stored verifier is the exact input an offline dictionary attack needs, so
// no gate command may ever print it or the passphrase.
func TestGateStatusRevealsNoSecret(t *testing.T) {
	eng, sock := gateAdminSocket(t)
	const password = "leak-check-passphrase"
	if _, err := eng.SetGatePassword(password); err != nil {
		t.Fatal(err)
	}
	gate, _, err := eng.LoadGate()
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := gateStatusCommand(sock, &out); err != nil {
		t.Fatal(err)
	}
	printed := out.String()
	if !strings.Contains(printed, gate.PairRefHex) {
		t.Fatalf("status omitted pair_ref: %q", printed)
	}
	for label, secret := range map[string]string{
		"passphrase": password,
		"record_w0":  gate.RecordW0Hex,
		"record_w1":  gate.RecordW1Hex,
		"record_l":   gate.LHex,
	} {
		if strings.Contains(printed, secret) {
			t.Fatalf("gate status leaked %s: %q", label, printed)
		}
	}
}

func TestGateStatusReportsUnconfigured(t *testing.T) {
	_, sock := gateAdminSocket(t)
	var out bytes.Buffer
	if err := gateStatusCommand(sock, &out); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "No pairing passphrase") {
		t.Fatalf("unexpected status: %q", out.String())
	}
}

func TestGateClearRemovesTheStoredGate(t *testing.T) {
	eng, sock := gateAdminSocket(t)
	if _, err := eng.SetGatePassword("to-be-removed-soon"); err != nil {
		t.Fatal(err)
	}
	if err := runCommand([]string{"gate", "clear"}, sock); err != nil {
		t.Fatal(err)
	}
	if _, found, err := eng.LoadGate(); err != nil || found {
		t.Fatalf("gate survived clear: found=%v err=%v", found, err)
	}
}

// A non-terminal stdin without --password-stdin must fail loudly. Falling back
// to a plain read would echo the passphrase into the scrollback of whatever
// invoked it.
func TestGateSetWithoutTerminalRefusesToPrompt(t *testing.T) {
	_, sock := gateAdminSocket(t)
	var out bytes.Buffer
	err := gateSetCommand(nil, sock, strings.NewReader("whatever-goes-here\n"), &out)
	if err == nil {
		t.Fatal("prompted without a terminal")
	}
	if !strings.Contains(err.Error(), "--password-stdin") {
		t.Fatalf("error should point at the scriptable path: %v", err)
	}
}

func TestGateSetRejectsEmptyStdin(t *testing.T) {
	_, sock := gateAdminSocket(t)
	var out bytes.Buffer
	if err := gateSetCommand([]string{"--password-stdin"}, sock, strings.NewReader(""), &out); err == nil {
		t.Fatal("empty stdin accepted")
	}
}

// A short passphrase must be refused by the daemon, not silently stored. The
// CLI deliberately does not duplicate the length rule, so this also proves the
// daemon's verdict reaches the operator.
func TestGateSetSurfacesDaemonRejection(t *testing.T) {
	eng, sock := gateAdminSocket(t)
	var out bytes.Buffer
	err := gateSetCommand([]string{"--password-stdin"}, sock, strings.NewReader("short\n"), &out)
	if err == nil {
		t.Fatal("short passphrase accepted")
	}
	if _, found, loadErr := eng.LoadGate(); loadErr != nil || found {
		t.Fatalf("rejected passphrase was stored: found=%v err=%v", found, loadErr)
	}
}

func TestGateUsageErrors(t *testing.T) {
	_, sock := gateAdminSocket(t)
	for _, args := range [][]string{
		{"gate"},
		{"gate", "bogus"},
		{"gate", "status", "extra"},
		{"gate", "clear", "extra"},
	} {
		if err := runCommand(args, sock); err == nil {
			t.Fatalf("%v was accepted", args)
		}
	}
}

// A gate on a daemon that never registered has no daemon_id to bind the
// Argon2id salt to, so setting one must fail rather than store a record that
// no phone could ever reproduce.
func TestGateSetRequiresRegistration(t *testing.T) {
	store, err := state.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	a, _ := mux.NewPipePair(8)
	eng := daemon.NewEngine(nil, a, runtime.NewFake())
	eng.Store = store
	sock := startLiveAdmin(t, eng)

	var out bytes.Buffer
	if err := gateSetCommand([]string{"--password-stdin"}, sock, strings.NewReader("unregistered-daemon\n"), &out); err == nil {
		t.Fatal("gate was set before the daemon registered")
	}
	if _, found, loadErr := eng.LoadGate(); loadErr != nil || found {
		t.Fatalf("gate stored without a daemon_id: found=%v err=%v", found, loadErr)
	}
}
