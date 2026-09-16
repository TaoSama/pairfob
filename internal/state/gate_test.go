package state

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// validGate builds a record shaped like spake2plus.DeriveRecord output: two
// non-zero P-256 scalars and an uncompressed point.
func validGate() Gate {
	return Gate{
		Mode:        GateModePassword,
		PairRefHex:  strings.Repeat("ab", 16),
		RecordW0Hex: strings.Repeat("3c", 32),
		RecordW1Hex: strings.Repeat("7d", 32),
		LHex:        "04" + strings.Repeat("5e", 64),
		CreatedAt:   1757000000,
	}
}

func TestGateRoundTripAndFileMode(t *testing.T) {
	dir := t.TempDir()
	store, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	want := validGate()
	want.UpdatedAt = want.CreatedAt + 60
	if err := store.SaveGate(want); err != nil {
		t.Fatal(err)
	}
	got, ok, err := store.LoadGate()
	if err != nil || !ok {
		t.Fatalf("LoadGate ok=%v err=%v", ok, err)
	}
	if got != want {
		t.Fatalf("gate=%+v want %+v", got, want)
	}
	info, err := os.Stat(filepath.Join(dir, "gate.json"))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("gate.json mode=%o want 600", info.Mode().Perm())
	}
}

// The daemon reads gate.json back by JSON tag, so the on-disk key names are
// part of the contract rather than an implementation detail.
func TestGateJSONFieldNames(t *testing.T) {
	store, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SaveGate(validGate()); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(store.path("gate.json"))
	if err != nil {
		t.Fatal(err)
	}
	var raw map[string]any
	if err := json.Unmarshal(b, &raw); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"mode", "pair_ref", "record_w0", "record_w1", "record_l", "created_at"} {
		if _, exists := raw[key]; !exists {
			t.Fatalf("gate.json is missing key %q, got %v", key, raw)
		}
	}
	if _, exists := raw["updated_at"]; exists {
		t.Fatal("zero updated_at should be omitted")
	}
	// The passphrase must never reach disk in any form.
	if strings.Contains(string(b), "password_hash") {
		t.Fatal("gate.json leaked a passphrase field")
	}
}

func TestGateLoadMissingFileIsNotAnError(t *testing.T) {
	store, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	gate, ok, err := store.LoadGate()
	if err != nil {
		t.Fatalf("missing gate.json returned err=%v", err)
	}
	if ok {
		t.Fatal("missing gate.json reported as present")
	}
	if gate != (Gate{}) {
		t.Fatalf("missing gate.json returned %+v want zero value", gate)
	}
}

func TestGateSaveRejectsInvalidRecords(t *testing.T) {
	store, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name   string
		mutate func(*Gate)
	}{
		{"empty mode", func(g *Gate) { g.Mode = "" }},
		{"unknown mode", func(g *Gate) { g.Mode = "totp" }},
		{"short pair ref", func(g *Gate) { g.PairRefHex = strings.Repeat("ab", 8) }},
		{"uppercase pair ref", func(g *Gate) { g.PairRefHex = strings.ToUpper(strings.Repeat("ab", 16)) }},
		{"non hex pair ref", func(g *Gate) { g.PairRefHex = strings.Repeat("zz", 16) }},
		{"empty w0", func(g *Gate) { g.RecordW0Hex = "" }},
		{"zero w0", func(g *Gate) { g.RecordW0Hex = strings.Repeat("0", 64) }},
		{"zero w1", func(g *Gate) { g.RecordW1Hex = strings.Repeat("0", 64) }},
		{"oversized w1", func(g *Gate) { g.RecordW1Hex = strings.Repeat("7d", 33) }},
		{"short L", func(g *Gate) { g.LHex = "04" + strings.Repeat("5e", 32) }},
		{"long L", func(g *Gate) { g.LHex = "04" + strings.Repeat("5e", 65) }},
		{"compressed L", func(g *Gate) { g.LHex = "03" + strings.Repeat("5e", 64) }},
		{"zero created at", func(g *Gate) { g.CreatedAt = 0 }},
		{"negative created at", func(g *Gate) { g.CreatedAt = -1 }},
		{"updated before created", func(g *Gate) { g.UpdatedAt = g.CreatedAt - 1 }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			gate := validGate()
			tc.mutate(&gate)
			if err := store.SaveGate(gate); err == nil {
				t.Fatalf("SaveGate accepted %s", tc.name)
			}
			if _, err := os.Stat(store.path("gate.json")); !os.IsNotExist(err) {
				t.Fatalf("rejected gate was written to disk (stat err=%v)", err)
			}
		})
	}
}

// A gate that was valid when written must still be re-validated on load, so a
// tampered file cannot downgrade the verifier.
func TestGateLoadRejectsTamperedFile(t *testing.T) {
	store, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name    string
		content string
	}{
		{"malformed json", `{"mode":`},
		{"mode downgraded", `{"mode":"none","pair_ref":"` + strings.Repeat("ab", 16) +
			`","record_w0":"3c","record_w1":"7d","record_l":"04` + strings.Repeat("5e", 64) + `","created_at":1}`},
		{"truncated L", `{"mode":"password","pair_ref":"` + strings.Repeat("ab", 16) +
			`","record_w0":"3c","record_w1":"7d","record_l":"0405","created_at":1}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := store.SaveGate(validGate()); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(store.path("gate.json"), []byte(tc.content), 0600); err != nil {
				t.Fatal(err)
			}
			gate, ok, err := store.LoadGate()
			if err == nil {
				t.Fatalf("tampered gate accepted: %+v", gate)
			}
			if ok {
				t.Fatal("tampered gate reported as present")
			}
		})
	}
}

func TestGateClear(t *testing.T) {
	store, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := store.ClearGate(); err != nil {
		t.Fatalf("ClearGate on missing file returned %v", err)
	}
	if err := store.SaveGate(validGate()); err != nil {
		t.Fatal(err)
	}
	if err := store.ClearGate(); err != nil {
		t.Fatal(err)
	}
	if _, ok, err := store.LoadGate(); ok || err != nil {
		t.Fatalf("after ClearGate ok=%v err=%v", ok, err)
	}
	if err := store.ClearGate(); err != nil {
		t.Fatalf("second ClearGate returned %v", err)
	}
}

// Re-deriving the verifier for the same passphrase must reuse the stored
// pair_ref, so overwriting an existing gate keeps it addressable.
func TestGateOverwriteKeepsPairRef(t *testing.T) {
	store, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	first := validGate()
	if err := store.SaveGate(first); err != nil {
		t.Fatal(err)
	}
	second := first
	second.RecordW0Hex = strings.Repeat("11", 32)
	second.RecordW1Hex = strings.Repeat("22", 32)
	second.LHex = "04" + strings.Repeat("33", 64)
	second.UpdatedAt = first.CreatedAt + 3600
	if err := store.SaveGate(second); err != nil {
		t.Fatal(err)
	}
	got, ok, err := store.LoadGate()
	if err != nil || !ok {
		t.Fatalf("LoadGate ok=%v err=%v", ok, err)
	}
	if got != second {
		t.Fatalf("gate=%+v want %+v", got, second)
	}
	if got.PairRefHex != first.PairRefHex {
		t.Fatal("pair_ref changed across rotation")
	}
}
