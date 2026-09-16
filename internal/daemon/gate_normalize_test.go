package daemon

import (
	"testing"
)

// The passphrase is the SPAKE2+ `s` value, so the daemon and the PWA must
// produce byte-identical strings from the same keystrokes or DeriveRecord
// yields two different verifiers and the phone is told "wrong password" with
// nothing left to debug. These cases are the exact code points where the two
// plausible trim rules disagree, and each one is reachable from a real phone:
// a CJK IME emits U+3000, macOS Option+Space emits U+00A0, and a paste out of a
// rich-text field can carry U+2002 or U+0085.
//
// The mirror on the other end is trimOuterSpace in pwa/src/lib/pairing-password.ts
// and the table in its test file. Changing either side alone locks out every
// phone that already knows the passphrase, so the two must move together.
func TestNormalizePasswordMatchesPWATrimContract(t *testing.T) {
	const base = "passphrase-ok"

	trimmed := []struct{ name, input string }{
		{"ascii space", base + " "},
		{"tab", base + "\t"},
		{"newline", "\n" + base},
		{"no-break space U+00A0", base + "\u00a0"},
		{"next line U+0085", base + "\u0085"},
		{"ogham space U+1680", base + "\u1680"},
		{"en space U+2002", base + "\u2002"},
		{"hair space U+200A", base + "\u200a"},
		{"line separator U+2028", base + "\u2028"},
		{"narrow nbsp U+202F", base + "\u202f"},
		{"ideographic space U+3000", base + "\u3000"},
		{"both ends", "\u3000" + base + "\u00a0"},
	}
	for _, tc := range trimmed {
		got, err := normalizePassword(tc.input)
		if err != nil {
			t.Fatalf("%s: unexpected error: %v", tc.name, err)
		}
		if got != base {
			t.Fatalf("%s: normalized to %q, want %q", tc.name, got, base)
		}
	}

	// Kept, not trimmed. Both ends deliberately leave these alone: JavaScript's
	// String.prototype.trim would eat U+FEFF and Go would not, so neither end
	// relies on it, and zero-width characters are content to both.
	kept := []struct{ name, input string }{
		{"byte order mark U+FEFF", base + "\ufeff"},
		{"zero width space U+200B", base + "\u200b"},
	}
	for _, tc := range kept {
		got, err := normalizePassword(tc.input)
		if err != nil {
			t.Fatalf("%s: unexpected error: %v", tc.name, err)
		}
		if got == base {
			t.Fatalf("%s: was trimmed to %q; the PWA keeps it, so the records would differ", tc.name, got)
		}
		if got != tc.input {
			t.Fatalf("%s: normalized to %q, want the input unchanged", tc.name, got)
		}
	}

	// Interior whitespace is part of the secret; a passphrase is not a code.
	interior := "pass word\u00a0here"
	if got, err := normalizePassword(interior); err != nil || got != interior {
		t.Fatalf("interior whitespace altered: got %q err %v", got, err)
	}

	// A passphrase of nothing but blanks trims away and must not pass the floor.
	if _, err := normalizePassword("\u00a0\u3000 \t\n"); err == nil {
		t.Fatal("a passphrase of only whitespace was accepted")
	}
}

// Length is bounded in UTF-8 bytes because that is what Go's len() measures and
// what the PWA's TextEncoder counts. Using UTF-16 units on the phone would let
// a CJK or emoji passphrase pass there and be rejected here.
func TestNormalizePasswordBoundsAreUTF8Bytes(t *testing.T) {
	// Four bytes each, so 32 of them sit exactly on the 128-byte ceiling.
	const emoji = "\U0001F600"

	atCeiling := ""
	for range 32 {
		atCeiling += emoji
	}
	if got, err := normalizePassword(atCeiling); err != nil || len(got) != maxPasswordBytes {
		t.Fatalf("128-byte passphrase rejected: len=%d err=%v", len(got), err)
	}
	if _, err := normalizePassword(atCeiling + emoji); err == nil {
		t.Fatal("132-byte passphrase was accepted past the ceiling")
	}

	// Two CJK characters are 6 bytes: short in Go, but only 2 UTF-16 units.
	if _, err := normalizePassword("\u5bc6\u7801"); err == nil {
		t.Fatal("a 6-byte passphrase was accepted below the floor")
	}
	if _, err := normalizePassword("12345678"); err != nil {
		t.Fatalf("an 8-byte passphrase was rejected at the floor: %v", err)
	}
}

// Control characters are rejected rather than stripped. Stripping would derive
// a record for a passphrase the operator never typed, and the phone applies the
// same rule, so a paste artifact fails the same way on both ends.
func TestNormalizePasswordRejectsControlCharacters(t *testing.T) {
	for _, bad := range []string{
		"has a\x00null byte",
		"inner\nnewline here",
		"delete\x7fchar here",
		"c1\u0085control here",
	} {
		if _, err := normalizePassword(bad); err == nil {
			t.Fatalf("control character accepted in %q", bad)
		}
	}
}
