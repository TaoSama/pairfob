package daemon

import (
	"os"
	"strconv"
	"strings"
	"testing"
	"unicode"
)

// FORK: password-gate — pins the whole trim set, not a sample of it.
//
// gate_normalize_test.go covers the code points where the two plausible trim
// rules disagree, which is the right set to reason about by hand. What it
// cannot catch is drift in the parts nobody thought to list: the PWA's
// GO_SPACE (pwa/src/lib/pairing-password.ts) is a hand-transcribed copy of
// Go's unicode.IsSpace table, and a copy of a table is only correct until one
// end is edited. The failure is silent and total -- a passphrase that trims
// differently on the two ends derives a different Argon2id record, and every
// phone that already knows the passphrase is told "wrong password".
//
// So this asserts the contract as a set: exactly these code points trim, and
// nothing else in Unicode does. A Go release that adds a space character, or a
// hand edit to either side, fails here with the specific code point named
// rather than as a pairing failure in the field.
// pwaPasswordSource is the other end of the passphrase contract. The path is
// relative because the two ends ship from one repository; if the PWA ever moves
// out, this test should fail loudly rather than quietly stop checking anything.
const pwaPasswordSource = "../../pwa/src/lib/pairing-password.ts"

func readPWAPasswordSource(t *testing.T) string {
	t.Helper()
	src, err := os.ReadFile(pwaPasswordSource)
	if err != nil {
		t.Fatalf("cannot read the PWA end of the contract at %s: %v", pwaPasswordSource, err)
	}
	return string(src)
}

// parsePWATrimSet extracts the code points from the PWA's GO_SPACE literal.
// Line comments are stripped first: the table annotates entries with names like
// "ASCII: \t \n" that would otherwise be scanned for hex.
func parsePWATrimSet(t *testing.T) map[rune]bool {
	t.Helper()
	src := readPWAPasswordSource(t)

	open := strings.Index(src, "const GO_SPACE = new Set([")
	if open < 0 {
		t.Fatalf("GO_SPACE is gone from %s; the trim contract moved and this test no longer checks it", pwaPasswordSource)
	}
	body := src[open:]
	end := strings.Index(body, "])")
	if end < 0 {
		t.Fatalf("GO_SPACE in %s is not a closed literal; cannot read the trim set", pwaPasswordSource)
	}
	body = stripLineComments(body[strings.Index(body, "[")+1 : end])

	set := map[rune]bool{}
	for _, field := range strings.Split(body, ",") {
		field = strings.TrimSpace(field)
		if field == "" {
			continue
		}
		point, err := strconv.ParseUint(strings.TrimPrefix(field, "0x"), 16, 32)
		if err != nil {
			t.Fatalf("GO_SPACE entry %q in %s is not a hex code point: %v", field, pwaPasswordSource, err)
		}
		set[rune(point)] = true
	}
	// An empty or tiny parse would make every assertion below vacuously true,
	// which is the one way this test could fail silently. ASCII space alone is
	// enough of a floor to prove the parser found a real table.
	if !set[' '] || len(set) < 6 {
		t.Fatalf("parsed only %d code points from GO_SPACE; the parser is broken, not the contract", len(set))
	}
	return set
}

func stripLineComments(s string) string {
	var b strings.Builder
	for _, line := range strings.Split(s, "\n") {
		if i := strings.Index(line, "//"); i >= 0 {
			line = line[:i]
		}
		b.WriteString(line)
		b.WriteString("\n")
	}
	return b.String()
}

func TestNormalizePasswordTrimSetIsExactlyGoIsSpace(t *testing.T) {
	// Read out of the shipped PWA source rather than transcribed into this file.
	// A copy here would be a copy of a copy: it could drift from the .ts that
	// actually runs on the phone and this test would keep passing, comparing two
	// stale tables to each other. Parsing the real file is what makes the
	// assertion about the deployed contract instead of about a snapshot of it.
	pwaTrimSet := parsePWATrimSet(t)

	// Every code point Go trims must be one the PWA trims too. Sweeping all of
	// Unicode rather than the table means a Go upgrade that widens IsSpace is
	// caught here instead of by a phone.
	for r := rune(0); r <= unicode.MaxRune; r++ {
		if unicode.IsSpace(r) && !pwaTrimSet[r] {
			t.Fatalf("Go trims U+%04X but the PWA's GO_SPACE does not: a passphrase "+
				"ending in it derives two different records", r)
		}
	}
	for r := range pwaTrimSet {
		if !unicode.IsSpace(r) {
			t.Fatalf("the PWA trims U+%04X but Go keeps it: same divergence, other direction", r)
		}
	}

	// The set assertions above compare tables. This one proves normalizePassword
	// actually applies that table, so the test still means something if the
	// implementation stops using strings.TrimSpace.
	const base = "passphrase-ok"
	for r := range pwaTrimSet {
		got, err := normalizePassword(string(r) + base + string(r))
		if err != nil {
			t.Fatalf("U+%04X: normalizePassword rejected a trimmable passphrase: %v", r, err)
		}
		if got != base {
			t.Fatalf("U+%04X: normalized to %q, want %q", r, got, base)
		}
	}
}

// Control characters are rejected, and the PWA reproduces Go's unicode.IsControl
// as the two Latin-1 ranges [0x00-0x1F] and [0x7F-0x9F]. That equivalence holds
// today but is an assumption about a Unicode category, not a definition of one,
// so it is checked across the whole range rather than trusted.
func TestIsControlIsExactlyTheTwoLatin1Ranges(t *testing.T) {
	// Confirm the PWA still expresses the rule as the two Latin-1 ranges before
	// asserting the equivalence; if it switched to a different test, comparing
	// against these bounds would be checking a rule nobody applies.
	src := readPWAPasswordSource(t)
	const pwaControlTest = "point <= 0x1f || (point >= 0x7f && point <= 0x9f)"
	if !strings.Contains(src, pwaControlTest) {
		t.Fatalf("the PWA no longer rejects control characters with %q; re-derive this equivalence", pwaControlTest)
	}

	for r := rune(0); r <= unicode.MaxRune; r++ {
		inPWARange := r <= 0x1f || (r >= 0x7f && r <= 0x9f)
		if unicode.IsControl(r) != inPWARange {
			t.Fatalf("U+%04X: Go IsControl=%v, PWA range=%v; one end would reject a "+
				"passphrase the other accepts", r, unicode.IsControl(r), inPWARange)
		}
	}
}

// U+FEFF is the one character where the obvious implementation on each end
// disagrees: JavaScript's String.prototype.trim strips it, Go's TrimSpace does
// not. Both ends therefore avoid the built-in trim. If Go ever starts treating
// it as space, the PWA's explicit set would still keep it.
func TestByteOrderMarkIsContentOnBothEnds(t *testing.T) {
	if unicode.IsSpace('\ufeff') {
		t.Fatal("Go now trims U+FEFF; the PWA's GO_SPACE keeps it, so the records would differ")
	}
	const base = "passphrase-ok"
	got, err := normalizePassword(base + "\ufeff")
	if err != nil {
		t.Fatalf("a passphrase ending in U+FEFF was rejected: %v", err)
	}
	if got != base+"\ufeff" {
		t.Fatalf("U+FEFF was altered: got %q", got)
	}
}

// The bounds are UTF-8 byte counts on both ends, and the PWA spells them as
// MIN/MAX_PASSWORD_BYTES. A change to either constant alone silently splits the
// two ends: the phone would refuse to send a passphrase the daemon stored, or
// send one the daemon rejects after the operator already enrolled it.
func TestPasswordBoundsMatchThePWAConstants(t *testing.T) {
	// Read from the shipped source for the same reason as the trim set: a
	// literal here would stop tracking the file that actually runs.
	pwaMin := parsePWAConstant(t, "MIN_PASSWORD_BYTES")
	pwaMax := parsePWAConstant(t, "MAX_PASSWORD_BYTES")
	if minPasswordBytes != pwaMin || maxPasswordBytes != pwaMax {
		t.Fatalf("bounds drifted from the PWA: Go %d..%d, PWA %d..%d",
			minPasswordBytes, maxPasswordBytes, pwaMin, pwaMax)
	}

	// Guard the constants against being read as UTF-16 units or characters.
	// Two CJK characters are 6 UTF-8 bytes but 2 of anything else.
	if _, err := normalizePassword(strings.Repeat("密", 2)); err == nil {
		t.Fatal("a 6-byte passphrase passed the floor; the bound is not counting UTF-8 bytes")
	}
}

// parsePWAConstant reads an exported numeric constant out of the PWA source, so
// the Go bounds are compared against the shipped value rather than a copy.
func parsePWAConstant(t *testing.T, name string) int {
	t.Helper()
	src := readPWAPasswordSource(t)

	marker := "export const " + name + " = "
	i := strings.Index(src, marker)
	if i < 0 {
		t.Fatalf("%s is gone from %s; the length contract moved", name, pwaPasswordSource)
	}
	rest := src[i+len(marker):]
	end := strings.IndexAny(rest, ";\n")
	if end < 0 {
		t.Fatalf("%s in %s is not terminated", name, pwaPasswordSource)
	}
	value, err := strconv.Atoi(strings.TrimSpace(rest[:end]))
	if err != nil {
		t.Fatalf("%s in %s is not a plain number: %v", name, pwaPasswordSource, err)
	}
	return value
}
