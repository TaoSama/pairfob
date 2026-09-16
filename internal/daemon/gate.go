package daemon

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"pairfob/internal/crypto/canon"
	"pairfob/internal/crypto/spake2plus"
	"pairfob/internal/envelope"
	"pairfob/internal/state"
)

const (
	// A passphrase is typed on a phone keyboard, so the floor trades a little
	// entropy for usability and leans on the gate throttle for the rest.
	minPasswordBytes = 8
	// The ceiling exists so a hostile client cannot force an unbounded Argon2id
	// input through the admin socket.
	maxPasswordBytes = 128
)

// normalizePassword accepts any printable UTF-8 passphrase. Unlike a pairing
// code it is not folded into an alphabet: the operator typed these exact bytes
// and the phone must derive the identical SPAKE2+ record from them. Only outer
// whitespace is trimmed, because a trailing space from a paste or an on-screen
// keyboard is invisible and would otherwise fail the handshake with no clue.
//
// The trim set is unicode.IsSpace and must stay byte-identical to the PWA's
// trimOuterSpace (pwa/src/lib/pairing-password.ts). An ASCII-only trim is not
// enough in practice: a CJK IME emits U+3000 and macOS Option+Space emits
// U+00A0, so those arrive at the edges of a real paste. If the two ends
// disagreed on even one code point, the same typed passphrase would derive two
// different records and fail as a confirm mismatch indistinguishable from a
// wrong passphrase. U+FEFF is deliberately kept by both ends -- JavaScript's
// String.prototype.trim would strip it and Go would not, so neither end uses it.
func normalizePassword(password string) (string, error) {
	norm := strings.TrimSpace(password)
	if !utf8.ValidString(norm) {
		return "", errors.New("pairing password must be valid UTF-8")
	}
	if n := len(norm); n < minPasswordBytes || n > maxPasswordBytes {
		return "", errors.New("pairing password must be 8-128 bytes")
	}
	if strings.IndexFunc(norm, unicode.IsControl) != -1 {
		return "", errors.New("pairing password must not contain control characters")
	}
	return norm, nil
}

// gateRecord derives the SPAKE2+ verifier for a passphrase against a fixed
// pair_ref. The ref is part of the Argon2id salt, so it must be the stored one
// rather than a fresh random value: rotating it would invalidate the gate for
// every phone that already knows the passphrase.
func (e *Engine) gateRecord(password, ref string) spake2plus.Record {
	return spake2plus.DeriveRecord(password, e.DaemonID, ref)
}

// LoadGate returns the persisted gate verifier, if the operator configured one.
func (e *Engine) LoadGate() (state.Gate, bool, error) {
	if e.Store == nil {
		return state.Gate{}, false, nil
	}
	return e.Store.LoadGate()
}

// SetGatePassword derives and persists a verifier for password. An existing
// gate keeps its pair_ref so previously-taught phones stay compatible only when
// the passphrase is unchanged; a new passphrase deliberately produces a new
// record under the same ref, which invalidates the old one.
func (e *Engine) SetGatePassword(password string) (state.Gate, error) {
	if e.Store == nil {
		return state.Gate{}, errors.New("a persistent state store is required to set a pairing password")
	}
	if e.DaemonID == "" {
		return state.Gate{}, errors.New("daemon must register before a pairing password can be set")
	}
	norm, err := normalizePassword(password)
	if err != nil {
		return state.Gate{}, err
	}
	existing, found, err := e.Store.LoadGate()
	if err != nil {
		return state.Gate{}, err
	}
	ref := existing.PairRefHex
	now := time.Now().Unix()
	created := existing.CreatedAt
	if !found || ref == "" {
		ref, err = newGateRef()
		if err != nil {
			return state.Gate{}, err
		}
		created = now
	}
	record := e.gateRecord(norm, ref)
	gate := state.Gate{
		Mode:        state.GateModePassword,
		PairRefHex:  ref,
		RecordW0Hex: record.W0.Text(16),
		RecordW1Hex: record.W1.Text(16),
		LHex:        hex.EncodeToString(record.L),
		CreatedAt:   created,
	}
	if found {
		gate.UpdatedAt = now
	}
	if err := e.Store.SaveGate(gate); err != nil {
		return state.Gate{}, err
	}
	e.audit("gate_password_set", map[string]any{"pair_ref": ref, "rotated": found})
	return gate, nil
}

// ClearGatePassword removes the gate and burns any slot currently serving it,
// so a phone mid-handshake cannot complete against a revoked passphrase.
func (e *Engine) ClearGatePassword() error {
	if e.Store == nil {
		return errors.New("a persistent state store is required to clear a pairing password")
	}
	if err := e.Store.ClearGate(); err != nil {
		return err
	}
	e.mu.Lock()
	ref := ""
	if e.pair != nil && e.pair.persistent {
		ref = e.burnPairLocked(e.pair)
	}
	e.mu.Unlock()
	if ref != "" {
		e.sendPairClose(ref)
	}
	e.audit("gate_password_cleared", nil)
	return nil
}

func newGateRef() (string, error) {
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return canon.PairRefHex(raw), nil
}

// OpenPasswordGate publishes the stored passphrase verifier as the active
// pairing slot.
//
// It differs from OpenPairing in three ways, and each difference is what makes
// a persistent login gate possible:
//
//   - the pair_ref and the record come from disk instead of being minted, so
//     the same passphrase keeps working across daemon restarts;
//   - the slot is marked persistent, which suppresses the operator-approval
//     wait: proving knowledge of the passphrase is the authorization;
//   - failures do not burn the slot, because a burned gate would let anyone
//     lock every phone out with three wrong guesses.
func (e *Engine) OpenPasswordGate() (PairingStatus, error) {
	e.pairOpenMu.Lock()
	defer e.pairOpenMu.Unlock()
	if e.DaemonID == "" {
		return PairingStatus{}, errors.New("daemon must register before pairing")
	}
	gate, found, err := e.LoadGate()
	if err != nil {
		return PairingStatus{}, err
	}
	if !found {
		return PairingStatus{}, errors.New("no pairing password is configured")
	}
	record, err := gateSpakeRecord(gate)
	if err != nil {
		return PairingStatus{}, err
	}
	ref := gate.PairRefHex
	ttl := e.pairingTTL()
	pair := &pairingSlot{
		ref: ref, record: record, persistent: true,
		admitCh: make(chan struct{}), readyCh: make(chan struct{}),
		expiresAt: time.Now().Add(ttl),
	}
	if e.muxVersion() == 2 {
		pair.openWait = make(chan error, 1)
	}

	e.mu.Lock()
	oldRef := e.burnPairLocked(e.pair)
	e.pair = pair
	e.mu.Unlock()
	if oldRef != "" && oldRef != ref {
		e.sendPairClose(oldRef)
	}
	if err := e.Conn.Send(envelope.JSON(envelope.TypPAIR_OPEN, [16]byte{}, e.pairOpenPayload(ref))); err != nil {
		e.mu.Lock()
		if e.pair != nil && e.pair.ref == ref {
			e.burnPairLocked(e.pair)
		}
		e.mu.Unlock()
		return PairingStatus{}, err
	}
	if e.muxVersion() == 2 {
		if err := e.waitPairOpenAck(pair); err != nil {
			return PairingStatus{}, err
		}
	}
	expiry := time.AfterFunc(ttl, func() { e.expirePairing(pair) })
	e.mu.Lock()
	if e.pair == pair && !pair.closed {
		pair.expiry = expiry
	} else {
		expiry.Stop()
	}
	loc := ""
	if pair.locReady {
		loc = pair.loc
	}
	expires := pair.expiresAt
	devices := e.pairedCountLocked()
	e.mu.Unlock()
	e.audit("gate_open", map[string]any{"pair_ref": ref})
	// The offer URL deliberately carries no code: the phone supplies the
	// passphrase, and embedding it would defeat the point of the gate.
	offer, err := e.pairingOffer(ref, "", loc)
	if err != nil {
		return PairingStatus{Ref: ref, Loc: loc, Devices: devices, ExpiresAt: expires}, nil
	}
	return PairingStatus{Ref: ref, URL: offer.URL, Loc: loc, Devices: devices, ExpiresAt: expires}, nil
}

// reopenPasswordGate republishes the gate after its slot was consumed or
// expired, so the next phone finds something to attach to.
//
// It runs asynchronously on purpose. Its callers sit on the frame-handling
// path, and OpenPasswordGate waits for the relay's PAIR_OPEN ack — an ack that
// arrives through that very path. Calling it inline would deadlock the daemon.
func (e *Engine) reopenPasswordGate() {
	go func() {
		if _, _, err := e.LoadGate(); err != nil {
			e.audit("gate_reopen_failed", map[string]any{"error": err.Error()})
			return
		}
		if _, err := e.OpenPasswordGate(); err != nil {
			// A cleared gate is the expected way for this to fail, so it is
			// recorded rather than retried: there is nothing left to publish.
			e.audit("gate_reopen_failed", map[string]any{"error": err.Error()})
		}
	}()
}

// gateSelfAdmits reports whether this slot authorizes itself. Only a
// persistent gate slot does, and only once the SPAKE2+ confirmation has
// actually verified — the caller must never treat "it is a gate" alone as
// authorization, or an unauthenticated attach would be admitted.
func (e *Engine) gateSelfAdmits(pair *pairingSlot) bool {
	if pair == nil {
		return false
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	return pair.persistent && pair.confirmVerified && !pair.closed && e.pair == pair
}

func gateSpakeRecord(gate state.Gate) (spake2plus.Record, error) {
	l, err := hex.DecodeString(gate.LHex)
	if err != nil || len(l) != 65 || l[0] != 4 {
		return spake2plus.Record{}, errors.New("gate record contains an invalid P-256 point")
	}
	w0 := spake2plus.ScalarFromHex(gate.RecordW0Hex)
	w1 := spake2plus.ScalarFromHex(gate.RecordW1Hex)
	if w0 == nil || w1 == nil || w0.Sign() == 0 || w1.Sign() == 0 {
		return spake2plus.Record{}, errors.New("gate record contains an invalid SPAKE2+ scalar")
	}
	return spake2plus.Record{W0: w0, W1: w1, L: l}, nil
}

const (
	// Failures tolerated in the window before the backoff starts. A person who
	// mistypes a passphrase twice should not be made to wait.
	gateFreeAttempts = 3
	gateWindow       = time.Minute
	gateCooldownBase = time.Second
	// The ceiling keeps a sustained attack expensive without ever making the
	// gate permanently unusable for the operator.
	gateCooldownMax = time.Minute
)

// gateCooldown is the wait imposed after `failures` bad proofs in the window.
func gateCooldown(failures int) time.Duration {
	over := failures - gateFreeAttempts
	if over <= 0 {
		return 0
	}
	if over > 20 {
		return gateCooldownMax
	}
	wait := gateCooldownBase << uint(over-1)
	if wait > gateCooldownMax {
		return gateCooldownMax
	}
	return wait
}

func (e *Engine) pruneGateFailuresLocked(now time.Time) {
	cutoff := now.Add(-gateWindow)
	i := 0
	for i < len(e.gateFailures) && e.gateFailures[i].Before(cutoff) {
		i++
	}
	e.gateFailures = append([]time.Time(nil), e.gateFailures[i:]...)
}

// noteGateFailureLocked records a rejected proof and extends the cooldown.
// Success is deliberately not recorded: the daemon cannot tell an operator's
// phone from an attacker who guessed right, so letting a success clear the
// ledger would hand out a free reset from the backoff.
func (e *Engine) noteGateFailureLocked(now time.Time) {
	e.pruneGateFailuresLocked(now)
	e.gateFailures = append(e.gateFailures, now)
	if wait := gateCooldown(len(e.gateFailures)); wait > 0 {
		e.gateCooldownUntil = now.Add(wait)
	}
}

// refundGateAttemptLocked drops the most recent charge after a proof turns out
// to be correct. Attempts are billed optimistically when the exchange starts,
// because by the time the daemon has answered with confirm_v the guess is
// already spent whether or not the peer bothers to confirm. Only a verified
// confirm distinguishes the owner from a guesser, so only it earns the refund.
func (e *Engine) refundGateAttemptLocked() {
	if n := len(e.gateFailures); n > 0 {
		e.gateFailures = e.gateFailures[:n-1]
	}
	if wait := gateCooldown(len(e.gateFailures)); wait == 0 {
		e.gateCooldownUntil = time.Time{}
	}
}

// allowGateAttemptLocked reports whether a new proof against the gate may be
// evaluated now. It is read-only: attempts refused during a cooldown are not
// counted, so flooding cannot extend the block it is already serving.
func (e *Engine) allowGateAttemptLocked(now time.Time) bool {
	e.pruneGateFailuresLocked(now)
	if len(e.gateFailures) == 0 {
		e.gateCooldownUntil = time.Time{}
		return true
	}
	return !now.Before(e.gateCooldownUntil)
}
