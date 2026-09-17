package state

import (
	"errors"
	"math/big"
	"regexp"
)

const gateFile = "gate.json"

// GateModePassword marks a gate whose verifier was derived from an operator
// passphrase that stays reusable across devices.
const GateModePassword = "password"

// Gate holds the SPAKE2+ augmented verifier for the persistent login gate. It
// never stores the passphrase or any reversible function of it: W0, W1 and L
// are the same public record an attacker would need to run an online guess
// against. PairRefHex must stay stable for the life of the gate because the
// Argon2id salt binds the record to daemon_id and pair_ref, so a rotated
// pair_ref would silently invalidate every future verification.
type Gate struct {
	Mode        string `json:"mode"`
	PairRefHex  string `json:"pair_ref"`
	RecordW0Hex string `json:"record_w0"`
	RecordW1Hex string `json:"record_w1"`
	LHex        string `json:"record_l"`
	CreatedAt   int64  `json:"created_at"`
	UpdatedAt   int64  `json:"updated_at,omitempty"`
}

var (
	// canon.PairRefHex hex-encodes a 16-byte pair_ref, so the stored form is
	// always 32 lowercase hex characters.
	gatePairRefPattern = regexp.MustCompile(`^[0-9a-f]{32}$`)
	// P-256 scalars fit in 32 bytes; big.Int hex has no fixed width.
	gateScalarPattern = regexp.MustCompile(`^[0-9a-f]{1,64}$`)
	// Uncompressed P-256 point: 0x04 tag followed by the 64-byte affine pair.
	gateLPattern = regexp.MustCompile(`^04[0-9a-f]{128}$`)
)

// LoadGate returns the stored gate. A missing file is not an error: the daemon
// simply has no password gate configured yet.
func (s *Store) LoadGate() (Gate, bool, error) {
	var gate Gate
	ok, err := s.loadOptional(gateFile, &gate)
	if err != nil || !ok {
		return Gate{}, false, err
	}
	if err := validateGate(gate); err != nil {
		return Gate{}, false, err
	}
	return gate, true, nil
}

func (s *Store) SaveGate(gate Gate) error {
	if err := validateGate(gate); err != nil {
		return err
	}
	return atomicJSON(s.path(gateFile), gate)
}

func (s *Store) ClearGate() error { return s.clearOptional(gateFile) }

func validateGate(gate Gate) error {
	if gate.Mode != GateModePassword {
		return errors.New("gate.json mode must be password")
	}
	if !gatePairRefPattern.MatchString(gate.PairRefHex) {
		return errors.New("gate.json pair_ref must be 32 lowercase hex characters")
	}
	if !gateScalarPattern.MatchString(gate.RecordW0Hex) || !gateScalarPattern.MatchString(gate.RecordW1Hex) {
		return errors.New("gate.json contains an invalid SPAKE2+ scalar")
	}
	if isZeroHexScalar(gate.RecordW0Hex) || isZeroHexScalar(gate.RecordW1Hex) {
		return errors.New("gate.json contains a zero SPAKE2+ scalar")
	}
	if !gateLPattern.MatchString(gate.LHex) {
		return errors.New("gate.json record_l must be an uncompressed P-256 point")
	}
	if gate.CreatedAt <= 0 {
		return errors.New("gate.json created_at must be positive")
	}
	if gate.UpdatedAt != 0 && gate.UpdatedAt < gate.CreatedAt {
		return errors.New("gate.json updated_at predates created_at")
	}
	return nil
}

func isZeroHexScalar(hexScalar string) bool {
	n, ok := new(big.Int).SetString(hexScalar, 16)
	return !ok || n.Sign() == 0
}
