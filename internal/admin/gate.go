package admin

import (
	"encoding/json"
	"errors"
	"net"
	"time"
)

// deriveGateTimeout bounds a gate.set round trip. Setting a passphrase runs
// Argon2id (3 passes over 64 MiB, internal/crypto/spake2plus/spake.go:40) and
// then republishes the slot, which on mux v2 waits for the relay's PAIR_OPEN
// ack. The default adminTimeout is too tight for that on a loaded machine.
const deriveGateTimeout = 30 * time.Second

// GateStatus is the operator-visible view of the passphrase gate. It carries no
// passphrase and no verifier: W0/W1/L are exactly what an attacker would need
// to mount an offline guess, so they never cross the socket.
type GateStatus struct {
	Configured bool   `json:"configured"`
	PairRef    string `json:"pair_ref,omitempty"`
	CreatedAt  int64  `json:"created_at,omitempty"`
	UpdatedAt  int64  `json:"updated_at,omitempty"`
}

// GateService is an optional capability, like ProcessService. Keeping it off
// the Service interface means the existing test fakes and any other
// implementation keep compiling unchanged.
type GateService interface {
	GateStatus() (GateStatus, error)
	SetGatePassword(password string) (GateStatus, error)
	ClearGatePassword() error
}

// gateRequest is decoded separately from Request so the passphrase never lands
// in the struct that the rest of the admin surface logs and passes around.
type gateRequest struct {
	Password string `json:"password,omitempty"`
}

func isGateOp(op string) bool {
	return op == "gate.status" || op == "gate.set" || op == "gate.clear"
}

// handleGate answers the gate ops. It returns false for anything else so the
// normal dispatch runs.
//
// The raw request body is re-decoded here rather than widened into Request:
// gate.set carries the operator's passphrase, and a field on Request would put
// it within reach of every other op's handling.
func handleGate(conn net.Conn, svc Service, req Request, body []byte) bool {
	if !isGateOp(req.Op) {
		return false
	}
	gate, ok := svc.(GateService)
	if !ok {
		_ = json.NewEncoder(conn).Encode(errResult(errors.New("unknown_op")))
		return true
	}
	_ = json.NewEncoder(conn).Encode(dispatchGate(gate, req.Op, body))
	return true
}

func dispatchGate(gate GateService, op string, body []byte) Response {
	switch op {
	case "gate.status":
		status, err := gate.GateStatus()
		if err != nil {
			return errResult(err)
		}
		return okResult(status)
	case "gate.set":
		var payload gateRequest
		if len(body) > 0 && json.Unmarshal(body, &payload) != nil {
			return errResult(errors.New("bad_request"))
		}
		if payload.Password == "" {
			return errResult(errors.New("password required"))
		}
		status, err := gate.SetGatePassword(payload.Password)
		if err != nil {
			return errResult(err)
		}
		return okResult(status)
	case "gate.clear":
		if err := gate.ClearGatePassword(); err != nil {
			return errResult(err)
		}
		return okResult(map[string]any{"ok": true})
	default:
		return errResult(errors.New("unknown_op"))
	}
}
