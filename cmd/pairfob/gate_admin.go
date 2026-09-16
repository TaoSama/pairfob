package main

import (
	"pairfob/internal/admin"
	"pairfob/internal/state"
)

// gateStatusOf projects the stored gate into the operator-visible shape. The
// verifier fields (W0/W1/L) are deliberately dropped: they are the exact input
// an offline dictionary attack needs, and nothing outside the daemon has a use
// for them.
func gateStatusOf(gate state.Gate, found bool) admin.GateStatus {
	if !found {
		return admin.GateStatus{Configured: false}
	}
	return admin.GateStatus{
		Configured: true,
		PairRef:    gate.PairRefHex,
		CreatedAt:  gate.CreatedAt,
		UpdatedAt:  gate.UpdatedAt,
	}
}

func (a liveAdmin) GateStatus() (admin.GateStatus, error) {
	gate, found, err := a.eng.LoadGate()
	if err != nil {
		return admin.GateStatus{}, err
	}
	return gateStatusOf(gate, found), nil
}

// SetGatePassword stores the verifier and immediately publishes it, so the
// operator can set a passphrase on a running daemon and have a phone use it
// without restarting anything.
func (a liveAdmin) SetGatePassword(password string) (admin.GateStatus, error) {
	gate, err := a.eng.SetGatePassword(password)
	if err != nil {
		return admin.GateStatus{}, err
	}
	if _, err := a.eng.OpenPasswordGate(); err != nil {
		return admin.GateStatus{}, err
	}
	return gateStatusOf(gate, true), nil
}

func (a liveAdmin) ClearGatePassword() error { return a.eng.ClearGatePassword() }
