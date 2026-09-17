package daemon

//
// pairing_concurrent_test.go drives Engine.Handle directly and shows what the
// single pairing slot does when two routes reach it at once. That is the
// daemon in isolation. It deliberately leaves one question open: can two routes
// reach it at once over the real transport?
//
// This file answers that question empirically rather than by reading
// mux/pairing.go. The two layers give different answers, and conflating them
// would either overstate the defect (claiming a live crossover that the relay
// prevents) or understate it (dismissing a real daemon bug because today's
// relay happens to mask it). Both conclusions are pinned here so a rework that
// changes either layer has to confront the pair.

import (
	"encoding/json"
	"testing"
	"time"

	"pairfob/internal/envelope"
	"pairfob/internal/mux"
	"pairfob/internal/phone"
	"pairfob/internal/runtime"
	"pairfob/internal/state"
)

// relayClient is a raw relay connection: enough of the phone's opening moves to
// reach the attach decision, and no more. phone.Client cannot be used here
// because it treats a relay ERROR as a returned error and hangs up, which
// releases the very bind whose retention is under test.
type relayClient struct {
	conn *mux.Pipe
	hub  *mux.Pipe
	stop chan struct{}
}

func newRelayClient(t *testing.T, hub *mux.Hub) *relayClient {
	t.Helper()
	phA, hubC := mux.NewPipePair(32)
	stop := pump(t, hubC, func(f envelope.Frame) { hub.HandleClient(hubC, f) })
	t.Cleanup(func() {
		select {
		case <-stop:
		default:
			close(stop)
		}
	})
	if err := phA.Send(envelope.JSON(envelope.TypHELLO_CLIENT, [16]byte{}, map[string]any{"v": 1, "protocol": 1})); err != nil {
		t.Fatal("hello:", err)
	}
	return &relayClient{conn: phA, hub: hubC, stop: stop}
}

// attach sends PAIR_ATTACH and returns the relay's verdict frame.
func (c *relayClient) attach(t *testing.T, ref string) envelope.Frame {
	t.Helper()
	body := map[string]any{"v": 1}
	if ref != "" {
		body["pair_ref"] = ref
	}
	if err := c.conn.Send(envelope.JSON(envelope.TypPAIR_ATTACH, [16]byte{}, body)); err != nil {
		t.Fatal("attach:", err)
	}
	f, ok := c.conn.RecvTimeout(2 * time.Second)
	if !ok {
		t.Fatal("relay never answered PAIR_ATTACH")
	}
	return f
}

// errCode extracts the relay's error code, or "" when the frame is not an error.
func errCode(f envelope.Frame) string {
	if f.Typ != envelope.TypERROR {
		return ""
	}
	var body struct {
		Code string `json:"code"`
	}
	if json.Unmarshal(f.Payload, &body) != nil {
		return ""
	}
	return body.Code
}

// relayGateSetup opens a persistent passphrase gate behind a real mux.Hub. The
// gate, not a one-use code, is the case that matters: a one-use slot is
// consumed by design, so asking whether two phones can share it is moot. The
// gate is meant to stay open indefinitely for many phones, which is exactly
// where a relay-level single-attach rule becomes a product constraint.
func relayGateSetup(t *testing.T, password string) (*Engine, *mux.Hub, string) {
	t.Helper()
	store, err := state.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	hub := mux.NewHub("pf_relay_conc")
	engA, hubD := mux.NewPipePair(32)
	eng := NewEngine(hub, engA, runtime.NewFake())
	eng.Store = store
	eng.AutoAdmit = false
	stopD := pump(t, hubD, func(f envelope.Frame) { hub.HandleDaemon(hubD, f) })
	t.Cleanup(func() { close(stopD) })
	if err := eng.Register("pf_relay_conc"); err != nil {
		t.Fatal(err)
	}
	stopE := make(chan struct{})
	go eng.RecvLoop(stopE)
	t.Cleanup(func() { close(stopE) })

	if _, err := eng.SetGatePassword(password); err != nil {
		t.Fatal("set gate password:", err)
	}
	status, err := eng.OpenPasswordGate()
	if err != nil {
		t.Fatal("open gate:", err)
	}
	time.Sleep(150 * time.Millisecond)
	return eng, hub, status.Ref
}

// TestRelayRefusesSecondConcurrentAttach is the layer-(b) measurement. It is
// the reason the crossover described in the handover cannot happen today: the
// second phone is turned away by the relay and never produces a frame the
// daemon's pairing slot could observe.
//
// This is a characterization test, not an endorsement. It pins the masking so
// that anyone removing the guard -- which a per-route rework must do to let two
// phones pair at once -- discovers here that doing so exposes the daemon
// behaviour measured in pairing_concurrent_test.go.
func TestRelayRefusesSecondConcurrentAttach(t *testing.T) {
	eng, hub, ref := relayGateSetup(t, "correct-horse-battery-staple")

	first := newRelayClient(t, hub)
	got := first.attach(t, ref)
	if got.Typ != envelope.TypPAIR_ATTACHED {
		t.Fatalf("first attach was refused: typ=%#x code=%q", got.Typ, errCode(got))
	}

	// The first client stays connected, so its bind is still held. This is the
	// ordinary case: a phone in the middle of a handshake.
	second := newRelayClient(t, hub)
	rejected := second.attach(t, ref)
	if code := errCode(rejected); code != "pair_busy" {
		t.Fatalf("second concurrent attach was not refused with pair_busy: typ=%#x code=%q payload=%s",
			rejected.Typ, code, rejected.Payload)
	}

	// The decisive half: the daemon must not have seen the second phone at all.
	// If the relay had bound it, the slot would carry the second route.
	eng.mu.Lock()
	routeID := [16]byte{}
	if eng.pair != nil {
		routeID = eng.pair.routeID
	}
	eng.mu.Unlock()
	if routeID != got.RouteID {
		t.Fatalf("daemon slot route %x does not match the only admitted route %x; "+
			"the refused phone reached the daemon after all", routeID, got.RouteID)
	}
}

// TestRelayReleasesSlotWhenFirstPhoneDisconnects records the shape of the
// exclusion: it is a mutex, not a one-shot. Whether the gate stays reachable
// after a stalled attempt depends entirely on the relay noticing the drop, so
// this pins the release path that makes the persistent gate usable at all.
//
// COUPLING NOTE for anyone moving the gate's throttle billing point: this test
// makes three attaches against one persistent gate, and gateFreeAttempts is 3
// (gate.go:282). Billing today happens at SpakeShareP, inside an
// `if pair.persistent` block (pairing.go:589), so a bare attach costs nothing
// and the count is harmless -- measured, not assumed: the gate ledger stays at
// 0 across all three. Move the charge earlier, to PAIR_ATTACHED, and this test
// sits exactly on the boundary: it would begin failing on the throttle rather
// than on the behaviour it means to check. It is the first test that will
// notice such a move, which is why the arithmetic is written down here.
func TestRelayReleasesSlotWhenFirstPhoneDisconnects(t *testing.T) {
	_, hub, ref := relayGateSetup(t, "correct-horse-battery-staple")

	first := newRelayClient(t, hub)
	if got := first.attach(t, ref); got.Typ != envelope.TypPAIR_ATTACHED {
		t.Fatalf("first attach refused: code=%q", errCode(got))
	}
	second := newRelayClient(t, hub)
	if code := errCode(second.attach(t, ref)); code != "pair_busy" {
		t.Fatalf("expected pair_busy while the first phone holds the bind, got %q", code)
	}

	// The first phone goes away without ever completing the handshake -- the
	// common real-world case of a user who closes the tab.
	close(first.stop)
	hub.DropConn(first.hub)
	time.Sleep(50 * time.Millisecond)

	third := newRelayClient(t, hub)
	got := third.attach(t, ref)
	if got.Typ != envelope.TypPAIR_ATTACHED {
		t.Fatalf("gate stayed wedged after the first phone disconnected: typ=%#x code=%q; "+
			"an abandoned attempt would lock every other phone out", got.Typ, errCode(got))
	}
}

// TestRelaySerializesTwoPhonesOnOneGate is the product-level statement of the
// same fact, phrased the way a user would experience it: two people holding the
// same passphrase can both get in, but strictly one after the other. Racing
// them is not merely slower, it fails outright.
//
// The measurement that matters is the failure mode. If the loser is rejected
// with a distinguishable relay error, a client can retry; if it is silently
// starved, it cannot. Both outcomes are accepted here because either is honest
// relay behaviour -- what is asserted is that exactly one wins and that the
// gate survives to serve the other afterwards.
func TestRelaySerializesTwoPhonesOnOneGate(t *testing.T) {
	const password = "correct-horse-battery-staple"
	eng, hub, ref := relayGateSetup(t, password)

	type result struct {
		client *phone.Client
		err    error
	}
	results := make(chan result, 2)
	for range 2 {
		go func() {
			phA, hubC := mux.NewPipePair(32)
			stop := pump(t, hubC, func(f envelope.Frame) { hub.HandleClient(hubC, f) })
			ph := &phone.Client{Conn: phA}
			err := ph.PairWithPassword(ref, password, "")
			if err != nil {
				// Release the bind, exactly as gate_e2e_test.go's gatePhone
				// does: a failed attempt left connected wedges the slot.
				close(stop)
				hub.DropConn(hubC)
			} else {
				t.Cleanup(func() { close(stop) })
			}
			results <- result{ph, err}
		}()
	}

	var ok []*phone.Client
	var failures []error
	for range 2 {
		r := <-results
		if r.err != nil {
			failures = append(failures, r.err)
			continue
		}
		ok = append(ok, r.client)
	}

	if len(ok) != 1 {
		t.Fatalf("expected the relay to admit exactly one of two simultaneous phones, admitted %d (errors: %v)",
			len(ok), failures)
	}
	t.Logf("MEASURED: relay admitted 1 of 2 simultaneous phones; loser reported: %v", failures)

	// The loser must be able to come back. A persistent gate that one racing
	// phone can spoil for good would be worse than a one-use code.
	time.Sleep(500 * time.Millisecond)
	eng.mu.Lock()
	alive := eng.pair != nil && eng.pair.persistent && !eng.pair.closed
	gateRef := ""
	if alive {
		gateRef = eng.pair.ref
	}
	eng.mu.Unlock()
	if !alive {
		t.Fatal("gate did not survive two simultaneous attempts; the loser can never retry")
	}

	retryA, hubC := mux.NewPipePair(32)
	stopR := pump(t, hubC, func(f envelope.Frame) { hub.HandleClient(hubC, f) })
	defer close(stopR)
	retry := &phone.Client{Conn: retryA}
	if err := retry.PairWithPassword(gateRef, password, ""); err != nil {
		t.Fatal("the rejected phone could not pair on retry:", err)
	}
	if retry.DeviceID == ok[0].DeviceID {
		t.Fatalf("retry reused the winner's device_id %q", retry.DeviceID)
	}
	if string(retry.PSK) == string(ok[0].PSK) {
		t.Fatal("retry received the winner's PSK; the shared passphrase leaked into key material")
	}
}

// TestRelaySlotDeadlineDoesNotOutliveThePersistentGate pins the structural
// mismatch between the two layers, which is the constraint a persistent gate
// has to live with rather than a bug in either one.
//
// The daemon's gate is durable: the verifier is on disk and survives restarts.
// The relay's pair_slot is not -- it carries a deadline capped at 300s
// (mux/pairing.go:44 clamps req.TTLS to 60..300), because the relay must be
// able to garbage-collect slots for daemons that vanished. So "persistent" is
// implemented as re-publication, not as a slot that never expires: the daemon
// republishes on expiry (pairing.go:295) and after each completed pairing
// (pairing.go:567).
//
// That makes the republication path load-bearing in a way nothing else asserts.
// If it ever stops firing, the passphrase keeps working in every unit test that
// inspects daemon state while being unreachable through the relay -- the gate
// would simply stop answering a few minutes after startup. This test drives the
// expiry for real and then requires a phone to still get in over the relay.
func TestRelaySlotDeadlineDoesNotOutliveThePersistentGate(t *testing.T) {
	const password = "correct-horse-battery-staple"
	store, err := state.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	hub := mux.NewHub("pf_relay_ttl")
	engA, hubD := mux.NewPipePair(32)
	eng := NewEngine(hub, engA, runtime.NewFake())
	eng.Store = store
	eng.AutoAdmit = false
	// A short daemon-side TTL forces the expiry-and-republish cycle to happen
	// inside the test instead of minutes later. PairingTTL below the 60s floor
	// falls back to the default (pairing.go:136), so the slot is expired
	// directly rather than by waiting.
	stopD := pump(t, hubD, func(f envelope.Frame) { hub.HandleDaemon(hubD, f) })
	defer close(stopD)
	if err := eng.Register("pf_relay_ttl"); err != nil {
		t.Fatal(err)
	}
	stopE := make(chan struct{})
	go eng.RecvLoop(stopE)
	defer close(stopE)

	if _, err := eng.SetGatePassword(password); err != nil {
		t.Fatal(err)
	}
	first, err := eng.OpenPasswordGate()
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(150 * time.Millisecond)

	eng.mu.Lock()
	slot := eng.pair
	eng.mu.Unlock()
	if slot == nil {
		t.Fatal("no slot after opening the gate")
	}
	// Fire the deadline the relay would eventually enforce.
	eng.expirePairing(slot)

	// The gate must come back on its own, under the same ref, and be reachable
	// over the relay -- daemon state alone is not the claim being tested.
	deadline := time.Now().Add(3 * time.Second)
	gateRef := ""
	for time.Now().Before(deadline) {
		eng.mu.Lock()
		if eng.pair != nil && eng.pair.persistent && !eng.pair.closed {
			gateRef = eng.pair.ref
		}
		eng.mu.Unlock()
		if gateRef != "" {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if gateRef == "" {
		t.Fatal("the gate did not republish after its relay slot expired; the passphrase would stop working minutes after startup")
	}
	if gateRef != first.Ref {
		t.Fatalf("pair_ref changed across republication: %q then %q; every phone holding the old QR would be stranded", first.Ref, gateRef)
	}

	phA, hubC := mux.NewPipePair(32)
	stopC := pump(t, hubC, func(f envelope.Frame) { hub.HandleClient(hubC, f) })
	defer close(stopC)
	ph := &phone.Client{Conn: phA}
	if err := ph.PairWithPassword(gateRef, password, ""); err != nil {
		t.Fatal("phone could not pair after the relay slot expired and was republished:", err)
	}
	if !waitForDevice(eng, ph.DeviceID, 2*time.Second) {
		t.Fatal("device from the republished gate was not persisted")
	}
}

// waitForDevice polls for the device row. The daemon persists it after the ack
// leaves, so the phone returning from PairWithPassword does not by itself mean
// the write has landed.
func waitForDevice(eng *Engine, id string, d time.Duration) bool {
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if eng.HasDevice(id) {
			return true
		}
		time.Sleep(20 * time.Millisecond)
	}
	return false
}
