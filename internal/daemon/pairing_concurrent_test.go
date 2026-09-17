package daemon

//
// concurrency characterization for the single pairing
// slot (engine.go:47 pairingSlot, engine.go:172 Engine.pair).
//
// These tests drive Engine.Handle directly with independent route_ids. That is
// what a relay does when it binds more than one PairingWS to the same daemon.
// The in-repo relay refuses to do so (mux/pairing.go:207 answers pair_busy for
// a second attach), so the daemon's own behaviour under concurrent pairing has
// no coverage today and is asserted here for the first time.

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"pairfob/internal/crypto/aead"
	"pairfob/internal/crypto/canon"
	"pairfob/internal/crypto/sessionkeys"
	"pairfob/internal/crypto/spake2plus"
	"pairfob/internal/envelope"
	"pairfob/internal/mux"
	"pairfob/internal/runtime"
)

const (
	// concurrentStepWait bounds one SPAKE round trip. Everything after the
	// Argon2 record derivation is P-256 arithmetic, so this stays generous
	// even under the race detector.
	concurrentStepWait = 10 * time.Second
	// concurrentIdleWait bounds "the daemon must stay silent" assertions. It
	// has to outlive scheduling jitter without stretching the suite.
	concurrentIdleWait = 400 * time.Millisecond
)

// pairRouter demuxes the daemon's single relay uplink into per-route inboxes so
// that several mock phones can share one Engine the way a relay fans frames out.
type pairRouter struct {
	mu     sync.Mutex
	routes map[[16]byte]chan envelope.Frame
	ctrl   chan envelope.Frame
}

func newPairRouter(t *testing.T, peer *mux.Pipe) *pairRouter {
	t.Helper()
	r := &pairRouter{routes: map[[16]byte]chan envelope.Frame{}, ctrl: make(chan envelope.Frame, 128)}
	stop := make(chan struct{})
	done := make(chan struct{})
	t.Cleanup(func() { close(stop); <-done })
	go func() {
		defer close(done)
		for {
			f, ok := peer.RecvTimeout(20 * time.Millisecond)
			select {
			case <-stop:
				return
			default:
			}
			if !ok {
				continue
			}
			dst := r.ctrl
			if f.RouteID != ([16]byte{}) {
				dst = r.inbox(f.RouteID)
			}
			select {
			case dst <- f:
			default:
			}
		}
	}()
	return r
}

func (r *pairRouter) inbox(rid [16]byte) chan envelope.Frame {
	r.mu.Lock()
	defer r.mu.Unlock()
	ch := r.routes[rid]
	if ch == nil {
		ch = make(chan envelope.Frame, 32)
		r.routes[rid] = ch
	}
	return ch
}

func (r *pairRouter) wait(rid [16]byte, d time.Duration) (envelope.Frame, bool) {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case f := <-r.inbox(rid):
		return f, true
	case <-timer.C:
		return envelope.Frame{}, false
	}
}

// waitClose reports whether the daemon broadcast a PAIR_CLOSE for ref.
func (r *pairRouter) waitClose(ref string, d time.Duration) bool {
	deadline := time.Now().Add(d)
	for {
		remain := time.Until(deadline)
		if remain <= 0 {
			return false
		}
		timer := time.NewTimer(remain)
		select {
		case f := <-r.ctrl:
			timer.Stop()
			if f.Typ != envelope.TypPAIR_CLOSE {
				continue
			}
			var body struct {
				PairRef string `json:"pair_ref"`
			}
			if json.Unmarshal(f.Payload, &body) == nil && body.PairRef == ref {
				return true
			}
		case <-timer.C:
			return false
		}
	}
}

// mockPhone is a pairing-side SPAKE2+ prover bound to one route_id. It mirrors
// phone.Client.Pair (internal/phone/client.go:53) but lets a test pick the
// route and interleave the steps of two phones against a single Engine.
type mockPhone struct {
	name     string
	eng      *Engine
	rid      [16]byte
	prover   *spake2plus.Prover
	shareP   []byte
	keys     spake2plus.Keys
	c2s, s2c *aead.Direction
	deviceID string
	psk      []byte
}

// newMockPhone takes a pre-derived record on purpose: every phone attacking one
// pair_ref derives the identical record, and Argon2 dominates the runtime here.
func newMockPhone(name string, eng *Engine, tag byte, rec spake2plus.Record, pairRef string) *mockPhone {
	var rid [16]byte
	for i := range rid {
		rid[i] = tag
	}
	rid[15] = tag ^ 0x5a
	pr := spake2plus.NewProver(rec, spake2plus.IdProver(pairRef), eng.DaemonID, "")
	return &mockPhone{name: name, eng: eng, rid: rid, prover: pr, shareP: pr.Start()}
}

func (p *mockPhone) attach() {
	p.eng.Handle(envelope.JSON(envelope.TypPAIR_ATTACHED, p.rid, map[string]any{
		"v": 1, "attempt_id": "at_" + p.name, "route_id": hex.EncodeToString(p.rid[:]),
	}))
}

func (p *mockPhone) fwd(body map[string]any) {
	raw, err := json.Marshal(body)
	if err != nil {
		panic(err)
	}
	p.eng.Handle(envelope.Frame{Version: 1, Typ: envelope.TypFWD, RouteID: p.rid, Payload: raw})
}

func (p *mockPhone) sendShare() {
	p.fwd(map[string]any{"v": 1, "op": "SpakeShareP", "share": canon.B64URL(p.shareP)})
}

// recvShareV consumes SpakeShareV and derives this phone's pairing keys.
func (p *mockPhone) recvShareV(r *pairRouter) error {
	f, ok := r.wait(p.rid, concurrentStepWait)
	if !ok {
		return fmt.Errorf("%s: %w waiting for SpakeShareV", p.name, errSilentStarvation)
	}
	if f.Typ == envelope.TypERROR {
		return fmt.Errorf("%s: %w", p.name, frameErrorCode(f))
	}
	var sv struct {
		Op       string `json:"op"`
		Share    string `json:"share"`
		ConfirmV string `json:"confirm_v"`
	}
	if json.Unmarshal(f.Payload, &sv) != nil || sv.Op != "SpakeShareV" {
		return fmt.Errorf("%s: unexpected frame typ=%#x payload=%s", p.name, f.Typ, f.Payload)
	}
	shareV, err := canon.DecodeB64URL(sv.Share)
	if err != nil {
		return fmt.Errorf("%s: bad verifier share: %w", p.name, err)
	}
	keys, err := p.prover.Finish(shareV)
	if err != nil {
		return fmt.Errorf("%s: prover finish: %w", p.name, err)
	}
	confirmV, err := canon.DecodeB64URL(sv.ConfirmV)
	if err != nil || !spake2plus.ConfirmEqual(keys.ConfirmV, confirmV) {
		return fmt.Errorf("%s: confirm_v mismatch", p.name)
	}
	p.keys = keys
	kc2s, ks2c := sessionkeys.PairingKeys(keys.KShared)
	p.c2s = &aead.Direction{Key: kc2s, Dir: aead.DirClient}
	p.s2c = &aead.Direction{Key: ks2c, Dir: aead.DirServer}
	return nil
}

func (p *mockPhone) sendConfirm() {
	p.fwd(map[string]any{"v": 1, "op": "SpakeConfirmP", "confirm_p": canon.B64URL(p.keys.ConfirmP)})
}

// recvCredential opens the sealed ConfirmPairing request, records the
// device_id/psk the daemon minted for this route, and acks it.
//
// A credential sealed under the other phone's key cannot be opened here, and a
// credential belonging to the other handshake fails the SAS check. A successful
// return is therefore positive evidence that this route's credential was not
// crossed with another route's.
func (p *mockPhone) recvCredential(r *pairRouter) error {
	f, ok := r.wait(p.rid, concurrentStepWait)
	if !ok {
		return fmt.Errorf("%s: %w waiting for ConfirmPairing", p.name, errSilentStarvation)
	}
	if f.Typ == envelope.TypERROR {
		return fmt.Errorf("%s: %w", p.name, frameErrorCode(f))
	}
	pt, err := aead.Open(p.s2c, p.rid, f.Payload)
	if err != nil {
		return fmt.Errorf("%s: open ConfirmPairing: %w", p.name, err)
	}
	var conf struct {
		ID     string `json:"id"`
		Op     string `json:"op"`
		Params struct {
			DeviceID string `json:"device_id"`
			PSK      string `json:"device_psk"`
			SAS      string `json:"sas"`
		} `json:"params"`
	}
	if json.Unmarshal(pt, &conf) != nil || conf.Op != "ConfirmPairing" || conf.ID == "" {
		return fmt.Errorf("%s: invalid ConfirmPairing %s", p.name, pt)
	}
	if conf.Params.SAS != sessionkeys.SAS(p.keys.KShared) {
		return fmt.Errorf("%s: SAS mismatch -- credential belongs to another handshake", p.name)
	}
	psk, err := canon.DecodeB64URL(conf.Params.PSK)
	if err != nil || len(psk) != 32 {
		return fmt.Errorf("%s: bad device_psk", p.name)
	}
	p.deviceID, p.psk = conf.Params.DeviceID, psk
	ack, err := json.Marshal(map[string]any{
		"v": 1, "id": conf.ID, "ok": true, "result": map[string]any{"label": p.name},
	})
	if err != nil {
		return err
	}
	sealed, err := aead.Seal(p.c2s, p.rid, ack)
	if err != nil {
		return err
	}
	p.eng.Handle(envelope.Frame{Version: 1, Typ: envelope.TypFWD, RouteID: p.rid, Payload: sealed})
	return nil
}

// pair runs the whole phone side of the handshake on this route.
func (p *mockPhone) pair(r *pairRouter) error {
	p.attach()
	p.sendShare()
	if err := p.recvShareV(r); err != nil {
		return err
	}
	p.sendConfirm()
	return p.recvCredential(r)
}

// errSilentStarvation marks the failure mode where the daemon neither answers
// nor rejects a route -- the phone only learns of the loss by timing out.
var errSilentStarvation = errors.New("route starved: no reply and no error")

func frameErrorCode(f envelope.Frame) error {
	var body envelope.ErrorBody
	if json.Unmarshal(f.Payload, &body) != nil || body.Code == "" {
		return errors.New("unreadable relay error")
	}
	return errors.New(body.Code)
}

func newPairingEngine(t *testing.T) (*Engine, *pairRouter) {
	t.Helper()
	a, peer := mux.NewPipePair(128)
	eng := NewEngine(nil, a, runtime.NewFake())
	eng.DaemonID = "d_0123456789abcdef0123"
	eng.AutoAdmit = true
	return eng, newPairRouter(t, peer)
}

// openPairingForTest opens a slot and lifts the already-derived SPAKE record
// out of it. Re-deriving would cost another 64 MiB Argon2 pass per phone.
func openPairingForTest(t *testing.T, eng *Engine, code string) (PairingStatus, spake2plus.Record) {
	t.Helper()
	st, err := eng.OpenPairing(code)
	if err != nil {
		t.Fatal(err)
	}
	eng.mu.Lock()
	rec := eng.pair.record
	eng.mu.Unlock()
	return st, rec
}

// activePairRef returns the ref of the live slot, or "" when no slot is open.
func activePairRef(eng *Engine) string {
	eng.mu.Lock()
	defer eng.mu.Unlock()
	if eng.pair == nil || eng.pair.closed {
		return ""
	}
	return eng.pair.ref
}

// ---------------------------------------------------------------------------
// Test A: two phones, one pairing record.
// ---------------------------------------------------------------------------

// TestConcurrentPairSecondAttachClobbersFirstHandshake is a CHARACTERIZATION
// test: it asserts today's defect so any rework of the pairing slot has to
// confront it deliberately.
//
// CURRENT BEHAVIOUR (asserted below):
//
//	handlePairAttached (pairing.go:404) overwrites pair.routeID and calls
//	resetPairAttemptLocked (pairing.go:434), which throws away the in-flight
//	verifier and keys. The first phone's next frame then fails the
//	`f.RouteID != pair.routeID` guard in handlePairFWD (pairing.go:520) and is
//	DROPPED WITH NO REPLY AT ALL. Phone one hangs until its own client timeout
//	while phone two walks off with the slot.
//
// DESIRED BEHAVIOUR after a per-route rework: either both routes carry
// independent handshake state to completion, or the second attach is refused
// with an explicit error on route two while route one keeps running. Silently
// starving an in-flight route is never the right answer.
func TestConcurrentPairSecondAttachClobbersFirstHandshake(t *testing.T) {
	eng, router := newPairingEngine(t)
	st, rec := openPairingForTest(t, eng, "7K3M9H2P")

	first := newMockPhone("first", eng, 0x11, rec, st.Ref)
	second := newMockPhone("second", eng, 0x22, rec, st.Ref)

	// Phone one gets as far as holding SpakeShareV.
	first.attach()
	first.sendShare()
	if err := first.recvShareV(router); err != nil {
		t.Fatalf("first phone could not start its handshake: %v", err)
	}

	// Phone two attaches mid-flight. Nothing rejects it.
	second.attach()

	eng.mu.Lock()
	routeID, attempt, keysWiped := eng.pair.routeID, eng.pair.attempt, len(eng.pair.keys.ConfirmP) == 0
	eng.mu.Unlock()
	if routeID != second.rid {
		t.Fatalf("second attach did not take over the slot: routeID=%x want=%x", routeID, second.rid)
	}
	if attempt != "at_second" {
		t.Fatalf("slot attempt=%q want at_second", attempt)
	}
	if !keysWiped {
		t.Fatal("second attach left the first phone's SPAKE keys in the slot")
	}

	// Phone one's confirm is now unroutable: no ERROR, no PAIR_CLOSE, nothing.
	first.sendConfirm()
	if f, ok := router.wait(first.rid, concurrentIdleWait); ok {
		t.Fatalf("DEFECT CHANGED: first phone received a reply typ=%#x payload=%s", f.Typ, f.Payload)
	}
	if activePairRef(eng) != st.Ref {
		t.Fatal("slot was burned; expected it to survive, now owned by the second phone")
	}

	// Phone two meanwhile pairs successfully on phone one's slot.
	second.sendShare()
	if err := second.recvShareV(router); err != nil {
		t.Fatalf("second phone handshake: %v", err)
	}
	second.sendConfirm()
	if err := second.recvCredential(router); err != nil {
		t.Fatalf("second phone credential: %v", err)
	}
	if !eng.HasDevice(second.deviceID) {
		t.Fatalf("second phone device %q was not persisted", second.deviceID)
	}
	if first.deviceID != "" {
		t.Fatalf("first phone unexpectedly obtained device %q", first.deviceID)
	}
}

// TestConcurrentPairTwoPhonesNeverCrossCredentials asserts the SAFETY invariant
// the handover notes doubted: under concurrency no phone may end up holding a
// credential minted for the other handshake, and no two phones may share a
// device_id or a PSK.
//
// recvCredential fails closed on an AEAD open failure or a SAS mismatch, so a
// crossed credential cannot slip through silently. These assertions are NOT
// weakened to accommodate the current implementation -- they are the real
// invariant, and they must keep holding after the rework.
func TestConcurrentPairTwoPhonesNeverCrossCredentials(t *testing.T) {
	eng, router := newPairingEngine(t)
	st, rec := openPairingForTest(t, eng, "ABCDEFGH")

	phones := []*mockPhone{
		newMockPhone("alpha", eng, 0x31, rec, st.Ref),
		newMockPhone("beta", eng, 0x42, rec, st.Ref),
	}

	var wg sync.WaitGroup
	errs := make([]error, len(phones))
	start := make(chan struct{})
	for i, p := range phones {
		wg.Add(1)
		go func(i int, p *mockPhone) {
			defer wg.Done()
			<-start
			errs[i] = p.pair(router)
		}(i, p)
	}
	close(start)
	wg.Wait()

	paired := 0
	for i, p := range phones {
		if errs[i] != nil {
			t.Logf("phone %s did not complete: %v", p.name, errs[i])
			continue
		}
		paired++
		if p.deviceID == "" || len(p.psk) != 32 {
			t.Fatalf("phone %s completed with device_id=%q psk_len=%d", p.name, p.deviceID, len(p.psk))
		}
		if !eng.HasDevice(p.deviceID) {
			t.Fatalf("phone %s holds device %q the daemon never persisted", p.name, p.deviceID)
		}
	}

	// Invariant 1: distinct identities and distinct secrets.
	if phones[0].deviceID != "" && phones[0].deviceID == phones[1].deviceID {
		t.Fatalf("CREDENTIAL CROSSOVER: both phones hold device_id %q", phones[0].deviceID)
	}
	if len(phones[0].psk) == 32 && len(phones[1].psk) == 32 &&
		string(phones[0].psk) == string(phones[1].psk) {
		t.Fatal("CREDENTIAL CROSSOVER: both phones hold the same device PSK")
	}

	// Invariant 2: a phone that did not complete must hold no credential.
	for i, p := range phones {
		if errs[i] != nil && (p.deviceID != "" || len(p.psk) != 0) {
			t.Fatalf("phone %s failed with %v yet kept device_id=%q", p.name, errs[i], p.deviceID)
		}
	}

	// Invariant 3: the daemon's device table must agree with what the phones
	// believe. A crossover would show up as a row count mismatch.
	if n := len(eng.ListDeviceRows()); n != paired {
		t.Fatalf("persisted device rows=%d but %d phones completed", n, paired)
	}
	if paired == 0 {
		t.Fatal("neither phone completed; at least one attempt must be able to win")
	}

	// A losing phone should fail loudly. CURRENT BEHAVIOUR is a silent stall,
	// recorded here rather than asserted, because the per-route rework is what
	// gives us an explicit error to assert on.
	for i, p := range phones {
		if errors.Is(errs[i], errSilentStarvation) {
			t.Logf("KNOWN GAP (awaiting per-route rework): phone %s was starved silently "+
				"instead of being refused: %v", p.name, errs[i])
		}
	}
	t.Logf("phones completing the handshake: %d/%d", paired, len(phones))
}

// ---------------------------------------------------------------------------
// Test B: pairFailureLocked is a denial-of-service surface.
// ---------------------------------------------------------------------------

// TestConcurrentPairThreeFailuresLockOutLegitimateUser pins down
// pairFailureLocked (pairing.go:444): the third rejected proof burns the WHOLE
// slot (pairing.go:462), not merely the offending attempt.
//
// For a one-shot QR pairing code that is a defensible anti-guessing policy. For
// the persistent password gate this fork is building it is a DoS: anyone who
// can reach the relay can shut the owner's login entrance with three wrong
// guesses, and the owner must physically return to the computer to reopen it.
//
// DESIRED BEHAVIOUR for a persistent gate: failures throttle the offending
// route (backoff / per-route lockout) and leave the gate itself open.
//
// UPDATE: that behaviour now exists. pairFailureLocked returns early for
// pair.persistent (pairing.go:458), so the burn below is specific to one-use
// codes -- which is why this test opens one with OpenPairing rather than
// OpenPasswordGate. It stays as the pin for the one-use policy; the gate's own
// no-burn guarantee and its replacement throttle are covered in
// gate_throttle_test.go and gate_attack_test.go.
func TestConcurrentPairThreeFailuresLockOutLegitimateUser(t *testing.T) {
	eng, router := newPairingEngine(t)
	st, rec := openPairingForTest(t, eng, "ABCDEFGH")

	attacker := newMockPhone("attacker", eng, 0x51, rec, st.Ref)
	attacker.attach()

	// Two rejected proofs: the slot survives, the attempt is reset.
	for i := 1; i <= 2; i++ {
		attacker.fwd(map[string]any{"v": 1, "op": "SpakeShareP", "share": "not-a-valid-share"})
		f, ok := router.wait(attacker.rid, concurrentStepWait)
		if !ok || f.Typ != envelope.TypERROR {
			t.Fatalf("failure %d: want ERROR got ok=%t typ=%#x", i, ok, f.Typ)
		}
		if err := frameErrorCode(f); err.Error() != "bad_pair_code" {
			t.Fatalf("failure %d: error code %v", i, err)
		}
		eng.mu.Lock()
		failures, closed := eng.pair.failures, eng.pair.closed
		eng.mu.Unlock()
		if failures != i || closed {
			t.Fatalf("failure %d: failures=%d closed=%t", i, failures, closed)
		}
	}

	// The third burns the slot for everybody.
	attacker.fwd(map[string]any{"v": 1, "op": "SpakeShareP", "share": "not-a-valid-share"})
	if !router.waitClose(st.Ref, concurrentStepWait) {
		t.Fatal("third failure did not emit PAIR_CLOSE")
	}
	if ref := activePairRef(eng); ref != "" {
		t.Fatalf("slot survived three failures: ref=%q", ref)
	}
	if got := eng.PairingStatus().Ref; got != "" {
		t.Fatalf("PairingStatus still advertises ref=%q", got)
	}

	// DoS PROVEN: the legitimate owner knows the correct code and still cannot
	// pair -- its attach is ignored because no slot is left to attach to.
	owner := newMockPhone("owner", eng, 0x62, rec, st.Ref)
	owner.attach()
	eng.mu.Lock()
	slotRestored := eng.pair != nil
	eng.mu.Unlock()
	if slotRestored {
		t.Fatal("DEFECT CHANGED: attach after burn recreated a slot")
	}
	owner.sendShare()
	if f, ok := router.wait(owner.rid, concurrentIdleWait); ok {
		t.Fatalf("DEFECT CHANGED: owner received a response typ=%#x payload=%s", f.Typ, f.Payload)
	}
	if n := len(eng.ListDeviceRows()); n != 0 {
		t.Fatalf("no device should exist after a locked-out pairing, got %d", n)
	}

	// Recovery demands an operator action at the computer: a fresh OpenPairing.
	st2, rec2 := openPairingForTest(t, eng, "ABCDEFGH")
	if st2.Ref == st.Ref {
		t.Fatal("reopened pairing reused the burned ref")
	}
	recovered := newMockPhone("recovered", eng, 0x73, rec2, st2.Ref)
	if err := recovered.pair(router); err != nil {
		t.Fatalf("owner still cannot pair after the operator reopened pairing: %v", err)
	}
	if !eng.HasDevice(recovered.deviceID) {
		t.Fatalf("recovered device %q not persisted", recovered.deviceID)
	}
}

// TestConcurrentPairFailureBudgetIsShared shows the failure counter is global:
// two different routes each spend from one budget, so one route can consume
// another route's allowance. A per-route gate must not behave this way.
func TestConcurrentPairFailureBudgetIsShared(t *testing.T) {
	eng, router := newPairingEngine(t)
	st, rec := openPairingForTest(t, eng, "ABCDEFGH")

	routeA := newMockPhone("routeA", eng, 0x81, rec, st.Ref)
	routeB := newMockPhone("routeB", eng, 0x92, rec, st.Ref)

	routeA.attach()
	for i := 1; i <= 2; i++ {
		routeA.fwd(map[string]any{"v": 1, "op": "SpakeShareP", "share": "bad"})
		if f, ok := router.wait(routeA.rid, concurrentStepWait); !ok || f.Typ != envelope.TypERROR {
			t.Fatalf("routeA failure %d: ok=%t typ=%#x", i, ok, f.Typ)
		}
	}

	// routeB has never failed, yet it inherits a budget of exactly one.
	routeB.attach()
	eng.mu.Lock()
	carried := eng.pair.failures
	eng.mu.Unlock()
	if carried != 2 {
		t.Fatalf("failure counter did not carry across attach: %d", carried)
	}
	routeB.fwd(map[string]any{"v": 1, "op": "SpakeShareP", "share": "bad"})
	if !router.waitClose(st.Ref, concurrentStepWait) {
		t.Fatal("routeB's first failure did not burn the shared slot")
	}
	if ref := activePairRef(eng); ref != "" {
		t.Fatalf("slot survived: ref=%q", ref)
	}
}

// ---------------------------------------------------------------------------
// Test C: data races under interleaved attach / FWD / burn.
// ---------------------------------------------------------------------------

// TestConcurrentPairAttachFWDBurnRace is a DATA RACE REGRESSION TEST. It was
// written as a reproducer and it earned its keep: under `go test -race` it
// failed reliably on a real unsynchronized access.
//
//	WRITE pair.routeID in handlePairAttached, holding e.mu (pairing.go:428)
//	READ  pair.routeID in handlePairFWD, after e.mu.Unlock, while addressing
//	      the SpakeShareV reply frame
//
// That read has since been fixed: the route is snapshotted under the lock
// before the unlock (pairing.go:631). The test now passes and guards the fix.
// The same unlocked-read shape would also have exposed pair.attempt, written in
// the same statement and read into the reply payload.
//
// REACHABILITY (important, and the reason this was never a live bug):
// in production Handle() is driven by the single RecvLoop goroutine
// (engine.go:468), so the relay transport alone cannot interleave these two --
// and the relay refuses a second concurrent attach anyway, which
// pairing_relay_concurrent_test.go measures directly. The hazard becomes live
// the moment a second concurrent frame source touches the pairing slot, which
// is precisely what a per-route rework introduces. This test fences the
// invariant ahead of that change.
//
// Two phones is enough: one must sit in the SpakeShareP branch with e.mu
// released while the other runs handlePairAttached. The operator-side churn
// deliberately does NOT call Deny, because burning the slot closes the window
// before the racing read can happen -- with Deny in the loop the original
// defect went undetected.
func TestConcurrentPairAttachFWDBurnRace(t *testing.T) {
	eng, _ := newPairingEngine(t)
	st, rec := openPairingForTest(t, eng, "7K3M9H2P")

	const routes = 4
	phones := make([]*mockPhone, routes)
	for i := range phones {
		phones[i] = newMockPhone(fmt.Sprintf("r%d", i), eng, byte(0xa0+i), rec, st.Ref)
	}

	var wg sync.WaitGroup
	stop := make(chan struct{})

	for _, p := range phones {
		wg.Add(1)
		go func(p *mockPhone) {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				// attach rewrites routeID/attempt under e.mu; sendShare drives
				// the peer goroutine into the unlocked read of both.
				p.attach()
				p.sendShare()
			}
		}(p)
	}

	// Operator-side churn: status reads and admits, racing the phones. Deny is
	// excluded on purpose -- see the doc comment.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}
			_ = eng.PairingStatus()
			_ = eng.Admit(st.Ref)
		}
	}()

	time.Sleep(750 * time.Millisecond)
	close(stop)
	wg.Wait()

	// The real assertion is the race detector's verdict. These checks only
	// confirm the engine did not additionally corrupt its own bookkeeping.
	eng.mu.Lock()
	pair := eng.pair
	consistent := pair == nil || (!pair.closed && pair.ref != "")
	eng.mu.Unlock()
	if !consistent {
		t.Fatal("engine left a closed slot installed as the active pairing")
	}
	for _, d := range eng.ListDeviceRows() {
		if d.ID == "" || d.PSK == "" {
			t.Fatalf("race left a malformed device row %+v", d)
		}
	}
}

// TestConcurrentPairBurnDuringConfirmIssue races burnPairLocked (pairing.go:485)
// against issueConfirmPairing (pairing.go:678). burnPairLocked zeroes pair.psk
// in place while issueConfirmPairing may still be serialising it, so this is
// the second place where -race has something to say.
func TestConcurrentPairBurnDuringConfirmIssue(t *testing.T) {
	eng, router := newPairingEngine(t)
	st, rec := openPairingForTest(t, eng, "ABCDEFGH")

	ph := newMockPhone("burned", eng, 0xc1, rec, st.Ref)
	ph.attach()
	ph.sendShare()
	if err := ph.recvShareV(router); err != nil {
		t.Fatalf("handshake: %v", err)
	}

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		ph.sendConfirm() // spawns issueConfirmPairing
	}()
	go func() {
		defer wg.Done()
		_ = eng.Deny(st.Ref) // burnPairLocked zeroes psk under e.mu
	}()
	wg.Wait()

	// Whichever order won, the slot must end up closed and no half-written
	// device row may survive.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && activePairRef(eng) != "" {
		time.Sleep(10 * time.Millisecond)
	}
	if ref := activePairRef(eng); ref != "" {
		t.Fatalf("slot still live after Deny: %q", ref)
	}
	for _, d := range eng.ListDeviceRows() {
		if d.ID == "" || d.PSK == "" {
			t.Fatalf("burn during ConfirmPairing persisted a malformed device %+v", d)
		}
	}
}
