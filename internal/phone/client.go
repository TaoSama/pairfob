package phone

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	"golang.org/x/crypto/curve25519"

	"pairfob/internal/crypto/aead"
	"pairfob/internal/crypto/canon"
	"pairfob/internal/crypto/sessionkeys"
	"pairfob/internal/crypto/spake2plus"
	"pairfob/internal/envelope"
	"pairfob/internal/mux"
)

type Client struct {
	Conn        mux.Conn
	DaemonID    string
	DeviceID    string
	Label       string
	PSK         []byte
	DaemonPK    ed25519.PublicKey
	Protocol    int
	routeID     [16]byte
	c2s, s2c    *aead.Direction
	Established bool
	Events      []json.RawMessage

	sendMu     sync.Mutex
	muxMu      sync.Mutex
	muxOnce    sync.Once
	muxPending map[string]chan rpcOutcome
}

// Protocol is the relay-facing envelope version used in HELLO_CLIENT,
// PAIR_ATTACH and SESSION_ATTACH. It defaults to 1, which is what the
// in-memory hub the tests run against expects; a client talking to a deployed
// v2 relay must set 2 or every attach comes back as bad_token
// (workers/pairfob-origin/src/room/pairing.ts:181).
//
// This is deliberately separate from the "v":1 inside the SPAKE2+ and RPC
// payloads. Those are end-to-end bytes the relay never parses, and they are
// frozen by the protocol contract in README.md.
func (c *Client) relayProtocol() int {
	if c.Protocol == 0 {
		return 1
	}
	return c.Protocol
}

// frameReceiver is the read half of whatever transport the client is running
// over. mux.Conn only declares Send and Close, because the hub never reads from
// a connection it was handed — receiving is the owner's business. The two
// owners here spell it differently: mux.Pipe reports a closed pipe through an
// ok flag, while wsnet.Conn returns an error.
type frameReceiver interface {
	RecvWithin(time.Duration) (envelope.Frame, error)
}

// recv reads one frame, bridging the in-memory pipe used by tests and the real
// websocket used against a deployed relay. Keeping both behind one method is
// what lets the same pairing code serve as an acceptance client: a handshake
// proven only over a pipe has not been proven against the relay at all.
func (c *Client) recv(timeout time.Duration) (envelope.Frame, error) {
	switch conn := c.Conn.(type) {
	case *mux.Pipe:
		f, ok := conn.RecvTimeout(timeout)
		if !ok {
			return envelope.Frame{}, errors.New("timeout")
		}
		return f, nil
	case frameReceiver:
		return conn.RecvWithin(timeout)
	default:
		return envelope.Frame{}, fmt.Errorf("phone client cannot receive over %T", c.Conn)
	}
}

// Pair completes a handshake against a one-use pairing code. The code is
// Crockford-folded first, so the operator can read it aloud and the typist can
// confuse O for 0 without breaking the proof.
func (c *Client) Pair(pairRef, code, daemonID string) error {
	return c.pair(pairRef, canon.NormalizeCrockford(code), daemonID)
}

// PairWithPassword completes the same handshake against the persistent
// passphrase gate. The secret is passed through byte for byte: Crockford
// folding is defined over an 8-glyph alphabet and would destroy a passphrase's
// case, punctuation and length, so the two ends would derive different records.
func (c *Client) PairWithPassword(pairRef, password, daemonID string) error {
	return c.pair(pairRef, password, daemonID)
}

func (c *Client) pair(pairRef, secret, daemonID string) error {
	if err := c.Conn.Send(envelope.JSON(envelope.TypHELLO_CLIENT, [16]byte{}, map[string]any{"v": c.relayProtocol(), "protocol": c.relayProtocol()})); err != nil {
		return err
	}
	attach := map[string]any{"v": c.relayProtocol()}
	if pairRef != "" {
		attach["pair_ref"] = pairRef
	}
	if err := c.Conn.Send(envelope.JSON(envelope.TypPAIR_ATTACH, [16]byte{}, attach)); err != nil {
		return err
	}
	f, err := c.recv(2 * time.Second)
	if err != nil {
		return err
	}
	if f.Typ != envelope.TypPAIR_ATTACHED {
		// A rejected attach comes back as an ERROR frame carrying the reason,
		// and swallowing it turns every distinct failure -- expired slot,
		// pair_busy, unknown ref -- into the same unhelpful sentence.
		if f.Typ == envelope.TypERROR {
			return fmt.Errorf("attach rejected: %w", frameError(f))
		}
		return fmt.Errorf("expected PAIR_ATTACHED, got frame type %d", f.Typ)
	}
	var attached struct {
		DaemonID string `json:"daemon_id"`
		PairRef  string `json:"pair_ref"`
	}
	if json.Unmarshal(f.Payload, &attached) != nil || attached.DaemonID == "" || len(attached.PairRef) != 32 {
		return errors.New("invalid PAIR_ATTACHED")
	}
	if pairRef != "" && pairRef != attached.PairRef {
		return errors.New("pair_ref mismatch")
	}
	if daemonID != "" && daemonID != attached.DaemonID {
		return errors.New("daemon_id mismatch")
	}
	pairRef, daemonID = attached.PairRef, attached.DaemonID
	c.routeID = f.RouteID
	rec := spake2plus.DeriveRecord(secret, daemonID, pairRef)
	idP := spake2plus.IdProver(pairRef)
	pr := spake2plus.NewProver(rec, idP, daemonID, "")
	shareP := pr.Start()
	payload, err := json.Marshal(map[string]any{"v": 1, "op": "SpakeShareP", "share": canon.B64URL(shareP)})
	if err != nil {
		return err
	}
	if err := c.Conn.Send(envelope.Frame{Version: 1, Typ: envelope.TypFWD, RouteID: c.routeID, Payload: payload}); err != nil {
		return err
	}
	f, err = c.recv(3 * time.Second)
	if err != nil {
		return err
	}
	var sv struct {
		Op       string `json:"op"`
		Share    string `json:"share"`
		ConfirmV string `json:"confirm_v"`
	}
	if f.Typ != envelope.TypFWD || f.RouteID != c.routeID {
		return fmt.Errorf("unexpected SPAKE frame type=%#x route=%x", f.Typ, f.RouteID)
	}
	if err := json.Unmarshal(f.Payload, &sv); err != nil || sv.Op != "SpakeShareV" {
		return errors.New("invalid SpakeShareV")
	}
	shareV, err := canon.DecodeB64URL(sv.Share)
	if err != nil {
		return fmt.Errorf("invalid verifier share: %w", err)
	}
	keys, err := pr.Finish(shareV)
	if err != nil {
		return err
	}
	confirmV, err := decodeB64Exact(sv.ConfirmV, len(keys.ConfirmV), "confirm_v")
	if err != nil {
		return err
	}
	if !spake2plus.ConfirmEqual(keys.ConfirmV, confirmV) {
		return errors.New("bad confirm_v")
	}
	cp, err := json.Marshal(map[string]any{"v": 1, "op": "SpakeConfirmP", "confirm_p": canon.B64URL(keys.ConfirmP)})
	if err != nil {
		return err
	}
	if err := c.Conn.Send(envelope.Frame{Version: 1, Typ: envelope.TypFWD, RouteID: c.routeID, Payload: cp}); err != nil {
		return err
	}
	kc2s, ks2c := sessionkeys.PairingKeys(keys.KShared)
	c2s := &aead.Direction{Key: kc2s, Dir: aead.DirClient}
	s2c := &aead.Direction{Key: ks2c, Dir: aead.DirServer}
	f, err = c.recv(30 * time.Second)
	if err != nil {
		return err
	}
	if f.Typ != envelope.TypFWD || f.RouteID != c.routeID {
		return fmt.Errorf("unexpected pairing result type=%#x route=%x", f.Typ, f.RouteID)
	}
	pt, err := aead.Open(s2c, c.routeID, f.Payload)
	if err != nil {
		return err
	}
	var conf struct {
		ID     string `json:"id"`
		Op     string `json:"op"`
		Params struct {
			DeviceID string `json:"device_id"`
			PSK      string `json:"device_psk"`
			DaemonPK string `json:"daemon_pk"`
			SAS      string `json:"sas"`
			FP       string `json:"fp"`
		} `json:"params"`
	}
	if err := json.Unmarshal(pt, &conf); err != nil || conf.Op != "ConfirmPairing" || conf.ID == "" {
		return errors.New("invalid ConfirmPairing request")
	}
	if sessionkeys.SAS(keys.KShared) != conf.Params.SAS {
		return errors.New("pairing confirmation mismatch")
	}
	psk, err := decodeB64Exact(conf.Params.PSK, 32, "device_psk")
	if err != nil {
		return err
	}
	pk, err := decodeB64Exact(conf.Params.DaemonPK, ed25519.PublicKeySize, "daemon_pk")
	if err != nil {
		return err
	}
	if conf.Params.DeviceID == "" {
		return errors.New("missing device_id")
	}
	c.DeviceID = conf.Params.DeviceID
	c.PSK = psk
	c.DaemonPK = ed25519.PublicKey(pk)
	if canon.Fingerprint16(c.DaemonPK) != conf.Params.FP {
		return errors.New("fp mismatch")
	}
	ack, _ := aead.Seal(c2s, c.routeID, sessionkeys.MustJSON(map[string]any{"v": 1, "id": conf.ID, "ok": true, "result": map[string]any{"label": c.Label}}))
	return c.Conn.Send(envelope.Frame{Version: 1, Typ: envelope.TypFWD, RouteID: c.routeID, Payload: ack})
}

func (c *Client) Resume(daemonID string) error {
	c.DaemonID = daemonID
	c.Established = false
	if err := c.Conn.Send(envelope.JSON(envelope.TypHELLO_CLIENT, [16]byte{}, map[string]any{"v": c.relayProtocol(), "protocol": c.relayProtocol()})); err != nil {
		return err
	}
	if err := c.Conn.Send(envelope.JSON(envelope.TypSESSION_ATTACH, [16]byte{}, map[string]any{"v": c.relayProtocol(), "daemon_id": daemonID})); err != nil {
		return err
	}
	f, err := c.recv(2 * time.Second)
	if err != nil {
		return err
	}
	if f.Typ == envelope.TypERROR {
		var b envelope.ErrorBody
		_ = json.Unmarshal(f.Payload, &b)
		return errors.New(b.Code)
	}
	if f.Typ != envelope.TypSESSION_BOUND {
		return errors.New("expected SESSION_BOUND")
	}
	c.routeID = f.RouteID
	var ephSk, ephPk [32]byte
	if _, err := io.ReadFull(rand.Reader, ephSk[:]); err != nil {
		return err
	}
	curve25519.ScalarBaseMult(&ephPk, &ephSk)
	nonce := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return err
	}
	h1 := sessionkeys.Hello1{V: 1, Op: "DeviceHello1", DeviceID: c.DeviceID, DaemonID: daemonID,
		EphX25519: canon.B64URL(ephPk[:]), Nonce: canon.B64URL(nonce)}
	raw, err := json.Marshal(h1)
	if err != nil {
		return err
	}
	if err := c.Conn.Send(envelope.Frame{Version: 1, Typ: envelope.TypFWD, RouteID: c.routeID, Payload: raw}); err != nil {
		return err
	}
	f, err = c.recv(2 * time.Second)
	if err != nil {
		return err
	}
	if f.Typ == envelope.TypERROR {
		return frameError(f)
	}
	if f.Typ != envelope.TypFWD || f.RouteID != c.routeID {
		return fmt.Errorf("unexpected DeviceHello2 frame type=%#x route=%x", f.Typ, f.RouteID)
	}
	var h2 sessionkeys.Hello2
	if err := json.Unmarshal(f.Payload, &h2); err != nil {
		return errors.New("invalid DeviceHello2")
	}
	if !h2.OK {
		return errors.New("hello2 not ok")
	}
	ephD, err := decodeB64Exact(h2.EphX25519, 32, "eph_x25519")
	if err != nil {
		return err
	}
	td := sessionkeys.TranscriptD(daemonID, c.DeviceID, ephPk[:], ephD, nonce, h2.TS, c.routeID)
	proofD, err := decodeB64Exact(h2.ProofD, 32, "proof_d")
	if err != nil {
		return err
	}
	if !sessionkeys.HMACEqual(sessionkeys.Proof(c.PSK, td), proofD) {
		return errors.New("bad proof_d")
	}
	sigD, err := decodeB64Exact(h2.SigD, ed25519.SignatureSize, "sig_d")
	if err != nil {
		return err
	}
	if !sessionkeys.VerifySig(c.DaemonPK, td, sigD) {
		return errors.New("bad sig_d")
	}
	h3 := sessionkeys.Hello3{V: 1, Op: "DeviceHello3", ProofP: canon.B64URL(sessionkeys.Proof(c.PSK, sessionkeys.TranscriptP(td)))}
	raw, err = json.Marshal(h3)
	if err != nil {
		return err
	}
	if err := c.Conn.Send(envelope.Frame{Version: 1, Typ: envelope.TypFWD, RouteID: c.routeID, Payload: raw}); err != nil {
		return err
	}
	var peer, dh [32]byte
	copy(peer[:], ephD)
	curve25519.ScalarMult(&dh, &ephSk, &peer)
	if dh == [32]byte{} {
		return errors.New("invalid peer X25519 public key")
	}
	kc, ks := sessionkeys.SessionKeys(dh[:], c.PSK)
	c.c2s = &aead.Direction{Key: kc, Dir: aead.DirClient}
	c.s2c = &aead.Direction{Key: ks, Dir: aead.DirServer}
	// Relay upgrades a ResumeHello only after the daemon explicitly confirms
	// DeviceHello3. Never guess establishment with a fixed delay.
	f, err = c.recv(15 * time.Second)
	if err != nil {
		c.c2s, c.s2c = nil, nil
		return fmt.Errorf("wait SESSION_ESTABLISHED: %w", err)
	}
	if f.Typ == envelope.TypERROR {
		c.c2s, c.s2c = nil, nil
		return frameError(f)
	}
	if f.Typ != envelope.TypSESSION_ESTABLISHED || f.RouteID != c.routeID {
		c.c2s, c.s2c = nil, nil
		return fmt.Errorf("unexpected establishment frame type=%#x route=%x", f.Typ, f.RouteID)
	}
	c.Established = true
	return nil
}

func (c *Client) RPC(op string, params any) (json.RawMessage, error) {
	return c.RPCTimeout(op, params, 3*time.Second)
}

func (c *Client) RPCTimeout(op string, params any, timeout time.Duration) (json.RawMessage, error) {
	c.muxMu.Lock()
	muxed := c.muxPending != nil
	c.muxMu.Unlock()
	if muxed {
		return c.MuxRPC(op, params, timeout)
	}
	if !c.Established || c.c2s == nil || c.s2c == nil {
		return nil, errors.New("session not established")
	}
	id, err := c.sendRPC(op, params)
	if err != nil {
		return nil, err
	}
	deadline := time.Now().Add(timeout)
	for {
		remain := time.Until(deadline)
		if remain <= 0 {
			return nil, errors.New("timeout")
		}
		f, err := c.recv(remain)
		if err != nil {
			return nil, err
		}
		if f.Typ == envelope.TypERROR {
			return nil, frameError(f)
		}
		if f.Typ != envelope.TypFWD || f.RouteID != c.routeID {
			return nil, fmt.Errorf("unexpected RPC frame type=%#x route=%x", f.Typ, f.RouteID)
		}
		pt, err := aead.Open(c.s2c, c.routeID, f.Payload)
		if err != nil {
			return nil, err
		}
		var message struct {
			ID string `json:"id"`
			Op string `json:"op"`
		}
		if err := json.Unmarshal(pt, &message); err != nil {
			return nil, errors.New("invalid RPC response")
		}
		if message.ID == "" && (message.Op == "TerminalFrame" || message.Op == "TerminalClosed") {
			c.Events = append(c.Events, append(json.RawMessage(nil), pt...))
			continue
		}
		var resp struct {
			ID     string          `json:"id"`
			OK     bool            `json:"ok"`
			Result json.RawMessage `json:"result"`
			Error  *struct {
				Code    string `json:"code"`
				Message string `json:"message"`
			} `json:"error"`
		}
		if err := json.Unmarshal(pt, &resp); err != nil || resp.ID != id {
			return nil, errors.New("invalid RPC response")
		}
		if !resp.OK {
			if resp.Error != nil {
				return nil, errors.New(resp.Error.Code)
			}
			return nil, errors.New("rpc failed")
		}
		return resp.Result, nil
	}
}

func decodeB64Exact(s string, n int, field string) ([]byte, error) {
	b, err := canon.DecodeB64URL(s)
	if err != nil {
		return nil, fmt.Errorf("invalid %s: %w", field, err)
	}
	if len(b) != n {
		return nil, fmt.Errorf("invalid %s length %d", field, len(b))
	}
	return b, nil
}

func frameError(f envelope.Frame) error {
	var b envelope.ErrorBody
	if err := json.Unmarshal(f.Payload, &b); err != nil || b.Code == "" {
		return errors.New("invalid relay error")
	}
	return errors.New(b.Code)
}
