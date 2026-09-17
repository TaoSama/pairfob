// Command gateacceptance drives one real phone-shaped client against a
// deployed relay: it pairs with nothing but the passphrase, is issued a
// credential, reconnects with that credential, and runs an RPC.
//
// It exists because every other proof of the passphrase gate is an in-process
// pipe. This one speaks WebSocket to the public origin, so it exercises the
// relay, the Durable Object, the daemon's gate slot and the credential issue
// path exactly as a browser would.
package main

import (
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/gorilla/websocket"

	"pairfob/internal/phone"
	"pairfob/internal/wsnet"
)

func main() {
	origin := flag.String("origin", "", "relay origin, e.g. https://pair.taoai.site")
	daemonID := flag.String("daemon-id", "", "daemon_id to pair with")
	pairRef := flag.String("pair-ref", "", "pair_ref of the open passphrase gate")
	password := flag.String("password", "", "pairing passphrase (or PAIRFOB_PAIR_PASSWORD)")
	wrong := flag.Bool("wrong-password", false, "send a deliberately wrong passphrase to prove rejection")
	flag.Parse()

	if *password == "" {
		*password = os.Getenv("PAIRFOB_PAIR_PASSWORD")
	}
	if *origin == "" || *daemonID == "" || *pairRef == "" || *password == "" {
		fmt.Fprintln(os.Stderr, "usage: gateacceptance --origin URL --daemon-id ID --pair-ref REF --password PASS")
		os.Exit(2)
	}
	if err := run(*origin, *daemonID, *pairRef, *password, *wrong); err != nil {
		fmt.Fprintf(os.Stderr, "FAIL: %v\n", err)
		os.Exit(1)
	}
}

func clientURL(origin, daemonID string) string {
	ws := strings.Replace(strings.TrimRight(origin, "/"), "https://", "wss://", 1)
	ws = strings.Replace(ws, "http://", "ws://", 1)
	return fmt.Sprintf("%s/v2/ws?role=client&daemon_id=%s", ws, daemonID)
}

// dialAsBrowser opens the client websocket the way the PWA does.
//
// wsnet.DialProtocol sends no Origin header, and the relay requires a
// same-host one for role=client (workers/pairfob-origin/src/worker.ts:124) so
// that a page on another site cannot drive somebody's daemon. A non-browser
// client that wants to stand in for the phone has to present the same header,
// which is why this does not reuse the daemon-side dialer.
func dialAsBrowser(rawURL, origin string) (*wsnet.Conn, error) {
	tlsCfg, err := wsnet.ClientTLSConfig()
	if err != nil {
		return nil, err
	}
	d := websocket.Dialer{
		Subprotocols:     []string{wsnet.SubprotocolV2},
		TLSClientConfig:  tlsCfg,
		Proxy:            http.ProxyFromEnvironment,
		HandshakeTimeout: 30 * time.Second,
	}
	header := http.Header{}
	header.Set("Origin", strings.TrimRight(origin, "/"))
	ws, resp, err := d.Dial(rawURL, header)
	if err != nil {
		if resp != nil {
			return nil, fmt.Errorf("%w (http %d)", err, resp.StatusCode)
		}
		return nil, err
	}
	if ws.Subprotocol() != wsnet.SubprotocolV2 {
		_ = ws.Close()
		return nil, fmt.Errorf("relay did not negotiate %s", wsnet.SubprotocolV2)
	}
	return wsnet.Wrap(ws), nil
}

func run(origin, daemonID, pairRef, password string, wrong bool) error {
	url := clientURL(origin, daemonID)

	// Phase 1: pair using only the passphrase.
	conn, err := dialAsBrowser(url, origin)
	if err != nil {
		return fmt.Errorf("dial relay: %w", err)
	}
	ph := &phone.Client{Conn: conn, Protocol: 2}
	secret := password
	if wrong {
		secret = password + "-wrong"
	}
	start := time.Now()
	err = ph.PairWithPassword(pairRef, secret, daemonID)
	if wrong {
		conn.Close()
		if err == nil {
			return fmt.Errorf("a wrong passphrase was accepted")
		}
		fmt.Printf("PASS wrong passphrase rejected in %v: %v\n", time.Since(start).Round(time.Millisecond), err)
		return nil
	}
	if err != nil {
		conn.Close()
		return fmt.Errorf("pair with passphrase: %w", err)
	}
	fmt.Printf("PASS paired over %s in %v\n", origin, time.Since(start).Round(time.Millisecond))
	fmt.Printf("  device_id %s\n", ph.DeviceID)
	fmt.Printf("  psk_len   %d bytes\n", len(ph.PSK))
	if len(ph.PSK) != 32 {
		conn.Close()
		return fmt.Errorf("expected a 32-byte device PSK, got %d", len(ph.PSK))
	}
	deviceID, psk, daemonPK := ph.DeviceID, ph.PSK, ph.DaemonPK
	conn.Close()

	// Phase 2: reconnect as a returning device, which is what "it just works
	// afterwards" means in practice -- no passphrase, only the stored PSK.
	time.Sleep(500 * time.Millisecond)
	conn2, err := dialAsBrowser(url, origin)
	if err != nil {
		return fmt.Errorf("dial relay for resume: %w", err)
	}
	defer conn2.Close()
	back := &phone.Client{Conn: conn2, DeviceID: deviceID, PSK: psk, DaemonPK: daemonPK, Protocol: 2}
	start = time.Now()
	if err := back.Resume(daemonID); err != nil {
		return fmt.Errorf("resume with stored credential: %w", err)
	}
	fmt.Printf("PASS resumed with the stored credential in %v\n", time.Since(start).Round(time.Millisecond))

	// Phase 3: an actual RPC, so the session is shown to carry real traffic
	// rather than merely completing a handshake.
	// Snapshot is what the PWA asks for the moment it attaches, so a successful
	// one means the phone would actually have a screen to show rather than an
	// empty shell.
	raw, err := back.RPCTimeout("Snapshot", map[string]any{}, 25*time.Second)
	if err != nil {
		return fmt.Errorf("Snapshot rpc: %w", err)
	}
	var pretty any
	if err := json.Unmarshal(raw, &pretty); err != nil {
		return fmt.Errorf("decode Snapshot: %w", err)
	}
	out, _ := json.Marshal(pretty)
	fmt.Printf("PASS Snapshot returned %d bytes: %s\n", len(raw), truncate(string(out), 400))
	fmt.Printf("\ncredential (store nothing): device_id=%s psk=%s…\n", deviceID, base64.RawURLEncoding.EncodeToString(psk)[:8])
	return nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
