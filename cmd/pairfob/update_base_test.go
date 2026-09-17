package main

import "testing"

func TestOriginFromRelayURL(t *testing.T) {
	for _, c := range []struct{ in, want string }{
		{"wss://pair.example.test/v2/ws?role=daemon&daemon_id=d_1", "https://pair.example.test"},
		{"ws://127.0.0.1:8787/v2/ws", "http://127.0.0.1:8787"},
		{"https://pair.example.test", "https://pair.example.test"},
		{"", ""},
		{"::not a url::", ""},
		{"ftp://pair.example.test/x", ""},
	} {
		if got := originFromRelayURL(c.in); got != c.want {
			t.Fatalf("originFromRelayURL(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestResolveDownloadBasePrefersOverrideThenEnrolledOrigin(t *testing.T) {
	// A self-hosted deployment serves its own builds, so the enrolled origin is
	// used ahead of the public site.
	base, err := resolveDownloadBase("https://pair.example.test")
	if err != nil {
		t.Fatal(err)
	}
	if base != "https://pair.example.test/dl" {
		t.Fatalf("enrolled origin base = %q", base)
	}

	// No enrollment: the public site is the only thing left to try.
	base, err = resolveDownloadBase("")
	if err != nil {
		t.Fatal(err)
	}
	if base != defaultDownloadBase {
		t.Fatalf("fallback base = %q", base)
	}

	// The explicit override outranks the enrolled origin.
	t.Setenv("PAIRFOB_DOWNLOAD_BASE", "https://mirror.example.test/dl/")
	base, err = resolveDownloadBase("https://pair.example.test")
	if err != nil {
		t.Fatal(err)
	}
	if base != "https://mirror.example.test/dl" {
		t.Fatalf("override base = %q", base)
	}
}

func TestResolveDownloadBaseRejectsPlaintextRemote(t *testing.T) {
	// http is only allowed on loopback; a plaintext remote origin would let a
	// network attacker choose the binary that replaces the daemon.
	if _, err := resolveDownloadBase("http://pair.example.test"); err == nil {
		t.Fatal("plaintext remote origin was accepted")
	}
	if _, err := resolveDownloadBase("http://127.0.0.1:8787"); err != nil {
		t.Fatalf("loopback origin rejected: %v", err)
	}
}

func TestDaemonDownloadBaseFallsBackToRelayURL(t *testing.T) {
	// plan.Origin is empty on a resumed boot, so the relay URL is what names the
	// deployment; the web update button depends on this path.
	if got := daemonDownloadBase("", "wss://pair.example.test/v2/ws?role=daemon"); got != "https://pair.example.test/dl" {
		t.Fatalf("relay fallback = %q", got)
	}
	if got := daemonDownloadBase("https://plan.example.test", "wss://relay.example.test/v2/ws"); got != "https://plan.example.test/dl" {
		t.Fatalf("plan origin should win: %q", got)
	}
	// An unusable base must not take the daemon down with it.
	if got := daemonDownloadBase("http://plan.example.test", ""); got != "" {
		t.Fatalf("unusable base = %q", got)
	}
}
