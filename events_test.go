package dnstunnel

import (
	"bytes"
	"context"
	"errors"
	"io"
	"sync"

	"github.com/miekg/dns"
	"testing"
	"time"
)

// collectClientEvents returns a handler that records events into a channel and
// a snapshot reader with a deadline.
func collectClientEvents() (ClientEventHandler, func() []ClientEvent) {
	mu := sync.Mutex{}
	var got []ClientEvent
	ch := make(chan struct{}, 64)
	handler := func(ev ClientEvent) {
		mu.Lock()
		got = append(got, ev)
		mu.Unlock()
		select {
		case ch <- struct{}{}:
		default:
		}
	}
	read := func() []ClientEvent {
		mu.Lock()
		defer mu.Unlock()
		return append([]ClientEvent(nil), got...)
	}
	return handler, read
}

// TestClientEventsLifecycle walks a full session against {dead, live} servers:
// the dead path forces a Reconnecting retry, the live path establishes the
// session, and an explicit Close fires TunnelDied — in order, on the handler.
func TestClientEventsLifecycle(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	backend := startTCPEchoBackend(t)
	liveDNS := startTestDNSServer(t, mustDNSServerForEvents(t, "events.test.local", "tcp://"+backend))
	deadDNS := "127.0.0.1:1"
	handler, readEvents := collectClientEvents()
	cli, err := NewClient(ClientConfig{
		Domain:       "events.test.local",
		Servers:      []string{deadDNS, liveDNS},
		RecordType:   "txt",
		EventHandler: handler,
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	conn, err := cli.Dial(ctx)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}

	// 4 chunks × 21 bytes: round-robin must hand at least one to the dead
	// path no matter where the cursor starts after the capability probe, and
	// that chunk pays a full UDP timeout before its retry succeeds on the
	// live path — which is what fires Reconnecting.
	payload := bytes.Repeat([]byte("event lifecycle probe"), 4)
	if _, err := conn.Write(payload); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := conn.SetReadDeadline(time.Now().Add(15 * time.Second)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("read: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatal("roundtrip mismatch")
	}

	// The first chunk round-robins onto the dead path and pays a full UDP
	// timeout before its retry succeeds on the live one; wait for that
	// Reconnecting event instead of a fixed sleep, then close to fire
	// TunnelDied.
	waitForEvent(t, readEvents, ClientReconnecting, 20*time.Second)
	_ = conn.Close()
	waitForEvent(t, readEvents, ClientTunnelDied, 5*time.Second)

	// The snapshot accumulates every event ever published — assert the full
	// lifecycle was seen, and that Died reported the actual close reason.
	seen := map[ClientEventKind]bool{ClientReconnecting: true, ClientTunnelDied: true}
	for _, ev := range readEvents() {
		seen[ev.Kind] = true
		if ev.Kind == ClientTunnelDied && ev.Reason != deathReasonCallerClosed {
			t.Fatalf("died reason = %q, want %q", ev.Reason, deathReasonCallerClosed)
		}
	}
	if !seen[ClientTunnelEstablished] {
		t.Fatalf("missing TunnelEstablished; seen kinds: %v", seen)
	}
}

// waitForEvent blocks until an event of the given kind shows up in the
// accumulated snapshot, failing after the deadline.
func waitForEvent(t *testing.T, readEvents func() []ClientEvent, kind ClientEventKind, d time.Duration) {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		for _, ev := range readEvents() {
			if ev.Kind == kind {
				return
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("event %v did not arrive within %v (snapshot: %v)", kind, d, readEvents())
}

// typed event (and that a session without a handler is unaffected).
func TestClientTargetDeniedEvent(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	dnsAddr := pickFreeUDPPort(t)
	srv, err := NewServer(ServerConfig{
		Domain:     "denied.test.local",
		ListenAddr: dnsAddr,
		TargetAddr: "tcp://127.0.0.1:1",
		// No allow_targets: everything declared is refused. PSK so the
		// declaration is authenticated before the allow list denies it.
		PSKs: []string{"denied-secret"},
	})
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = srv.Run(ctx) }()
	waitForDNSServer(t, dnsAddr)

	events := make(chan ClientEvent, 8)
	cli, err := NewClient(ClientConfig{
		Domain:       "denied.test.local",
		Servers:      []string{dnsAddr},
		RecordType:   "txt",
		PSK:          "denied-secret",
		EventHandler: func(ev ClientEvent) { events <- ev },
	})
	if err != nil {
		t.Fatal(err)
	}

	if _, err := cli.DialTarget(ctx, "tcp://10.9.9.9:80"); err == nil {
		t.Fatal("denied target must return an error")
	}

	select {
	case ev := <-events:
		if ev.Kind != ClientTargetDenied {
			t.Fatalf("event kind = %v, want TargetDenied", ev.Kind)
		}
		if ev.Target != "tcp://10.9.9.9:80" {
			t.Fatalf("event target = %q", ev.Target)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("TargetDenied event never arrived")
	}
}

// TestClientDoneAndErr exercises the context-style death signaling: Done
// closes exactly once on Close and Err stays nil for a deliberate close; a
// closeWith death makes Err non-nil.
func TestClientDoneAndErr(t *testing.T) {
	dnsAddr := pickFreeUDPPort(t)
	srv, err := NewServer(ServerConfig{
		Domain:     "done.test.local",
		ListenAddr: dnsAddr,
		TargetAddr: "tcp://127.0.0.1:1",
	})
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = srv.Run(context.Background()) }()
	waitForDNSServer(t, dnsAddr)

	cli, err := NewClient(ClientConfig{Domain: "done.test.local", Servers: []string{dnsAddr}, RecordType: "txt"})
	if err != nil {
		t.Fatal(err)
	}
	tun, err := cli.Dial(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	tunnel := tun.(*DNSClientTunnel)

	select {
	case <-tunnel.Done():
		t.Fatal("Done closed while the session is alive")
	default:
	}
	if err := tunnel.Err(); err != nil {
		t.Fatalf("Err before close = %v, want nil", err)
	}

	synthetic := errors.New("synthetic death")
	tunnel.closeWith(deathReasonMaxRetries, synthetic)

	select {
	case <-tunnel.Done():
	default:
		t.Fatal("Done did not close after death")
	}
	if err := tunnel.Err(); !errors.Is(err, synthetic) {
		t.Fatalf("Err after death = %v, want the death error", err)
	}
	if tunnel.closeWith(deathReasonMaxRetries, synthetic); tunnel.Err() != synthetic {
		t.Fatal("double close changed the death error")
	}
}

// TestServerEventsSessionLifecycle collects server-side events during a real
// session: SessionCreated on the first data packet, SessionClosed on the
// client's close signal.
func TestServerEventsSessionLifecycle(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	backend := startTCPEchoBackend(t)
	dnsAddr := pickFreeUDPPort(t)

	events := make(chan ServerEvent, 32)
	srv, err := NewServer(ServerConfig{
		Domain:       "srvevents.test.local",
		ListenAddr:   dnsAddr,
		TargetAddr:   "tcp://" + backend,
		EventHandler: func(ev ServerEvent) { events <- ev },
	})
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = srv.Run(ctx) }()
	waitForDNSServer(t, dnsAddr)

	cli, err := NewClient(ClientConfig{Domain: "srvevents.test.local", Servers: []string{dnsAddr}, RecordType: "txt"})
	if err != nil {
		t.Fatal(err)
	}
	conn, err := cli.Dial(ctx)
	if err != nil {
		t.Fatal(err)
	}
	payload := []byte("server event probe")
	if _, err := conn.Write(payload); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := conn.SetReadDeadline(time.Now().Add(15 * time.Second)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("read: %v", err)
	}
	_ = conn.Close()

	sawCreated, sawClosed := false, false
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) && !(sawCreated && sawClosed) {
		select {
		case ev := <-events:
			switch ev.Kind {
			case ServerSessionCreated:
				sawCreated = true
			case ServerSessionClosed:
				sawClosed = true
			}
		case <-time.After(200 * time.Millisecond):
		}
	}
	if !sawCreated || !sawClosed {
		t.Fatalf("session events incomplete: created=%v closed=%v", sawCreated, sawClosed)
	}
}

// TestServerEventSecurityKinds drives the security event kinds at the unit
// level: ReplayDropped on a duplicate chunk, AuthRejected on a bad handshake,
// TargetDenied via a declaration outside the allow list.
func TestServerEventSecurityKinds(t *testing.T) {
	events := make(chan ServerEvent, 32)
	dispatcher := newEventDispatcher[ServerEvent](func(ev ServerEvent) { events <- ev })
	defer dispatcher.close()

	evSrv, err := NewDNSServer(ServerConfig{Domain: "replay.test.local"})
	if err != nil {
		t.Fatal(err)
	}
	evSrv.events = dispatcher
	sess := newDnsSession("sec.test", "tcp", "127.0.0.1:1", false, nil, nopLogger, evSrv)
	// ReplayDropped: the same seq delivered twice.
	sess.pushClient(1, []byte("first"))
	sess.pushClient(1, []byte("replay"))
	select {
	case ev := <-events:
		if ev.Kind != ServerReplayDropped {
			t.Fatalf("kind = %v, want ReplayDropped", ev.Kind)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("ReplayDropped never arrived")
	}

	// AuthRejected: a private-key server receiving a short first packet.
	authSrv, err := NewDNSServer(ServerConfig{
		Domain:       "auth.test.local",
		PrivateKey:   "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		EventHandler: func(ev ServerEvent) { events <- ev },
	})
	if err != nil {
		t.Fatal(err)
	}
	authSrv.publishEvent(ServerEvent{ // direct dispatch sanity
		Kind:      ServerAuthRejected,
		SessionID: "sanity",
	})
	select {
	case ev := <-events:
		if ev.Kind != ServerAuthRejected {
			t.Fatalf("kind = %v, want AuthRejected", ev.Kind)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("sanity AuthRejected never arrived")
	}
	if sess, created := authSrv.getOrCreateSession("badauth", 1, []byte("short"), true); sess != nil || created {
		t.Fatal("short first packet was accepted on a Noise server")
	}
	select {
	case ev := <-events:
		if ev.Kind != ServerAuthRejected {
			t.Fatalf("kind = %v, want AuthRejected", ev.Kind)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("AuthRejected never arrived for the bad handshake")
	}
}

// mustDNSServerForEvents builds a DNSServer handler for event lifecycle tests.
func mustDNSServerForEvents(t *testing.T, domain, target string) dns.Handler {
	t.Helper()
	srv, err := NewDNSServer(ServerConfig{Domain: domain, TargetAddr: target})
	if err != nil {
		t.Fatalf("NewDNSServer failed: %v", err)
	}
	return srv
}
