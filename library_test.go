package dnstunnel

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// startTCPEchoBackend runs a TCP echo server and returns its address.
func startTCPEchoBackend(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("tcp echo listen failed: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				_, _ = io.Copy(conn, conn)
			}(c)
		}
	}()
	return ln.Addr().String()
}

// startUDPEchoBackend runs a UDP echo server and returns its address.
func startUDPEchoBackend(t *testing.T) string {
	t.Helper()
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("udp echo listen failed: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	go func() {
		buf := make([]byte, 65535)
		for {
			n, raddr, err := conn.ReadFrom(buf)
			if err != nil {
				return
			}
			if _, err := conn.WriteTo(buf[:n], raddr); err != nil {
				return
			}
		}
	}()
	return conn.LocalAddr().String()
}

// pickFreeUDPPort reserves an ephemeral UDP port for the tunnel server.
func pickFreeUDPPort(t *testing.T) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve port failed: %v", err)
	}
	addr := pc.LocalAddr().String()
	_ = pc.Close()
	return addr
}

// waitForDNSServer polls until the tunnel DNS listener answers, so tests that
// exercise Server.Run do not depend on a startup sleep.
func waitForDNSServer(t *testing.T, addr string) {
	t.Helper()
	c := &dns.Client{Net: "udp", Timeout: 300 * time.Millisecond}
	m := new(dns.Msg)
	m.SetQuestion("probe.test.", dns.TypeTXT)
	for i := 0; i < 30; i++ {
		if _, _, err := c.Exchange(m, addr); err == nil {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("DNS server at %s never became ready", addr)
}

func TestNewClientValidation(t *testing.T) {
	if _, err := NewClient(ClientConfig{Servers: []string{"127.0.0.1:53"}}); err == nil {
		t.Fatal("expected error for missing domain")
	}
	if _, err := NewClient(ClientConfig{Domain: "d.example"}); err == nil {
		t.Fatal("expected error for missing servers")
	}
	if _, err := NewClient(ClientConfig{Domain: "d.example", Servers: []string{"127.0.0.1:53"}, PublicKey: "not-a-key"}); err == nil {
		t.Fatal("expected error for invalid public key")
	}
	// A/AAAA cannot carry authenticated Noise frames.
	if _, err := NewClient(ClientConfig{Domain: "d.example", Servers: []string{"127.0.0.1:53"}, RecordType: "a", PublicKey: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"}); err == nil {
		t.Fatal("expected error for noise over A records")
	}
	if _, err := NewClient(ClientConfig{Domain: "d.example", Servers: []string{"127.0.0.1:53"}, RecordType: "bogus"}); err == nil {
		t.Fatal("expected error for unknown record type")
	}
	if _, err := NewClient(ClientConfig{Domain: "d.example", Servers: []string{"127.0.0.1:53"}}); err != nil {
		t.Fatalf("valid config rejected: %v", err)
	}
}

func TestClientDialerPropagation(t *testing.T) {
	dialer := &net.Dialer{Timeout: 123 * time.Millisecond}
	path := newDNSPath("udp://127.0.0.1:53", dialer)
	defer path.close()
	if path.dnsCli == nil || path.dnsCli.Dialer != dialer {
		t.Fatal("custom dialer was not propagated to the DNS client")
	}

	doh := newDNSPath("https://resolver.example/dns-query", dialer)
	defer doh.close()
	transport, ok := doh.httpCli.Transport.(*http.Transport)
	if !ok || transport.DialContext == nil {
		t.Fatal("custom dialer was not propagated to the DoH transport")
	}
}

func TestNewServerValidation(t *testing.T) {
	if _, err := NewServer(ServerConfig{TargetAddr: "tcp://127.0.0.1:22"}); err == nil {
		t.Fatal("expected error for missing domain")
	}
	if _, err := NewServer(ServerConfig{Domain: "d.example", PrivateKey: "nope"}); err == nil {
		t.Fatal("expected error for invalid private key")
	}
	srv, err := NewServer(ServerConfig{Domain: "d.example"})
	if err != nil {
		t.Fatalf("valid server config rejected: %v", err)
	}
	if srv.cfg.ListenAddr == "" || srv.cfg.TargetAddr == "" {
		t.Fatalf("defaults not applied: %+v", srv.cfg)
	}
}

// TestClientDialThroughServerRun exercises the full public library surface:
// Server.Run binds a real listener, Client.Dial opens a Noise-encrypted stream
// session through it, and the session behaves like a net.Conn including
// deadlines.
func TestClientDialThroughServerRun(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	backend := startTCPEchoBackend(t)
	dnsAddr := pickFreeUDPPort(t)

	kp, err := GenerateNoiseKeyPair()
	if err != nil {
		t.Fatalf("generate keypair failed: %v", err)
	}
	privHex, _ := FormatNoiseKey(kp.PrivateKey)
	pubHex, _ := FormatNoiseKey(kp.PublicKey)

	srv, err := NewServer(ServerConfig{
		ListenAddr: dnsAddr,
		TargetAddr: "tcp://" + backend,
		Domain:     "lib.test.local",
		PrivateKey: privHex,
	})
	if err != nil {
		t.Fatalf("NewServer failed: %v", err)
	}
	runErr := make(chan error, 1)
	go func() { runErr <- srv.Run(ctx) }()
	waitForDNSServer(t, dnsAddr)

	cli, err := NewClient(ClientConfig{
		Domain:     "lib.test.local",
		Servers:    []string{dnsAddr},
		RecordType: "txt",
		PublicKey:  pubHex,
	})
	if err != nil {
		t.Fatalf("NewClient failed: %v", err)
	}

	conn, err := cli.Dial(ctx)
	if err != nil {
		t.Fatalf("Dial failed: %v", err)
	}
	defer conn.Close()

	if conn.LocalAddr() == nil || conn.RemoteAddr() == nil {
		t.Fatal("LocalAddr/RemoteAddr must not be nil")
	}

	payload := []byte("Hello from the library API over a Noise-encrypted DNS tunnel!")
	if _, err := conn.Write(payload); err != nil {
		t.Fatalf("write failed: %v", err)
	}
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("read failed: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("roundtrip mismatch: got %q", string(got))
	}

	// An expired read deadline must unblock a waiting Read.
	if err := conn.SetReadDeadline(time.Now().Add(50 * time.Millisecond)); err != nil {
		t.Fatalf("SetReadDeadline failed: %v", err)
	}
	if _, err := conn.Read(make([]byte, 8)); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("expected deadline error on idle connection, got %v", err)
	}
	_ = conn.SetReadDeadline(time.Time{})

	cancel()
	select {
	case err := <-runErr:
		if err != nil {
			t.Fatalf("Server.Run returned error: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Server.Run did not return after context cancellation")
	}
}

// TestClientDialUDPDatagramBoundaries is the core UDP dial guarantee: datagrams
// survive the tunnel with their boundaries intact, including datagrams far larger
// than one tunnel chunk and datagrams sent back to back.
func TestClientDialUDPDatagramBoundaries(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	backend := startUDPEchoBackend(t)
	dnsAddr := pickFreeUDPPort(t)

	srv, err := NewServer(ServerConfig{
		ListenAddr: dnsAddr,
		TargetAddr: "udp://" + backend,
		Domain:     "udp.test.local",
	})
	if err != nil {
		t.Fatalf("NewServer failed: %v", err)
	}
	go func() { _ = srv.Run(ctx) }()
	waitForDNSServer(t, dnsAddr)

	cli, err := NewClient(ClientConfig{
		Domain:     "udp.test.local",
		Servers:    []string{dnsAddr},
		RecordType: "txt",
	})
	if err != nil {
		t.Fatalf("NewClient failed: %v", err)
	}

	pconn, err := cli.DialUDP(ctx)
	if err != nil {
		t.Fatalf("DialUDP failed: %v", err)
	}
	defer pconn.Close()

	// Sizes chosen to cross chunk boundaries (32-byte upstream chunks, ~117-byte
	// downstream TXT capacity): single-chunk, multi-chunk, and tiny.
	sizes := []int{1, 10, 32, 33, 64, 100, 200, 300, 500, 1024}
	sent := make([][]byte, 0, len(sizes))
	for _, size := range sizes {
		b := make([]byte, size)
		if _, err := rand.Read(b); err != nil {
			t.Fatalf("payload generation failed: %v", err)
		}
		sent = append(sent, b)
		if _, err := pconn.WriteTo(b, nil); err != nil {
			t.Fatalf("WriteTo(size=%d) failed: %v", size, err)
		}
	}

	// All datagrams were written up front, so several sit in the tunnel pipeline
	// at once; reassembly must not merge or split them.
	if err := pconn.SetReadDeadline(time.Now().Add(30 * time.Second)); err != nil {
		t.Fatalf("SetReadDeadline failed: %v", err)
	}
	for i, want := range sent {
		buf := make([]byte, len(want)+64)
		n, raddr, err := pconn.ReadFrom(buf)
		if err != nil {
			t.Fatalf("ReadFrom(%d) failed: %v", i, err)
		}
		if raddr == nil {
			t.Fatal("ReadFrom returned nil address")
		}
		if n != len(want) {
			t.Fatalf("datagram %d boundary lost: got %d bytes, want %d", i, n, len(want))
		}
		if !bytes.Equal(buf[:n], want) {
			t.Fatalf("datagram %d content mismatch", i)
		}
	}

	// The tunnel is now drained: the next read must time out instead of hanging.
	if err := pconn.SetReadDeadline(time.Now().Add(500 * time.Millisecond)); err != nil {
		t.Fatalf("SetReadDeadline failed: %v", err)
	}
	if _, _, err := pconn.ReadFrom(make([]byte, 128)); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("expected timeout on empty tunnel, got %v", err)
	}
}

// TestLegacyDatagramSessionAgainstTCPTargetRefusedAtDial locks in the
// transport-match invariant: a legacy datagram session (UDP marker, no target
// declaration) against a server whose default target is tcp:// is refused when
// the backend dial starts, instead of silently sending datagrams at a TCP port.
func TestLegacyDatagramSessionAgainstTCPTargetRefusedAtDial(t *testing.T) {
	srv, err := NewDNSServer(ServerConfig{
		Domain:     "mismatch.test.local",
		TargetAddr: "tcp://127.0.0.1:22",
	})
	if err != nil {
		t.Fatalf("NewDNSServer failed: %v", err)
	}
	sess, created := srv.getOrCreateSession(udpSessionPrefix+"abcd1234", 1, nil, true)
	if sess == nil || !created {
		t.Fatalf("marker session was not created: sess=%v created=%v", sess, created)
	}
	srv.startBackendForwarder(sess)
	if !sess.closed {
		t.Fatal("datagram session against tcp:// target was not refused")
	}

	// Positive control: the same marker is accepted against a udp:// target.
	okSrv, err := NewDNSServer(ServerConfig{
		Domain:     "match.test.local",
		TargetAddr: "udp://127.0.0.1:5353",
	})
	if err != nil {
		t.Fatalf("NewDNSServer failed: %v", err)
	}
	sess, created = okSrv.getOrCreateSession(udpSessionPrefix+"abcd1234", 1, nil, true)
	if sess == nil || !created {
		t.Fatalf("UDP session against udp:// target was rejected: sess=%v created=%v", sess, created)
	}
	sess.close()
}

// TestMatchTargetPattern unit-tests the allow-list matcher: scheme/host/port
// must all match, host wildcards never cross a dot, and a bare "*" allows all.
func TestMatchTargetPattern(t *testing.T) {
	cases := []struct {
		pattern string
		network string
		addr    string
		want    bool
	}{
		{"tcp://127.0.0.1:22", "tcp", "127.0.0.1:22", true},
		{"tcp://127.0.0.1:22", "udp", "127.0.0.1:22", false},
		{"tcp://127.0.0.1:22", "tcp", "127.0.0.1:23", false},
		{"tcp://127.0.0.1:*", "tcp", "127.0.0.1:2222", true},
		{"udp://10.8.0.*:*", "udp", "10.8.0.5:51820", true},
		{"udp://10.8.0.*:*", "udp", "10.8.1.5:51820", false},
		{"*.example.com:80", "tcp", "a.example.com:80", true},
		{"*.example.com:80", "tcp", "a.b.example.com:80", false},
		{"*", "udp", "169.254.169.254:80", true},
		{"tcp://host:80", "tcp", "host.example.com:80", false},
	}
	for _, tc := range cases {
		if got := matchTargetPattern(tc.pattern, tc.network, tc.addr); got != tc.want {
			t.Errorf("matchTargetPattern(%q, %q, %q) = %v, want %v", tc.pattern, tc.network, tc.addr, got, tc.want)
		}
	}
	// An empty allow list denies everything.
	if targetAllowed(nil, "tcp", "127.0.0.1:22") {
		t.Error("empty allow list must deny declared targets")
	}
}

// TestTargetDeclarationExchange covers the flag 'T' flow end to end over a real
// DNS listener: a declared target is applied, a denied one is reported, and an
// empty declaration (DefaultTarget) reveals the server default's transport.
func TestTargetDeclarationExchange(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	backend := startTCPEchoBackend(t)
	dnsAddr := pickFreeUDPPort(t)

	srv, err := NewServer(ServerConfig{
		ListenAddr: dnsAddr,
		TargetAddr: "tcp://" + backend,
		Domain:     "declare.test.local",
		AllowTargets: []string{
			"tcp://127.0.0.1:*",
			"udp://127.0.0.1:5353",
		},
	})
	if err != nil {
		t.Fatalf("NewServer failed: %v", err)
	}
	go func() { _ = srv.Run(ctx) }()
	waitForDNSServer(t, dnsAddr)

	cli, err := NewClient(ClientConfig{
		Domain:     "declare.test.local",
		Servers:    []string{dnsAddr},
		RecordType: "txt",
		Target:     "tcp://127.0.0.1:22",
	})
	if err != nil {
		t.Fatalf("NewClient failed: %v", err)
	}

	// 1. A declared target passes the allow list and the session reports tcp.
	conn, err := cli.Dial(ctx)
	if err != nil {
		t.Fatalf("Dial with declared target failed: %v", err)
	}
	if tc, ok := conn.(*DNSClientTunnel); ok {
		if got := tc.Transport(); got != "tcp" {
			t.Fatalf("transport = %q, want tcp", got)
		}
	}
	conn.Close()

	// 2. A udp declaration for a Dial against a udp target is a client-side error.
	udpCli, err := NewClient(ClientConfig{
		Domain:     "declare.test.local",
		Servers:    []string{dnsAddr},
		RecordType: "txt",
		Target:     "udp://127.0.0.1:5353",
	})
	if err != nil {
		t.Fatalf("NewClient (udp target) failed: %v", err)
	}
	if _, err := udpCli.Dial(ctx); err == nil {
		t.Fatal("Dial with udp:// target must fail client-side")
	}

	// 3. A target outside the allow list is denied with a clear error.
	deniedCli, err := NewClient(ClientConfig{
		Domain:     "declare.test.local",
		Servers:    []string{dnsAddr},
		RecordType: "txt",
		Target:     "tcp://10.9.9.9:80",
	})
	if err != nil {
		t.Fatalf("NewClient (denied target) failed: %v", err)
	}
	if _, err := deniedCli.Dial(ctx); err == nil || !strings.Contains(err.Error(), "denied") {
		t.Fatalf("denied target error = %v, want 'denied'", err)
	}

	// 4. An empty declaration reveals the default target's transport.
	noTargetCli, err := NewClient(ClientConfig{
		Domain:     "declare.test.local",
		Servers:    []string{dnsAddr},
		RecordType: "txt",
	})
	if err != nil {
		t.Fatalf("NewClient (no target) failed: %v", err)
	}
	transport, err := noTargetCli.DefaultTarget(ctx)
	if err != nil {
		t.Fatalf("DefaultTarget failed: %v", err)
	}
	if transport != "tcp" {
		t.Fatalf("DefaultTarget = %q, want tcp", transport)
	}
}

// TestNoiseTargetDeclarationE2E covers the encrypted declaration path: with
// Noise_NK on, the flag 'T' payload travels as AEAD ciphertext under the
// reserved control sequence and the server must decrypt, apply and answer it.
func TestNoiseTargetDeclarationE2E(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	backend := startTCPEchoBackend(t)
	dnsAddr := pickFreeUDPPort(t)

	kp, err := GenerateNoiseKeyPair()
	if err != nil {
		t.Fatalf("generate keypair failed: %v", err)
	}
	privHex, _ := FormatNoiseKey(kp.PrivateKey)
	pubHex, _ := FormatNoiseKey(kp.PublicKey)

	srv, err := NewServer(ServerConfig{
		ListenAddr: dnsAddr,
		TargetAddr: "tcp://" + backend,
		Domain:     "noise-declare.test.local",
		PrivateKey: privHex,
		AllowTargets: []string{
			"tcp://127.0.0.1:*",
			"udp://127.0.0.1:*",
		},
	})
	if err != nil {
		t.Fatalf("NewServer failed: %v", err)
	}
	go func() { _ = srv.Run(ctx) }()
	waitForDNSServer(t, dnsAddr)

	cli, err := NewClient(ClientConfig{
		Domain:     "noise-declare.test.local",
		Servers:    []string{dnsAddr},
		RecordType: "txt",
		PublicKey:  pubHex,
		Target:     "tcp://" + backend,
	})
	if err != nil {
		t.Fatalf("NewClient failed: %v", err)
	}

	conn, err := cli.Dial(ctx)
	if err != nil {
		t.Fatalf("Dial with declared target over Noise failed: %v", err)
	}
	defer conn.Close()
	if tc, ok := conn.(*DNSClientTunnel); ok {
		if got := tc.Transport(); got != "tcp" {
			t.Fatalf("transport = %q, want tcp", got)
		}
	}

	// A full data round trip proves the declaration did not disturb the Noise
	// sequence spaces (the control sequence must not have collided).
	payload := []byte("round trip over encrypted tunnel with declared target")
	if _, err := conn.Write(payload); err != nil {
		t.Fatalf("write failed: %v", err)
	}
	if err := conn.SetReadDeadline(time.Now().Add(15 * time.Second)); err != nil {
		t.Fatalf("SetReadDeadline failed: %v", err)
	}
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("read failed: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("roundtrip mismatch: got %q", string(got))
	}

	// The encrypted empty declaration (DefaultTarget) must decrypt server-side.
	noTargetCli, err := NewClient(ClientConfig{
		Domain:     "noise-declare.test.local",
		Servers:    []string{dnsAddr},
		RecordType: "txt",
		PublicKey:  pubHex,
	})
	if err != nil {
		t.Fatalf("NewClient (no target) failed: %v", err)
	}
	transport, err := noTargetCli.DefaultTarget(ctx)
	if err != nil {
		t.Fatalf("DefaultTarget over Noise failed: %v", err)
	}
	if transport != "tcp" {
		t.Fatalf("DefaultTarget = %q, want tcp", transport)
	}
}

// TestMaxSessionsCap verifies the concurrent session limit: sessions beyond the
// cap are refused, and capacity frees up once sessions close.
func TestMaxSessionsCap(t *testing.T) {
	srv, err := NewDNSServer(ServerConfig{
		Domain:      "cap.test.local",
		TargetAddr:  "tcp://127.0.0.1:1",
		MaxSessions: 2,
	})
	if err != nil {
		t.Fatalf("NewDNSServer failed: %v", err)
	}
	s1, created := srv.getOrCreateSession("aaaa", 1, nil, true)
	if !created {
		t.Fatal("session 1 was not created")
	}
	s2, created := srv.getOrCreateSession("bbbb", 1, nil, true)
	if !created {
		t.Fatal("session 2 was not created")
	}
	if s3, created := srv.getOrCreateSession("cccc", 1, nil, true); s3 != nil || created {
		t.Fatal("session 3 was created despite the cap")
	}
	// Closing one frees a slot.
	s1.close()
	srv.mu.Lock()
	delete(srv.sessions, "aaaa")
	srv.mu.Unlock()
	s3, created := srv.getOrCreateSession("dddd", 1, nil, true)
	if s3 == nil || !created {
		t.Fatal("session 4 was not created after a slot freed up")
	}
	s2.close()
	s3.close()
}

// TestEDNS0LargerChunks verifies that with edns0 on, the server serves bigger
// downstream chunks than the 512-byte budget allows, end to end.
func TestEDNS0LargerChunks(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	backend := startTCPEchoBackend(t)
	dnsAddr := pickFreeUDPPort(t)

	srv, err := NewServer(ServerConfig{
		ListenAddr: dnsAddr,
		TargetAddr: "tcp://" + backend,
		Domain:     "edns.test.local",
		EDNS0:      true,
	})
	if err != nil {
		t.Fatalf("NewServer failed: %v", err)
	}
	go func() { _ = srv.Run(ctx) }()
	waitForDNSServer(t, dnsAddr)

	cli, err := NewClient(ClientConfig{
		Domain:     "edns.test.local",
		Servers:    []string{dnsAddr},
		RecordType: "txt",
		EDNS0:      true,
	})
	if err != nil {
		t.Fatalf("NewClient failed: %v", err)
	}

	conn, err := cli.Dial(ctx)
	if err != nil {
		t.Fatalf("Dial failed: %v", err)
	}
	defer conn.Close()

	// Larger than one 512-budget chunk would carry; smaller than the 1232 budget.
	payload := make([]byte, 300)
	if _, err := rand.Read(payload); err != nil {
		t.Fatalf("payload generation failed: %v", err)
	}
	go func() {
		_, _ = conn.Write(payload)
	}()
	got := make([]byte, len(payload))
	if err := conn.SetReadDeadline(time.Now().Add(15 * time.Second)); err != nil {
		t.Fatalf("SetReadDeadline failed: %v", err)
	}
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("read failed: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatal("EDNS0 roundtrip mismatch")
	}
}

// TestUDPFramingRoundTrip unit-tests the framing codec used by DialUDP.
func TestUDPFramingRoundTrip(t *testing.T) {
	payloads := [][]byte{{}, []byte("a"), []byte("hello"), make([]byte, udpFrameMaxDatagram)}
	for _, p := range payloads {
		frame := encodeUDPFrame(p)
		if len(frame) != udpFrameHeaderSize+len(p) {
			t.Fatalf("frame size mismatch: got %d, want %d", len(frame), udpFrameHeaderSize+len(p))
		}
		if got := binary.BigEndian.Uint16(frame[:udpFrameHeaderSize]); int(got) != len(p) {
			t.Fatalf("frame length prefix mismatch: got %d, want %d", got, len(p))
		}
		if !bytes.Equal(frame[udpFrameHeaderSize:], p) {
			t.Fatal("frame payload mismatch")
		}
	}
}
