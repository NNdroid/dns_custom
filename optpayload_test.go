package dnstunnel

import (
	"bytes"
	"context"
	"io"
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"
	"golang.org/x/crypto/curve25519"
)

// TestTargetResponseCapsRoundTrip pins the v3 target-declaration reply format:
// four bytes [status][udp][caps][optEcho], with two-byte pre-v3 replies still
// parsing (caps and optEcho default to zero).
func TestTargetResponseCapsRoundTrip(t *testing.T) {
	resp := encodeTargetResponse(targetStatusOK, true, capOptPayload|capReliableNULL, 0x7F)
	status, udp, caps, optEcho, ok := decodeTargetResponse(resp)
	if !ok || status != targetStatusOK || !udp || caps != capOptPayload|capReliableNULL || optEcho != 0x7F {
		t.Fatalf("round trip mismatch: ok=%v status=%d udp=%v caps=%d optEcho=%d", ok, status, udp, caps, optEcho)
	}

	// Pre-v3 servers answer two bytes; the client must read them and treat
	// the capability half as absent.
	status, udp, caps, optEcho, ok = decodeTargetResponse(resp[:2])
	if !ok || status != targetStatusOK || !udp || caps != 0 || optEcho != 0 {
		t.Fatalf("legacy reply mismatch: ok=%v status=%d udp=%v caps=%d optEcho=%d", ok, status, udp, caps, optEcho)
	}
}

// TestMaxUpstreamOptChunk sane for the sample deployment: the whole point of
// OPT payload mode is kilobyte upstream chunks.
func TestMaxUpstreamOptChunk(t *testing.T) {
	got := maxUpstreamOptChunk("tunnel.example.com", "tunnel2", "0123456789abcdef")
	if got < 512 {
		t.Fatalf("OPT chunk budget = %d, want >= 512 for a normal domain", got)
	}
	if got > dnsTunnelMaxOptChunk {
		t.Fatalf("OPT chunk budget = %d exceeds the sanity cap %d", got, dnsTunnelMaxOptChunk)
	}
}

// TestServerAcceptsOptPayloadForAuthenticatedSessions pins the server gate:
// the tunnel EDNS0 option carries upstream data only for authenticated
// sessions; unauthenticated ones stay on the QNAME (big-pipe policy).
func TestServerAcceptsOptPayloadForAuthenticatedSessions(t *testing.T) {
	serverPriv, err := ParseNoiseKey("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	if err != nil {
		t.Fatal(err)
	}
	serverPub, err := curve25519.X25519(serverPriv[:], curve25519.Basepoint)
	if err != nil {
		t.Fatal(err)
	}
	var serverPubArr [32]byte
	copy(serverPubArr[:], serverPub)
	clientNS, ePub, err := NewClientNoiseSession(serverPubArr)
	if err != nil {
		t.Fatal(err)
	}

	srv, err := NewDNSServer(ServerConfig{Domain: "opt.test.local", PrivateKey: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"})
	if err != nil {
		t.Fatal(err)
	}

	makeQuery := func(session string, optPayload []byte) *dns.Msg {
		name := buildQueryName("tunnel2", "opt.test.local", session, 1, 0, 2, flagData, nil)
		m := new(dns.Msg)
		m.SetQuestion(name, dns.TypeTXT)
		m.RecursionDesired = true
		m.SetEdns0(dnsTunnelEDNS0UDPSize, false)
		edns := m.IsEdns0()
		edns.Option = append(edns.Option, &dns.EDNS0_LOCAL{Code: ednsOptionTunnelPayload, Data: optPayload})
		return m
	}

	// Authenticated (Noise) session: the OPT payload must reach the stream.
	sess, created := srv.getOrCreateSession("0a1b2c3d4e5f6071", 1, ePub, true, "")
	if !created {
		t.Fatal("Noise session was not created")
	}
	ct := clientNS.SendCipher.Encrypt(2, []byte("hello-over-opt"))
	srv.ServeDNS(nopResponseWriter{}, makeQuery("0a1b2c3d4e5f6071", ct))
	sess.mu.Lock()
	got, _ := io.ReadAll(sess.clientBuf)
	sess.mu.Unlock()
	if string(got) != "hello-over-opt" {
		t.Fatalf("OPT payload did not reach the session stream: %q", got)
	}

	// Unauthenticated session on a keyless server: the OPT payload must be
	// ignored - authenticated() is what gates the extraction.
	plainSrv, err := NewDNSServer(ServerConfig{Domain: "opt.test.local"})
	if err != nil {
		t.Fatal(err)
	}
	sess2, created := plainSrv.getOrCreateSession("0b2c3d4e5f6071a2", 1, nil, true, "")
	if !created || sess2.authenticated() {
		t.Fatalf("unexpected session state: created=%v authed=%v", created, sess2.authenticated())
	}
	plainSrv.ServeDNS(nopResponseWriter{}, makeQuery("0b2c3d4e5f6071a2", ct))
	sess2.mu.Lock()
	got2, _ := io.ReadAll(sess2.clientBuf)
	sess2.mu.Unlock()
	if len(got2) != 0 {
		t.Fatalf("unauthenticated session accepted OPT payload: %q", got2)
	}
}

// nopResponseWriter satisfies dns.ResponseWriter for in-process ServeDNS calls
// that are only exercised for their side effects. ServeDNS touches RemoteAddr
// (rate limiting), which returns nil here - remoteAddrString renders that as "".
type nopResponseWriter struct{ w dns.ResponseWriter }

func (nopResponseWriter) WriteMsg(m *dns.Msg) error   { return nil }
func (nopResponseWriter) Write(b []byte) (int, error) { return 0, nil }
func (nopResponseWriter) RemoteAddr() net.Addr        { return nil }
func (nopResponseWriter) LocalAddr() net.Addr         { return nil }
func (nopResponseWriter) Network() string             { return "udp" }
func (nopResponseWriter) Close() error                { return nil }
func (nopResponseWriter) TsigStatus() error           { return nil }
func (nopResponseWriter) TsigTimersOnly(bool)         {}
func (nopResponseWriter) Hijack()                     {}

// TestOptPayloadEndToEnd drives a Noise+EDNS0 session through an OPT-capable
// server: every path canaries, the session upgrades to binary OPT payloads
// with a kilobyte chunk size, and a multi-kilobyte transfer round-trips.
func TestOptPayloadEndToEnd(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	backend := startTCPEchoBackend(t)
	dnsAddr := pickFreeUDPPort(t)

	kp, err := GenerateNoiseKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	privHex, _ := FormatNoiseKey(kp.PrivateKey)
	pubHex, _ := FormatNoiseKey(kp.PublicKey)

	srv, err := NewServer(ServerConfig{
		ListenAddr: dnsAddr,
		TargetAddr: "tcp://" + backend,
		Domain:     "opte2e.test.local",
		PrivateKey: privHex,
		EDNS0:      true,
	})
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = srv.Run(ctx) }()
	waitForDNSServer(t, dnsAddr)

	cli, err := NewClient(ClientConfig{
		Domain:     "opte2e.test.local",
		Servers:    []string{dnsAddr},
		RecordType: "txt",
		PublicKey:  pubHex,
		EDNS0:      true,
	})
	if err != nil {
		t.Fatal(err)
	}
	conn, err := cli.Dial(ctx)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer conn.Close()
	tun := conn.(*DNSClientTunnel)

	if !tun.optPayload {
		t.Fatal("session did not upgrade to OPT payload mode against a capable server")
	}
	if tun.chunkSize < 512 {
		t.Fatalf("OPT chunk size = %d, want >= 512", tun.chunkSize)
	}

	payload := bytes.Repeat([]byte{0x5A}, 8192)
	if _, err := conn.Write(payload); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := conn.SetReadDeadline(time.Now().Add(15 * time.Second)); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("read: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatal("round-trip payload corrupted over OPT mode")
	}
}

// optStrippingHandler simulates a resolver path that forwards the query but
// drops unknown EDNS0 options: exactly what the canary exists to detect.
type optStrippingHandler struct{ inner dns.Handler }

func (h optStrippingHandler) ServeDNS(w dns.ResponseWriter, req *dns.Msg) {
	if opt := req.IsEdns0(); opt != nil {
		kept := opt.Option[:0]
		for _, o := range opt.Option {
			if e, ok := o.(*dns.EDNS0_LOCAL); !ok || e.Code != ednsOptionTunnelPayload {
				kept = append(kept, o)
			}
		}
		opt.Option = kept
	}
	h.inner.ServeDNS(w, req)
}

// TestOptCanaryFallsBackToStrippingPath pins the fallback: a session whose
// only path strips the tunnel option stays in QNAME mode and still works.
func TestOptCanaryFallsBackToStrippingPath(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	backend := startTCPEchoBackend(t)
	dnsAddr := pickFreeUDPPort(t)

	srv, err := NewServer(ServerConfig{
		ListenAddr: dnsAddr,
		TargetAddr: "tcp://" + backend,
		Domain:     "optfallback.test.local",
		EDNS0:      true,
	})
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = srv.Run(ctx) }()
	waitForDNSServer(t, dnsAddr)

	// The client talks to the stripping proxy, which forwards to the real
	// server minus the tunnel option.
	proxyAddr := startTestDNSServer(t, optStrippingHandler{inner: srv.handler})

	cli, err := NewClient(ClientConfig{
		Domain:     "optfallback.test.local",
		Servers:    []string{proxyAddr},
		RecordType: "txt",
		EDNS0:      true,
	})
	if err != nil {
		t.Fatal(err)
	}
	conn, err := cli.Dial(ctx)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer conn.Close()
	tun := conn.(*DNSClientTunnel)

	if tun.optPayload {
		t.Fatal("session upgraded to OPT payloads despite an OPT-stripping path")
	}

	payload := []byte("fallback works")
	if _, err := conn.Write(payload); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := conn.SetReadDeadline(time.Now().Add(15 * time.Second)); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("read: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatal("QNAME-mode fallback corrupted the stream")
	}
}

// nullFilterHandler simulates a resolver path that forwards TXT normally but
// swallows NULL queries (empty NOERROR, no answers): exactly the NULL-filtering
// behavior the NULL canary exists to detect.
type nullFilterHandler struct{ inner dns.Handler }

func (h nullFilterHandler) ServeDNS(w dns.ResponseWriter, req *dns.Msg) {
	if req.Question[0].Qtype == dns.TypeNULL {
		empty := new(dns.Msg)
		empty.SetRcode(req, dns.RcodeSuccess)
		_ = w.WriteMsg(empty)
		return
	}
	h.inner.ServeDNS(w, req)
}

// TestReliableNULLEndToEnd pins the T5 upgrade: a Noise+EDNS0 session against
// a capable server upgrades TXT to binary NULL rdata with the reliable window,
// and a transfer round-trips through the framed NULL path.
func TestReliableNULLEndToEnd(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	backend := startTCPEchoBackend(t)
	dnsAddr := pickFreeUDPPort(t)

	kp, err := GenerateNoiseKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	privHex, _ := FormatNoiseKey(kp.PrivateKey)
	pubHex, _ := FormatNoiseKey(kp.PublicKey)

	srv, err := NewServer(ServerConfig{
		ListenAddr: dnsAddr,
		TargetAddr: "tcp://" + backend,
		Domain:     "nulle2e.test.local",
		PrivateKey: privHex,
		EDNS0:      true,
	})
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = srv.Run(ctx) }()
	waitForDNSServer(t, dnsAddr)

	cli, err := NewClient(ClientConfig{
		Domain:     "nulle2e.test.local",
		Servers:    []string{dnsAddr},
		RecordType: "txt",
		PublicKey:  pubHex,
		EDNS0:      true,
	})
	if err != nil {
		t.Fatal(err)
	}
	conn, err := cli.Dial(ctx)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer conn.Close()
	tun := conn.(*DNSClientTunnel)

	if tun.qtype != dns.TypeNULL || !tun.nullReliable {
		t.Fatalf("session did not upgrade to reliable NULL: qtype=%s nullReliable=%v",
			dns.TypeToString[tun.qtype], tun.nullReliable)
	}

	payload := bytes.Repeat([]byte{0xC3}, 4096)
	if _, err := conn.Write(payload); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := conn.SetReadDeadline(time.Now().Add(15 * time.Second)); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("read: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatal("round-trip payload corrupted over reliable NULL")
	}
}

// TestNullCanaryFallsBackToTXT pins the upgrade guard: a path that filters
// NULL queries keeps the session on TXT (and on the framed TXT transport),
// while the OPT capability can still upgrade independently.
func TestNullCanaryFallsBackToTXT(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	backend := startTCPEchoBackend(t)
	dnsAddr := pickFreeUDPPort(t)

	kp, err := GenerateNoiseKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	privHex, _ := FormatNoiseKey(kp.PrivateKey)
	pubHex, _ := FormatNoiseKey(kp.PublicKey)

	srv, err := NewServer(ServerConfig{
		ListenAddr: dnsAddr,
		TargetAddr: "tcp://" + backend,
		Domain:     "nullfallback.test.local",
		PrivateKey: privHex,
		EDNS0:      true,
	})
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = srv.Run(ctx) }()
	waitForDNSServer(t, dnsAddr)

	proxyAddr := startTestDNSServer(t, nullFilterHandler{inner: srv.handler})

	cli, err := NewClient(ClientConfig{
		Domain:     "nullfallback.test.local",
		Servers:    []string{proxyAddr},
		RecordType: "txt",
		PublicKey:  pubHex,
		EDNS0:      true,
	})
	if err != nil {
		t.Fatal(err)
	}
	conn, err := cli.Dial(ctx)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer conn.Close()
	tun := conn.(*DNSClientTunnel)

	if tun.qtype != dns.TypeTXT || tun.nullReliable {
		t.Fatalf("session upgraded despite a NULL-filtering path: qtype=%s nullReliable=%v",
			dns.TypeToString[tun.qtype], tun.nullReliable)
	}
	if !tun.optPayload {
		t.Fatal("OPT capability should have upgraded independently of NULL")
	}

	payload := []byte("txt fallback works")
	if _, err := conn.Write(payload); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := conn.SetReadDeadline(time.Now().Add(15 * time.Second)); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("read: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatal("TXT fallback corrupted the stream")
	}
}

// TestServerReliableNULLWindow pins the server side: a session whose
// capability exchange carried the canary serves NULL through the framed
// reliable window; one without it keeps the legacy best-effort path.
func TestServerReliableNULLWindow(t *testing.T) {
	s := newDnsSession("nullreliable0123", "", "tcp", "127.0.0.1:1", false, nil, nopLogger, nil)
	s.reliableNULL = true
	if !s.pushServer(bytes.Repeat([]byte{0x71}, 2048)) {
		t.Fatal("pushServer rejected payload")
	}
	chunks := s.serveDownstream(dns.TypeNULL, 70, dnsTunnelEDNS0UDPSize)
	if len(chunks) < 2 {
		t.Fatalf("reliable NULL served %d chunks per poll, want >= 2 (packed window)", len(chunks))
	}
	for _, c := range chunks {
		seq, _, payload, ok := decodeDownstreamFrame(c)
		if !ok || seq == 0 || len(payload) == 0 {
			t.Fatalf("reliable NULL chunk did not decode as a frame: ok=%v seq=%d", ok, seq)
		}
	}

	// Without the capability, NULL stays best-effort: a single unframed chunk.
	legacy := newDnsSession("nulllegacy012345", "", "tcp", "127.0.0.1:1", false, nil, nopLogger, nil)
	if !legacy.pushServer(bytes.Repeat([]byte{0x72}, 2048)) {
		t.Fatal("pushServer rejected payload")
	}
	legacyChunks := legacy.serveDownstream(dns.TypeNULL, 70, dnsTunnelEDNS0UDPSize)
	if len(legacyChunks) != 1 || len(legacyChunks[0]) != 800 {
		t.Fatalf("legacy NULL served %d chunks (first %d bytes), want one best-effort 800-byte chunk",
			len(legacyChunks), len(firstChunk(legacyChunks)))
	}
	// Raw payload bytes, not a frame header: byte 0 is the filler, not seq 1.
	if legacyChunks[0][0] != 0x72 {
		t.Fatalf("legacy NULL first byte = %#x, want raw filler 0x72", legacyChunks[0][0])
	}
}
