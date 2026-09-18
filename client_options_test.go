package dnstunnel

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// TestTLSConfigPropagation checks that a caller-supplied *tls.Config reaches
// both the DoT path (dns.Client.TLSConfig) and the DoH path
// (http.Transport.TLSClientConfig) instead of being silently dropped.
func TestTLSConfigPropagation(t *testing.T) {
	marker := &tls.Config{MinVersion: tls.VersionTLS12}
	path := newDNSPath("dot://127.0.0.1:853", nil, marker)
	defer path.close()
	if path.dnsCli == nil || path.dnsCli.TLSConfig != marker {
		t.Fatal("custom tls.Config was not propagated to the DoT client")
	}

	doh := newDNSPath("https://resolver.example/dns-query", nil, marker)
	defer doh.close()
	if doh.httpCli == nil {
		t.Fatal("DoH client missing")
	}
	transport := doh.httpCli.Transport.(*http.Transport)
	// The DoH transport stores a clone of the supplied config (it mutates it),
	// so compare semantic content instead of the pointer.
	if transport.TLSClientConfig == nil || transport.TLSClientConfig.MinVersion != marker.MinVersion {
		t.Fatal("custom tls.Config was not propagated to the DoH transport")
	}

	plain := newDNSPath("udp://127.0.0.1:53", nil, marker)
	defer plain.close()
	if plain.dnsCli == nil || plain.dnsCli.TLSConfig != marker {
		t.Fatal("tls.Config not stored on plain-UDP path (harmless, but must be consistent)")
	}
}

// selfSignedCertificate generates a throwaway server certificate for the DoT
// e2e test (loopback, verified via InsecureSkipVerify + ServerName).
func selfSignedCertificate(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "127.0.0.1"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IPAddresses:           []net.IP{net.IPv4(127, 0, 0, 1)},
		DNSNames:              []string{"localhost"},
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: cert}
}

// TestDoTUpstreamWithCustomTLSConfig runs a full tunnel session over a DoT
// upstream whose server presents a self-signed certificate — proving that
// ClientConfig.TLSConfig reaches the actual TLS handshake (and that the
// tunnel forwards correctly over it).
func TestDoTUpstreamWithCustomTLSConfig(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	backend := startTCPEchoBackend(t)
	dnsAddr := pickFreeUDPPort(t)

	srv, err := NewServer(ServerConfig{
		Domain:     "dot.test.local",
		ListenAddr: dnsAddr,
		TargetAddr: "tcp://" + backend,
	})
	if err != nil {
		t.Fatalf("NewServer failed: %v", err)
	}
	go func() { _ = srv.Run(ctx) }()
	waitForDNSServer(t, dnsAddr)

	// Wrap the tunnel's UDP listener with TLS on a second port: the "DoT
	// upstream" here is the tunnel server itself, fronted by TLS.
	cert := selfSignedCertificate(t)
	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", tlsCfg)
	if err != nil {
		t.Fatalf("tls listen: %v", err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go dnsSrvHandleConn(c, srv)
		}
	}()

	cli, err := NewClient(ClientConfig{
		Domain:     "dot.test.local",
		Servers:    []string{"dot://" + ln.Addr().String()},
		RecordType: "txt",
		TLSConfig: &tls.Config{
			InsecureSkipVerify: true, // self-signed test certificate
			ServerName:         "localhost",
		},
	})
	if err != nil {
		t.Fatalf("NewClient failed: %v", err)
	}

	conn, err := cli.Dial(ctx)
	if err != nil {
		t.Fatalf("Dial over DoT upstream failed: %v", err)
	}
	defer conn.Close()

	payload := []byte("DoT upstream with custom TLS config round trip")
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
		t.Fatal("DoT roundtrip mismatch")
	}
}

// TestDialTargetMultiBackend proves per-session target declarations from ONE
// Client: a tcp:// declaration reaches the HTTP backend while a udp://
// declaration reaches the DNS backend, on independent sessions.
func TestDialTargetMultiBackend(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	innerDNS := startTestDNSServer(t, innerDNSHandler())
	httpSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("tcp target hit"))
	}))
	defer httpSrv.Close()
	dnsAddr := pickFreeUDPPort(t)

	srv, err := NewServer(ServerConfig{
		Domain:     "multitarget.test.local",
		ListenAddr: dnsAddr,
		TargetAddr: "tcp://127.0.0.1:1", // default deliberately useless
		AllowTargets: []string{
			"tcp://127.0.0.1:*",
			"udp://127.0.0.1:*",
		},
		// Declarations require authentication: PSK proves the client.
		PSKs: []string{"multi-backend-secret"},
	})
	if err != nil {
		t.Fatalf("NewServer failed: %v", err)
	}
	go func() { _ = srv.Run(ctx) }()
	waitForDNSServer(t, dnsAddr)

	cli, err := NewClient(ClientConfig{
		Domain:     "multitarget.test.local",
		Servers:    []string{dnsAddr},
		RecordType: "txt",
		PSK:        "multi-backend-secret",
	})
	if err != nil {
		t.Fatalf("NewClient failed: %v", err)
	}

	// Session 1: tcp:// declaration reaches the HTTP backend.
	conn, err := cli.DialTarget(ctx, "tcp://"+httpSrv.Listener.Addr().String())
	if err != nil {
		t.Fatalf("DialTarget(tcp) failed: %v", err)
	}
	defer conn.Close()
	req := "GET / HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\r\n"
	if _, err := io.WriteString(conn, req); err != nil {
		t.Fatalf("http write: %v", err)
	}
	if err := conn.SetReadDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), &http.Request{Method: http.MethodGet})
	if err != nil {
		t.Fatalf("http response: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || !bytes.Equal(body, []byte("tcp target hit")) {
		t.Fatalf("tcp target response: status=%d body=%q", resp.StatusCode, body)
	}

	// Session 2: udp:// declaration reaches the DNS backend, same client.
	pconn, err := cli.DialUDPTarget(ctx, "udp://"+innerDNS)
	if err != nil {
		t.Fatalf("DialUDPTarget(udp) failed: %v", err)
	}
	defer pconn.Close()
	q := new(dns.Msg)
	q.SetQuestion("echo.test.", dns.TypeA)
	wire, _ := q.Pack()
	if err := pconn.SetReadDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	if _, err := pconn.WriteTo(wire, nil); err != nil {
		t.Fatalf("dns write: %v", err)
	}
	buf := make([]byte, 1500)
	n, _, err := pconn.ReadFrom(buf)
	if err != nil {
		t.Fatalf("dns read: %v", err)
	}
	r := new(dns.Msg)
	if err := r.Unpack(buf[:n]); err != nil {
		t.Fatalf("dns unpack: %v", err)
	}
	if r.Rcode != dns.RcodeSuccess || len(r.Answer) != 1 {
		t.Fatalf("dns response: rcode=%d answers=%d", r.Rcode, len(r.Answer))
	}

	// Mismatched transports are refused with a clear error.
	if _, err := cli.DialTarget(ctx, "udp://127.0.0.1:53"); err == nil {
		t.Fatal("DialTarget(udp://) must fail")
	}
	if _, err := cli.DialUDPTarget(ctx, "tcp://127.0.0.1:80"); err == nil {
		t.Fatal("DialUDPTarget(tcp://) must fail")
	}
	if _, err := cli.DialTarget(ctx, "quic://127.0.0.1:443"); err == nil {
		t.Fatal("DialTarget(unknown scheme) must fail")
	}
}

// dotResponseWriter adapts a single TLS/TCP connection into a dns.ResponseWriter
// so the test DoT bridge can serve tunnel queries received over it.
type dotResponseWriter struct {
	conn   net.Conn
	remote net.Addr
}

func (w *dotResponseWriter) LocalAddr() net.Addr  { return w.conn.LocalAddr() }
func (w *dotResponseWriter) RemoteAddr() net.Addr { return w.remote }
func (w *dotResponseWriter) WriteMsg(m *dns.Msg) error {
	b, err := m.Pack()
	if err != nil {
		return err
	}
	return writeDNSFrame(w.conn, b)
}
func (w *dotResponseWriter) Write(b []byte) (int, error) { return w.conn.Write(b) }
func (w *dotResponseWriter) Close() error                { return nil }
func (w *dotResponseWriter) TsigStatus() error           { return nil }
func (w *dotResponseWriter) TsigTimersOnly(bool)         {}
func (w *dotResponseWriter) Hijack()                     {}

// writeDNSFrame prefixes a DNS message with the 2-byte TCP length header.
func writeDNSFrame(conn net.Conn, b []byte) error {
	hdr := []byte{byte(len(b) >> 8), byte(len(b))}
	if _, err := conn.Write(hdr); err != nil {
		return err
	}
	_, err := conn.Write(b)
	return err
}

// dnsSrvHandleConn serves DNS-over-TCP messages arriving on one TLS connection
// through the tunnel server's handler, writing each reply back framed.
func dnsSrvHandleConn(c net.Conn, srv *Server) {
	defer c.Close()
	for {
		var hdr [2]byte
		if _, err := io.ReadFull(c, hdr[:]); err != nil {
			return
		}
		msgLen := int(hdr[0])<<8 | int(hdr[1])
		buf := make([]byte, msgLen)
		if _, err := io.ReadFull(c, buf); err != nil {
			return
		}
		m := new(dns.Msg)
		if err := m.Unpack(buf); err != nil {
			return
		}
		srv.handler.ServeDNS(&dotResponseWriter{conn: c, remote: c.RemoteAddr()}, m)
	}
}

// TestNewClientRejectsBadTarget locks in constructor-time target validation:
// unknown schemes and malformed declarations fail at NewClient, not on the
// first dial against a confused server.
func TestNewClientRejectsBadTarget(t *testing.T) {
	base := ClientConfig{
		Domain:  "valid.test.local",
		Servers: []string{"127.0.0.1:53"},
	}
	for _, target := range []string{"quic://127.0.0.1:443", "ftp://host:21", "tcp:", "://host", "udp://"} {
		cfg := base
		cfg.Target = target
		if _, err := NewClient(cfg); err == nil {
			t.Errorf("target %q was accepted", target)
		}
	}
	// Valid declarations still construct.
	for _, target := range []string{"", "tcp://127.0.0.1:22", "udp://10.8.0.1:51820"} {
		cfg := base
		cfg.Target = target
		if _, err := NewClient(cfg); err != nil {
			t.Errorf("target %q rejected: %v", target, err)
		}
	}
}

// TestNewServerRejectsBadConfig covers the server-side constructor checks:
// negative session caps and unreachable allow-list patterns must fail loudly.
func TestNewServerRejectsBadConfig(t *testing.T) {
	base := ServerConfig{Domain: "valid.test.local"}
	if _, err := NewServer(base); err != nil {
		t.Fatalf("valid server config rejected: %v", err)
	}

	cfg := base
	cfg.MaxSessions = -5
	if _, err := NewServer(cfg); err == nil {
		t.Error("negative max_sessions was accepted")
	}

	for _, pattern := range []string{"quic://host:443", "tcp://:80", "tcp://host:http", "://*"} {
		cfg := base
		cfg.AllowTargets = []string{pattern}
		if _, err := NewServer(cfg); err == nil {
			t.Errorf("allow_targets pattern %q was accepted", pattern)
		}
	}
	// Valid patterns still construct.
	for _, patterns := range [][]string{
		{"tcp://127.0.0.1:*"},
		{"udp://10.8.0.*:51820"},
		{"*"},
		{"*.example.com:80"},
		{"tcp://host"},
	} {
		cfg := base
		cfg.AllowTargets = patterns
		if _, err := NewServer(cfg); err != nil {
			t.Errorf("allow_targets %v rejected: %v", patterns, err)
		}
	}
}

// TestPSKAuthenticationE2E locks in the PSK security posture end to end:
// a client with the right PSK authenticates and transfers; a client with the
// wrong PSK and an anonymous client are both refused before any data flows.
func TestPSKAuthenticationE2E(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	backend := startTCPEchoBackend(t)
	dnsAddr := pickFreeUDPPort(t)

	srv, err := NewServer(ServerConfig{
		Domain:     "psk.test.local",
		ListenAddr: dnsAddr,
		TargetAddr: "tcp://" + backend,
		PSKs:       []string{"correct-horse-battery"},
	})
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = srv.Run(ctx) }()
	waitForDNSServer(t, dnsAddr)

	newClient := func(psk string) *Client {
		cli, err := NewClient(ClientConfig{
			Domain:     "psk.test.local",
			Servers:    []string{dnsAddr},
			RecordType: "txt",
			PSK:        psk,
		})
		if err != nil {
			t.Fatalf("NewClient(psk=%q): %v", psk, err)
		}
		return cli
	}

	payload := []byte("psk-authenticated transfer")
	got := make([]byte, len(payload))
	roundtrip := func(cli *Client) error {
		conn, err := cli.Dial(ctx)
		if err != nil {
			return err
		}
		defer conn.Close()
		if _, err := conn.Write(payload); err != nil {
			return err
		}
		if err := conn.SetReadDeadline(time.Now().Add(15 * time.Second)); err != nil {
			return err
		}
		if _, err := io.ReadFull(conn, got); err != nil {
			return err
		}
		return nil
	}

	// 1. Matching PSK: full roundtrip.
	if err := roundtrip(newClient("correct-horse-battery")); err != nil {
		t.Fatalf("roundtrip with correct PSK failed: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatal("roundtrip mismatch")
	}

	// 2. Wrong PSK: probe rejected, Dial fails.
	if err := roundtrip(newClient("wrong-secret")); err == nil {
		t.Fatal("wrong PSK must fail")
	}

	// 3. No PSK: probe rejected, Dial fails.
	if err := roundtrip(newClient("")); err == nil {
		t.Fatal("missing PSK must fail on a PSK server")
	}
}

// TestB3PlaintextServerRefusesDeclarations verifies the hijack fix: a server
// with neither Noise nor PSK refuses non-empty target declarations outright
// (REFUSED), while empty capability probes still answer with the default
// transport.
func TestB3PlaintextServerRefusesDeclarations(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	backend := startTCPEchoBackend(t)
	dnsAddr := pickFreeUDPPort(t)

	srv, err := NewServer(ServerConfig{
		Domain:     "plain.test.local",
		ListenAddr: dnsAddr,
		TargetAddr: "tcp://" + backend,
		// No Noise, no PSKs: fully open plaintext server.
	})
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = srv.Run(ctx) }()
	waitForDNSServer(t, dnsAddr)

	cli, err := NewClient(ClientConfig{
		Domain:     "plain.test.local",
		Servers:    []string{dnsAddr},
		RecordType: "txt",
		Target:     "tcp://10.9.9.9:80",
	})
	if err != nil {
		t.Fatal(err)
	}

	// The declaration is refused with a hard error (REFUSED rcode), not a
	// silent legacy fallback: misconfiguration must surface.
	_, err = cli.Dial(ctx)
	if err == nil {
		t.Fatal("declaration against plaintext server must fail")
	}
	if !strings.Contains(err.Error(), "refuses target declarations") {
		t.Fatalf("error = %v, want refusal", err)
	}
}

// TestQueryRateLimiter exercises the per-source token bucket: a burst within
// the rate is allowed, sustained flooding is dropped, and a disabled limiter
// always allows.
func TestQueryRateLimiter(t *testing.T) {
	srv, err := NewDNSServer(ServerConfig{
		Domain:             "rate.test.local",
		QueryRatePerSource: 5,
	})
	if err != nil {
		t.Fatal(err)
	}
	ra := &net.UDPAddr{IP: net.IPv4(10, 1, 1, 1), Port: 53}

	allowed, dropped := 0, 0
	for i := 0; i < 50; i++ {
		if srv.allowQuery(ra) {
			allowed++
		} else {
			dropped++
		}
	}
	// The bucket starts full (burst = rate) and refills slightly during the
	// loop, so 6 may slip through instead of exactly 5.
	if allowed < 5 || allowed > 6 || dropped != 50-allowed {
		t.Fatalf("burst of 50 at rate 5: allowed=%d dropped=%d, want 5-6 allowed", allowed, dropped)
	}

	// A different source IP has its own bucket.
	other := &net.UDPAddr{IP: net.IPv4(10, 1, 1, 2), Port: 53}
	if !srv.allowQuery(other) {
		t.Fatal("fresh source IP was rate-limited")
	}

	// Unlimited when the rate is 0.
	open, err := NewDNSServer(ServerConfig{Domain: "rate.test.local"})
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 100; i++ {
		if !open.allowQuery(ra) {
			t.Fatal("unlimited limiter dropped a query")
		}
	}
}
