package dnstunnel

import (
	"bytes"
	"context"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"
)

// TestWarnThrottleLimitsEmissions pins the log-flood hardening: a condition an
// attacker can trigger at query rate emits at most one warning per window, and
// the suppressed count surfaces in the admitted line.
func TestWarnThrottleLimitsEmissions(t *testing.T) {
	core, logs := observer.New(zapcore.InfoLevel)
	log := zap.New(core).Sugar()

	var th warnThrottle
	th.warnf(log, time.Millisecond, "flood %d", 1) // admitted
	th.warnf(log, time.Millisecond, "flood %d", 2) // suppressed
	th.warnf(log, time.Millisecond, "flood %d", 3) // suppressed
	if n := logs.Len(); n != 1 {
		t.Fatalf("emissions within one window = %d, want 1", n)
	}

	// After the window the next emission is admitted and carries the count of
	// the ones dropped in between.
	time.Sleep(2 * time.Millisecond)
	th.warnf(log, time.Hour, "flood %d", 4)
	if n := logs.Len(); n != 2 {
		t.Fatalf("emissions after the window = %d, want 2", n)
	}
	msg := logs.All()[1].Message
	if !bytes.Contains([]byte(msg), []byte("flood 4")) || !bytes.Contains([]byte(msg), []byte("suppressed 2")) {
		t.Fatalf("message %q does not carry the original text and the suppressed count", msg)
	}
}

// TestAnswerCaseValidationDropsSpoofedAndFallsBack pins the 0x20 defense: an
// answer that does not echo the query's QNAME case is refused, and after a
// short consecutive streak the check disables itself so a case-normalizing
// resolver path keeps working.
func TestAnswerCaseValidationDropsSpoofedAndFallsBack(t *testing.T) {
	tr := &DNSClientTunnel{log: nopLogger}

	sent := new(dns.Msg)
	sent.SetQuestion("SeSsIoN.1.0.P.0.tunnel2.example.com.", dns.TypeTXT)

	if !tr.answerCaseOK(sent, sent) {
		t.Fatal("answer echoing the exact case was rejected")
	}

	spoof := new(dns.Msg)
	spoof.SetQuestion("session.1.0.p.0.tunnel2.example.com.", dns.TypeTXT)
	for i := 0; i < dnsTunnelCaseFailLimit-1; i++ {
		if tr.answerCaseOK(sent, spoof) {
			t.Fatal("spoofed answer accepted before the fallback threshold")
		}
	}
	if tr.caseCheckDisabled.Load() {
		t.Fatal("validation disabled before reaching the threshold")
	}
	if tr.answerCaseOK(sent, spoof) {
		t.Fatal("mismatch at the threshold was accepted")
	}
	if !tr.caseCheckDisabled.Load() {
		t.Fatal("validation not disabled after the threshold")
	}
	if !tr.answerCaseOK(sent, spoof) {
		t.Fatal("answers must pass once the fallback disabled the check")
	}
}

// TestSkipToBeyondWindowIsClamped pins the skipTo clamp: a forged skipTo far
// ahead of anything the client has seen must not fling recvNext across the
// stream, while a legitimate in-window skipTo still applies.
func TestSkipToBeyondWindowIsClamped(t *testing.T) {
	tr := &DNSClientTunnel{
		qtype:    dns.TypeTXT,
		log:      nopLogger,
		inBuf:    new(bytes.Buffer),
		recvNext: 1,
		recvOOO:  make(map[uint32][]byte),
	}
	tr.inCond = sync.NewCond(&tr.inMu)

	forged := encodeDownstreamFrame(2, 50000, []byte("chunk"))
	tr.deliverDownstream(forged)
	if tr.recvNext != 1 {
		t.Fatalf("forged skipTo moved recvNext to %d; the gap-jump must be clamped", tr.recvNext)
	}
	if _, ok := tr.recvOOO[2]; !ok {
		t.Fatal("legitimate chunk of the forged frame was not buffered out-of-order")
	}

	legit := encodeDownstreamFrame(3, 3, []byte("ok"))
	if n := tr.deliverDownstream(legit); n != len("ok") {
		t.Fatalf("in-window skipTo + chunk delivered %d bytes, want %d", n, len("ok"))
	}
	if tr.recvNext != 4 {
		t.Fatalf("recvNext = %d, want 4 after the legitimate skipTo", tr.recvNext)
	}
	if got := tr.inBuf.Bytes(); !bytes.Equal(got, []byte("ok")) {
		t.Fatalf("inBuf = %q, want %q", got, "ok")
	}
}

// TestUpstreamOOOBufferBoundedByBytes pins the byte bound on the server's
// out-of-order upstream buffer: a client sending high-sequence chunks cannot
// pin more than dnsTunnelUpstreamOOOBytes per session.
func TestUpstreamOOOBufferBoundedByBytes(t *testing.T) {
	sess := newDnsSession("bytecap0123456", "", "tcp", "127.0.0.1:1", false, nil, nopLogger, nil)
	payload := bytes.Repeat([]byte{0x77}, 4096)

	// Skip dataSeq 1 and stream out-of-order chunks far past the byte cap.
	for i := uint32(2); i <= 400; i++ {
		sess.pushClient(i, payload)
	}
	if sess.clientOOOBytes > dnsTunnelUpstreamOOOBytes {
		t.Fatalf("clientOOOBytes = %d exceeds the %d byte cap", sess.clientOOOBytes, dnsTunnelUpstreamOOOBytes)
	}
	if len(sess.clientOOO) > dnsTunnelUpstreamOOOCap {
		t.Fatalf("clientOOO holds %d entries, cap is %d", len(sess.clientOOO), dnsTunnelUpstreamOOOCap)
	}

	// The in-order chunk completes the prefix: everything still buffered under
	// the cap flows through, the dropped tail is a gap.
	sess.pushClient(1, []byte("start"))
	if sess.clientNext == 2 {
		t.Fatal("contiguous buffered chunks were not drained after the in-order chunk")
	}
	if sess.clientOOOBytes < 0 {
		t.Fatalf("clientOOOBytes accounting went negative: %d", sess.clientOOOBytes)
	}
}

// TestCloseQueryIsAuthenticatedOnNoiseServers pins the teardown hardening: a
// payload-free (forged) close of a Noise session is refused, while the real
// client's sealed close removes the session.
func TestCloseQueryIsAuthenticatedOnNoiseServers(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	dnsAddr := pickFreeUDPPort(t)
	kp, err := GenerateNoiseKeyPair()
	if err != nil {
		t.Fatalf("generate keypair: %v", err)
	}
	privHex, _ := FormatNoiseKey(kp.PrivateKey)
	pubHex, _ := FormatNoiseKey(kp.PublicKey)

	srv, err := NewServer(ServerConfig{
		ListenAddr: dnsAddr,
		Domain:     "close.test.local",
		PrivateKey: privHex,
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	go func() { _ = srv.Run(ctx) }()
	waitForDNSServer(t, dnsAddr)

	cli, err := NewClient(ClientConfig{
		Domain:     "close.test.local",
		Servers:    []string{dnsAddr},
		RecordType: "txt",
		PublicKey:  pubHex,
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	conn, err := cli.Dial(ctx)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	tun, ok := conn.(*DNSClientTunnel)
	if !ok {
		t.Fatal("Dial did not return a DNSClientTunnel")
	}
	sessionID := tun.session

	// A forged payload-free close (what any observer of one QNAME could send)
	// must be refused: the answer is NXDOMAIN and the session survives.
	forged := buildQueryName("tunnel2", "close.test.local", sessionID, 999, 0, 0, flagClose, nil)
	m := new(dns.Msg)
	m.SetQuestion(forged, dns.TypeTXT)
	m.RecursionDesired = false
	resp, err := dns.Exchange(m, dnsAddr)
	if err != nil {
		t.Fatalf("forged close exchange failed: %v", err)
	}
	if resp.Rcode != dns.RcodeNameError {
		t.Fatalf("forged close answered rcode %d, want NXDOMAIN", resp.Rcode)
	}
	if _, alive := srv.handler.sessions[sessionID]; !alive {
		t.Fatal("forged close killed a Noise session")
	}

	// The real client close carries the AEAD tag and tears the session down.
	if err := conn.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if !waitForSessionGone(t, srv, sessionID) {
		t.Fatal("authenticated close did not remove the session")
	}
}

// TestCloseQueryOnPSKServersRequiresProof pins the PSK-only close gate: the
// same HMAC proof the capability probe carried must protect the close signal.
func TestCloseQueryOnPSKServersRequiresProof(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	dnsAddr := pickFreeUDPPort(t)
	srv, err := NewServer(ServerConfig{
		ListenAddr: dnsAddr,
		Domain:     "pskclose.test.local",
		TargetAddr: "tcp://127.0.0.1:1",
		PSKs:       []string{"hunter2"},
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	go func() { _ = srv.Run(ctx) }()
	waitForDNSServer(t, dnsAddr)

	cli, err := NewClient(ClientConfig{
		Domain:     "pskclose.test.local",
		Servers:    []string{dnsAddr},
		RecordType: "txt",
		PSK:        "hunter2",
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	conn, err := cli.Dial(ctx)
	if err != nil {
		t.Fatalf("Dial on a PSK server: %v", err)
	}
	tun, ok := conn.(*DNSClientTunnel)
	if !ok {
		t.Fatal("Dial did not return a DNSClientTunnel")
	}
	sessionID := tun.session

	// Close without the proof is refused.
	forged := buildQueryName("tunnel2", "pskclose.test.local", sessionID, 999, 0, 0, flagClose, nil)
	m := new(dns.Msg)
	m.SetQuestion(forged, dns.TypeTXT)
	m.RecursionDesired = false
	resp, err := dns.Exchange(m, dnsAddr)
	if err != nil {
		t.Fatalf("proofless close exchange failed: %v", err)
	}
	if resp.Rcode != dns.RcodeNameError {
		t.Fatalf("proofless close answered rcode %d, want NXDOMAIN", resp.Rcode)
	}
	if _, alive := srv.handler.sessions[sessionID]; !alive {
		t.Fatal("proofless close killed a PSK-authenticated session")
	}

	// The client's own close carries the proof and removes the session.
	if err := conn.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if !waitForSessionGone(t, srv, sessionID) {
		t.Fatal("close with proof did not remove the session")
	}
}

// waitForSessionGone polls the server's session table until the session
// disappears (the close signal travels on a detached goroutine) or the budget
// runs out.
func waitForSessionGone(t *testing.T, srv *Server, sessionID string) bool {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		srv.handler.mu.RLock()
		_, alive := srv.handler.sessions[sessionID]
		srv.handler.mu.RUnlock()
		if !alive {
			return true
		}
		time.Sleep(50 * time.Millisecond)
	}
	return false
}
