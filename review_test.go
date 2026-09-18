package dnstunnel

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func TestParseQueryNameRejectsMalformedInput(t *testing.T) {
	domain := "tunnel.example.com"
	valid := buildQueryName("tunnel2", domain, "session", 11, 7, 3, flagData, []byte("payload"))
	session, querySeq, ack, dataSeq, flag, data, err := parseQueryName(domain, valid)
	if err != nil {
		t.Fatalf("valid query rejected: %v", err)
	}
	if session != "session" || querySeq != 11 || ack != 7 || dataSeq != 3 || flag != flagData || string(data) != "payload" {
		t.Fatalf("valid query decoded incorrectly: session=%q query=%d ack=%d data=%d flag=%q payload=%q",
			session, querySeq, ack, dataSeq, flag, data)
	}

	labels := dns.SplitDomainName(valid)
	queryWith := func(index int, value string) string {
		copyLabels := append([]string(nil), labels...)
		copyLabels[index] = value
		return strings.Join(copyLabels, ".") + "."
	}
	cases := map[string]string{
		"bad query sequence":  queryWith(1, "x"),
		"bad acknowledgement": queryWith(2, "x"),
		"unknown flag":        queryWith(3, "X"),
		"bad data sequence":   queryWith(4, "x"),
		"bad base32 payload":  queryWith(5, "not-valid!"),
		"wrong domain":        queryWith(len(labels)-1, "invalid"),
	}
	for name, query := range cases {
		t.Run(name, func(t *testing.T) {
			if _, _, _, _, _, _, err := parseQueryName(domain, query); err == nil {
				t.Fatalf("malformed query was accepted: %s", query)
			}
		})
	}
}

func TestFitDownstreamPayloadMatchesLinearReference(t *testing.T) {
	qnames := []string{
		buildQueryName("tunnel2", "t.example", "s", 1, 0, 0, flagPoll, nil),
		buildQueryName("tunnel2", "a-very-long-tunnel-name.example.com", "0123456789abcdef", 12345, 67890, 7, flagData, make([]byte, 38)),
	}
	for _, qname := range qnames {
		for _, qtype := range []uint16{dns.TypeTXT, dns.TypeNULL, dns.TypeCNAME, dns.TypeA, dns.TypeAAAA} {
			for requested := 0; requested <= 300; requested++ {
				want := requested
				fixed := 12 + (len(qname) + 2) + 4 + (len(qname) + 2) + 10
				budget := dnsTunnelMaxUDPResponse - fixed
				for want > 0 && encodedRdataSize(want, qtype) > budget {
					want--
				}
				if budget <= 0 {
					want = 0
				}
				if got := fitDownstreamPayload(len(qname), requested, qtype); got != want {
					t.Fatalf("qtype=%d requested=%d: got %d want %d", qtype, requested, got, want)
				}
			}
		}
	}
}

func TestConcurrentDownstreamDeliveryStaysOrdered(t *testing.T) {
	const chunks = 256
	tun := newTestTunnel()
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 1; i <= chunks; i++ {
		seq := uint32(i)
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			var payload [4]byte
			binary.BigEndian.PutUint32(payload[:], seq)
			tun.deliverDownstream(encodeDownstreamFrame(seq, 0, payload[:]))
		}()
	}
	close(start)
	wg.Wait()

	got := tun.inBuf.Bytes()
	if len(got) != chunks*4 {
		t.Fatalf("received %d bytes, want %d", len(got), chunks*4)
	}
	for i := 1; i <= chunks; i++ {
		if seq := binary.BigEndian.Uint32(got[(i-1)*4 : i*4]); seq != uint32(i) {
			t.Fatalf("chunk %d contained sequence %d", i, seq)
		}
	}
}

func TestUnknownPollDoesNotCreateSession(t *testing.T) {
	srv, err := NewDNSServer(ServerConfig{Domain: "tunnel.example", TargetAddr: "127.0.0.1:1"})
	if err != nil {
		t.Fatal(err)
	}
	if sess, created := srv.getOrCreateSession("unknown", 0, nil, false); sess != nil || created {
		t.Fatalf("unknown poll returned session=%v created=%v", sess, created)
	}
	srv.mu.RLock()
	count := len(srv.sessions)
	srv.mu.RUnlock()
	if count != 0 {
		t.Fatalf("unknown poll allocated %d sessions", count)
	}
}

func TestServerBufferBackpressureWakesOnDrain(t *testing.T) {
	sess := newDnsSession("backpressure", "tcp", "127.0.0.1:1", false, nil, nopLogger, nil)
	sess.serverBuf.Write(make([]byte, dnsTunnelServerBufferLimit))
	done := make(chan bool, 1)
	go func() { done <- sess.pushServer([]byte{1}) }()

	select {
	case <-done:
		t.Fatal("pushServer returned before downstream buffer space was available")
	case <-time.After(20 * time.Millisecond):
	}

	if frame := sess.serveDownstream(dns.TypeTXT, len(testPollQName), dnsTunnelMaxUDPResponse); len(frame) == 0 {
		t.Fatal("serveDownstream did not drain the buffer")
	}
	select {
	case ok := <-done:
		if !ok {
			t.Fatal("pushServer reported a closed session")
		}
	case <-time.After(time.Second):
		t.Fatal("pushServer was not woken after downstream drain")
	}
}

func TestDoHResponseSizeIsBounded(t *testing.T) {
	endpoint := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(make([]byte, maxDNSWireMessageSize+1))
	}))
	defer endpoint.Close()

	path := newDNSPath(endpoint.URL, nil, nil)
	defer path.close()
	msg := new(dns.Msg)
	msg.SetQuestion("example.com.", dns.TypeA)
	if _, err := path.exchange(context.Background(), msg); err == nil || !strings.Contains(err.Error(), "larger") {
		t.Fatalf("oversized DoH response error = %v", err)
	}
}

func TestDNSPathRejectsAuthoritativeNXDOMAIN(t *testing.T) {
	addr := startTestDNSServer(t, dns.HandlerFunc(func(w dns.ResponseWriter, req *dns.Msg) {
		reply := new(dns.Msg)
		reply.SetRcode(req, dns.RcodeNameError)
		_ = w.WriteMsg(reply)
	}))
	path := newDNSPath(addr, nil, nil)
	defer path.close()
	msg := new(dns.Msg)
	msg.SetQuestion("missing.tunnel.example.", dns.TypeTXT)
	_, err := path.exchange(context.Background(), msg)
	if !errors.Is(err, ErrServerSessionGone) {
		t.Fatalf("NXDOMAIN error = %v, want ErrServerSessionGone", err)
	}
}

func TestDoHPathRejectsAuthoritativeNXDOMAIN(t *testing.T) {
	endpoint := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		wire, err := io.ReadAll(req.Body)
		if err != nil {
			t.Error(err)
			return
		}
		query := new(dns.Msg)
		if err := query.Unpack(wire); err != nil {
			t.Error(err)
			return
		}
		reply := new(dns.Msg)
		reply.SetRcode(query, dns.RcodeNameError)
		packed, err := reply.Pack()
		if err != nil {
			t.Error(err)
			return
		}
		w.Header().Set("Content-Type", "application/dns-message")
		_, _ = w.Write(packed)
	}))
	defer endpoint.Close()
	path := newDNSPath(endpoint.URL, nil, nil)
	defer path.close()
	msg := new(dns.Msg)
	msg.SetQuestion("missing.tunnel.example.", dns.TypeTXT)
	_, err := path.exchange(context.Background(), msg)
	if !errors.Is(err, ErrServerSessionGone) {
		t.Fatalf("DoH NXDOMAIN error = %v, want ErrServerSessionGone", err)
	}
}

func TestClosedSessionIsRemovedImmediately(t *testing.T) {
	srv, err := NewDNSServer(ServerConfig{Domain: "tunnel.example", TargetAddr: "127.0.0.1:1"})
	if err != nil {
		t.Fatal(err)
	}
	sess, created := srv.getOrCreateSession("closed-session", 1, []byte("x"), true)
	if sess == nil || !created {
		t.Fatal("session was not created")
	}
	sess.close()
	srv.mu.RLock()
	_, stillPresent := srv.sessions[sess.sessionID]
	srv.mu.RUnlock()
	if stillPresent {
		t.Fatal("closed session remained addressable")
	}
	if got, created := srv.getOrCreateSession(sess.sessionID, 0, nil, false); got != nil || created {
		t.Fatalf("closed session lookup = (%v, %v), want (nil, false)", got, created)
	}
}

func TestClosedSessionIsRetainedUntilDownstreamTailDrains(t *testing.T) {
	srv, err := NewDNSServer(ServerConfig{Domain: "tunnel.example", TargetAddr: "127.0.0.1:1"})
	if err != nil {
		t.Fatal(err)
	}
	sess, created := srv.getOrCreateSession("closed-tail", 1, []byte("x"), true)
	if sess == nil || !created || !sess.pushServer([]byte("tail")) {
		t.Fatal("session with downstream tail was not prepared")
	}
	sess.close()
	srv.mu.RLock()
	_, retained := srv.sessions[sess.sessionID]
	srv.mu.RUnlock()
	if !retained {
		t.Fatal("closed session was removed before its downstream tail could be read")
	}
	if got := sess.popServerNow(16, false); string(got) != "tail" {
		t.Fatalf("downstream tail = %q, want tail", got)
	}
	srv.mu.RLock()
	_, retained = srv.sessions[sess.sessionID]
	srv.mu.RUnlock()
	if retained {
		t.Fatal("closed session remained after its downstream tail drained")
	}
}

func TestWriteSurvivesMoreThanLegacyRetryLimit(t *testing.T) {
	const domain = "recover.tunnel.example"
	backend := startTCPEchoBackend(t)
	srv, err := NewDNSServer(ServerConfig{Domain: domain, TargetAddr: backend})
	if err != nil {
		t.Fatal(err)
	}
	var failed atomic.Int32
	handler := dns.HandlerFunc(func(w dns.ResponseWriter, req *dns.Msg) {
		if len(req.Question) > 0 {
			_, _, _, _, flag, data, parseErr := parseQueryName(domain, req.Question[0].Name)
			if parseErr == nil && flag == flagData && len(data) > 0 && failed.Add(1) <= 6 {
				reply := new(dns.Msg)
				reply.SetRcode(req, dns.RcodeServerFailure)
				_ = w.WriteMsg(reply)
				return
			}
		}
		srv.ServeDNS(w, req)
	})
	addr := startTestDNSServer(t, handler)
	cli, err := NewClient(ClientConfig{Domain: domain, Servers: []string{addr}, RecordType: "txt"})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	conn, err := cli.Dial(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(12 * time.Second))
	if _, err := conn.Write([]byte("r")); err != nil {
		t.Fatalf("write did not recover: %v", err)
	}
	got := make([]byte, 1)
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("echo after recovery: %v", err)
	}
	if string(got) != "r" || failed.Load() < 6 {
		t.Fatalf("echo=%q failedAttempts=%d", got, failed.Load())
	}
}

func TestWriteRetryStopsAtDeadline(t *testing.T) {
	const domain = "deadline.tunnel.example"
	backend := startTCPEchoBackend(t)
	srv, err := NewDNSServer(ServerConfig{Domain: domain, TargetAddr: backend})
	if err != nil {
		t.Fatal(err)
	}
	handler := dns.HandlerFunc(func(w dns.ResponseWriter, req *dns.Msg) {
		if len(req.Question) > 0 {
			_, _, _, _, flag, data, parseErr := parseQueryName(domain, req.Question[0].Name)
			if parseErr == nil && flag == flagData && len(data) > 0 {
				// Simulate a black-holed resolver: the client's normal transport
				// timeout is four seconds, so only the write deadline can unblock it.
				return
			}
		}
		srv.ServeDNS(w, req)
	})
	addr := startTestDNSServer(t, handler)
	cli, err := NewClient(ClientConfig{Domain: domain, Servers: []string{addr}, RecordType: "txt"})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := cli.Dial(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	start := time.Now()
	_ = conn.SetWriteDeadline(start.Add(350 * time.Millisecond))
	if _, err := conn.Write([]byte("x")); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("write error = %v, want deadline exceeded", err)
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("write deadline observed too late: %v", elapsed)
	}
}

func BenchmarkBuildQueryName(b *testing.B) {
	payload := make([]byte, 38)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = buildQueryName("tunnel2", "tunnel.example.com.", "0123456789abcdef", uint32(i), 10, 11, flagData, payload)
	}
}
