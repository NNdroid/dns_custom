package dnstunnel

import (
	"context"
	"encoding/binary"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func TestParseQueryNameRejectsMalformedInput(t *testing.T) {
	domain := "tunnel.example.com"
	valid := buildQueryName(domain, "session", 11, 7, 3, flagData, []byte("payload"))
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
		"bad query sequence":  queryWith(0, "x"),
		"bad acknowledgement": queryWith(1, "x"),
		"unknown flag":        queryWith(2, "X"),
		"bad data sequence":   queryWith(3, "x"),
		"bad base32 payload":  queryWith(4, "not-valid!"),
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
		buildQueryName("t.example", "s", 1, 0, 0, flagPoll, nil),
		buildQueryName("a-very-long-tunnel-name.example.com", "0123456789abcdef", 12345, 67890, 7, flagData, make([]byte, 38)),
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
				if got := fitDownstreamPayload(qname, requested, qtype); got != want {
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
	sess := newDnsSession("backpressure", "tcp", "127.0.0.1:1", false, nil, nopLogger)
	sess.serverBuf.Write(make([]byte, dnsTunnelServerBufferLimit))
	done := make(chan bool, 1)
	go func() { done <- sess.pushServer([]byte{1}) }()

	select {
	case <-done:
		t.Fatal("pushServer returned before downstream buffer space was available")
	case <-time.After(20 * time.Millisecond):
	}

	if frame := sess.serveDownstream(dns.TypeTXT, testPollQName, dnsTunnelMaxUDPResponse); len(frame) == 0 {
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

	path := newDNSPath(endpoint.URL)
	defer path.close()
	msg := new(dns.Msg)
	msg.SetQuestion("example.com.", dns.TypeA)
	if _, err := path.exchange(context.Background(), msg); err == nil || !strings.Contains(err.Error(), "larger") {
		t.Fatalf("oversized DoH response error = %v", err)
	}
}

func BenchmarkBuildQueryName(b *testing.B) {
	payload := make([]byte, 38)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = buildQueryName("tunnel.example.com.", "0123456789abcdef", uint32(i), 10, 11, flagData, payload)
	}
}
