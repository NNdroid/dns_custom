package dnstunnel

import (
	"bytes"
	"testing"

	"github.com/miekg/dns"
)

func TestLongDataQNameDoesNotPoisonLaterPoll(t *testing.T) {
	s := newDnsSession("0123456789abcdef", "tcp", "127.0.0.1:1", false, nil, nopLogger, nil)
	payload := bytes.Repeat([]byte{0x5a}, 96)
	if !s.pushServer(payload) {
		t.Fatal("pushServer rejected payload")
	}

	// A near-limit DATA QNAME may leave no room for a useful TXT answer. That
	// query should simply carry no downstream bytes; it must not permanently
	// reduce the session's later POLL capacity.
	if got := s.serveDownstream(dns.TypeTXT, 251, dnsTunnelMaxUDPResponse); len(got) != 0 {
		t.Fatalf("long QNAME unexpectedly carried %d downstream bytes", len(got))
	}
	if s.serverBuf.Len() != len(payload) {
		t.Fatalf("long QNAME consumed server data: have=%d want=%d", s.serverBuf.Len(), len(payload))
	}

	got := s.serveDownstream(dns.TypeTXT, 70, dnsTunnelMaxUDPResponse)
	if len(got) == 0 {
		t.Fatal("short poll QNAME could not fetch downstream data after long DATA QNAME")
	}
}

func TestOversizedRetransmitWaitsForShortPoll(t *testing.T) {
	s := newDnsSession("0123456789abcdef", "tcp", "127.0.0.1:1", false, nil, nopLogger, nil)
	payload := bytes.Repeat([]byte{0xa5}, 160)
	if !s.pushServer(payload) {
		t.Fatal("pushServer rejected payload")
	}

	first := s.serveDownstream(dns.TypeTXT, 70, dnsTunnelMaxUDPResponse)
	if len(first) == 0 {
		t.Fatal("short poll did not create first downstream chunk")
	}
	if len(s.serverOut) == 0 {
		t.Fatal("expected retransmit state after first downstream chunk")
	}

	// The existing chunk was sized for the short poll. A later very long DATA
	// query must not emit an oversized/truncated retransmission; keep it queued.
	if got := s.serveDownstream(dns.TypeTXT, 251, dnsTunnelMaxUDPResponse); len(got) != 0 {
		t.Fatalf("long QNAME emitted an existing chunk that does not fit: %d bytes", len(got))
	}
	if len(s.serverOut) == 0 {
		t.Fatal("long QNAME incorrectly discarded retransmit state")
	}

	retry := s.serveDownstream(dns.TypeTXT, 70, dnsTunnelMaxUDPResponse)
	if len(retry) == 0 {
		t.Fatal("short poll could not retransmit queued downstream chunk")
	}
}

func TestEncryptedRetransmitPreservesChunkAcrossQNameBudgets(t *testing.T) {
	key := bytes.Repeat([]byte{0x42}, 32)
	send, err := newNoiseCipherState(key)
	if err != nil {
		t.Fatal(err)
	}
	recv, err := newNoiseCipherState(key)
	if err != nil {
		t.Fatal(err)
	}
	s := newDnsSession("0123456789abcdef", "tcp", "127.0.0.1:1", false, &NoiseSession{SendCipher: send}, nopLogger, nil)
	payload := bytes.Repeat([]byte{0xa5}, 160)
	if !s.pushServer(payload) {
		t.Fatal("pushServer rejected payload")
	}
	first := s.serveDownstream(dns.TypeTXT, 70, dnsTunnelMaxUDPResponse)
	seq, _, encrypted, ok := decodeDownstreamFrame(first)
	if !ok {
		t.Fatal("short poll did not create a framed chunk")
	}
	plain, err := recv.Decrypt(uint64(seq), encrypted)
	if err != nil || !bytes.Equal(plain, payload) {
		t.Fatalf("encrypted payload mismatch: %v", err)
	}
	queuedBytes := s.serverOutBytes
	for i := 0; i < 5; i++ {
		if got := s.serveDownstream(dns.TypeTXT, 251, dnsTunnelMaxUDPResponse); len(got) != 0 {
			t.Fatal("long QNAME emitted oversized encrypted retransmit")
		}
	}
	retry := s.serveDownstream(dns.TypeTXT, 70, dnsTunnelMaxUDPResponse)
	if !bytes.Equal(first, retry) || s.serverOutBytes != queuedBytes || len(s.serverOut) != 1 {
		t.Fatal("deferring retransmit changed ciphertext or retransmission state")
	}
}
