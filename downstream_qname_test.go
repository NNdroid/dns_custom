package dnstunnel

import (
	"bytes"
	"testing"

	"github.com/miekg/dns"
)

// TestTCPCapScalesWithinRetransmitBudget pins the T1 relationship: the TCP
// chunk cap must leave a workable in-flight count inside the retransmission
// byte cap, or the byte cap - not the window - silently clamps TCP-mode
// throughput.
func TestTCPCapScalesWithinRetransmitBudget(t *testing.T) {
	if got := downstreamCapBudget(dns.TypeNULL, false, dnsTunnelTCPResponseSize); got != dnsTunnelTCPMaxServerChunk {
		t.Fatalf("TCP NULL chunk cap = %d, want %d", got, dnsTunnelTCPMaxServerChunk)
	}
	if got := downstreamCapBudget(dns.TypeTXT, false, dnsTunnelTCPResponseSize); got != dnsTunnelTCPMaxServerChunk {
		t.Fatalf("TCP TXT chunk cap = %d, want %d", got, dnsTunnelTCPMaxServerChunk)
	}
	if inFlight := dnsTunnelRetransmitBytes / dnsTunnelTCPMaxServerChunk; inFlight < 64 {
		t.Fatalf("retransmit budget holds only %d TCP chunks; want >= 64 in flight", inFlight)
	}
}

// TestDownstreamPackingServesMultipleChunksPerPoll pins T2: one reply packs
// several downstream chunks as separate answer RRs, so a poll drains more than
// the single-chunk cap per round trip.
func TestDownstreamPackingServesMultipleChunksPerPoll(t *testing.T) {
	s := newDnsSession("packtest0123456", "", "tcp", "127.0.0.1:1", false, nil, nopLogger, nil)
	if !s.pushServer(bytes.Repeat([]byte{0x61}, 2048)) {
		t.Fatal("pushServer rejected payload")
	}
	chunks := s.serveDownstream(dns.TypeTXT, 70, dnsTunnelEDNS0UDPSize)
	if len(chunks) < 2 {
		t.Fatalf("packing served %d chunks per poll, want >= 2", len(chunks))
	}
	total := 0
	for _, c := range chunks {
		_, _, payload, ok := decodeDownstreamFrame(c)
		if !ok || len(payload) == 0 {
			t.Fatalf("packed chunk did not decode: ok=%v len=%d", ok, len(c))
		}
		total += len(payload)
	}
	// Single-chunk service caps one poll at ~663 bytes; packing must beat it.
	if total <= 800 {
		t.Fatalf("packed reply carried only %d bytes, want well above the single-chunk cap", total)
	}
}

// TestDownstreamPackingCarriesRetransmitAlongsideFresh pins the loss-path win:
// with window room left, a poll returns fresh chunks AND the oldest un-acked
// retransmission in the same reply instead of spending a round trip on it.
func TestDownstreamPackingCarriesRetransmitAlongsideFresh(t *testing.T) {
	s := newDnsSession("packtest0123457", "", "tcp", "127.0.0.1:1", false, nil, nopLogger, nil)
	// A small first batch keeps the un-acked chunk small enough that it fits a
	// reply alongside fresh data (a full-size ~650-byte chunk consumes nearly
	// the whole EDNS0 budget on its own).
	if !s.pushServer(bytes.Repeat([]byte{0x62}, 400)) {
		t.Fatal("pushServer rejected payload")
	}
	if got := s.serveDownstream(dns.TypeTXT, 70, dnsTunnelEDNS0UDPSize); len(got) == 0 {
		t.Fatal("first serve produced nothing")
	}
	// No ack arrived: the first batch is un-acked but the window has room.
	if !s.pushServer([]byte("more-data")) {
		t.Fatal("pushServer rejected payload")
	}
	chunks := s.serveDownstream(dns.TypeTXT, 70, dnsTunnelEDNS0UDPSize)
	if len(chunks) < 2 {
		t.Fatalf("retransmit was not packed alongside fresh data: %d chunks", len(chunks))
	}
	// Fresh data is packed first; the oldest un-acked chunk rides at the end.
	last := chunks[len(chunks)-1]
	first, _, _, ok := decodeDownstreamFrame(last)
	if !ok || first != 1 {
		t.Fatalf("oldest un-acked chunk must ride the reply: got seq=%d ok=%v", first, ok)
	}
}

func TestLongDataQNameDoesNotPoisonLaterPoll(t *testing.T) {
	s := newDnsSession("0123456789abcdef", "", "tcp", "127.0.0.1:1", false, nil, nopLogger, nil)
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

	got := firstChunk(s.serveDownstream(dns.TypeTXT, 70, dnsTunnelMaxUDPResponse))
	if len(got) == 0 {
		t.Fatal("short poll QNAME could not fetch downstream data after long DATA QNAME")
	}
}

func TestOversizedRetransmitWaitsForShortPoll(t *testing.T) {
	s := newDnsSession("0123456789abcdef", "", "tcp", "127.0.0.1:1", false, nil, nopLogger, nil)
	payload := bytes.Repeat([]byte{0xa5}, 160)
	if !s.pushServer(payload) {
		t.Fatal("pushServer rejected payload")
	}

	first := firstChunk(s.serveDownstream(dns.TypeTXT, 70, dnsTunnelMaxUDPResponse))
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

	retry := firstChunk(s.serveDownstream(dns.TypeTXT, 70, dnsTunnelMaxUDPResponse))
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
	s := newDnsSession("0123456789abcdef", "", "tcp", "127.0.0.1:1", false, &NoiseSession{SendCipher: send}, nopLogger, nil)
	payload := bytes.Repeat([]byte{0xa5}, 160)
	if !s.pushServer(payload) {
		t.Fatal("pushServer rejected payload")
	}
	first := firstChunk(s.serveDownstream(dns.TypeTXT, 70, dnsTunnelMaxUDPResponse))
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
	retry := firstChunk(s.serveDownstream(dns.TypeTXT, 70, dnsTunnelMaxUDPResponse))
	if !bytes.Equal(first, retry) || s.serverOutBytes != queuedBytes || len(s.serverOut) != 1 {
		t.Fatal("deferring retransmit changed ciphertext or retransmission state")
	}
}
