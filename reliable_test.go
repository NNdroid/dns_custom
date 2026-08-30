package main

import (
	"bytes"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// TestServerUpstreamReassembly verifies the server dedups duplicates and delivers
// out-of-order upstream chunks strictly in dataSeq order to the backend.
func TestServerUpstreamReassembly(t *testing.T) {
	sess := newDnsSession("test", "tcp", "127.0.0.1:1", nil)
	// newDnsSession starts clientNext=1, so the first data chunk is dataSeq=1.

	// Deliver out of order, then a duplicate of an already-delivered chunk.
	sess.pushClient(1, []byte("AAAA"))
	sess.pushClient(3, []byte("CCCC"))
	sess.pushClient(2, []byte("BBBB"))
	sess.pushClient(2, []byte("XXXX")) // duplicate, must be dropped

	got := sess.clientBuf.String()
	want := "AAAABBBBCCCC"
	if got != want {
		t.Fatalf("upstream reassembly mismatch: got %q want %q", got, want)
	}
	if sess.clientNext != 4 {
		t.Fatalf("clientNext=%d, want 4", sess.clientNext)
	}
}

// TestClientDownstreamReassembly verifies the client reassembles out-of-order
// downstream chunks in serverSeq order, dedups, and advances its ACK.
func TestClientDownstreamReassembly(t *testing.T) {
	tun := &DNSClientTunnel{
		qtype:    dns.TypeTXT,
		inBuf:    new(bytes.Buffer),
		recvNext: 1,
		recvOOO:  make(map[uint32][]byte),
	}

	tun.deliverDownstream(encodeDownstreamFrame(1, 0, []byte("AAAA")))
	tun.deliverDownstream(encodeDownstreamFrame(3, 0, []byte("CCCC")))
	tun.deliverDownstream(encodeDownstreamFrame(2, 0, []byte("BBBB")))
	tun.deliverDownstream(encodeDownstreamFrame(2, 0, []byte("XXXX"))) // duplicate

	got := tun.inBuf.String()
	want := "AAAABBBBCCCC"
	if got != want {
		t.Fatalf("downstream reassembly mismatch: got %q want %q", got, want)
	}
	if tun.recvNext != 4 {
		t.Fatalf("recvNext=%d, want 4", tun.recvNext)
	}
	if atomic.LoadUint32(&tun.ack) != 3 {
		t.Fatalf("ack=%d, want 3", atomic.LoadUint32(&tun.ack))
	}
}

// TestDownstreamFrameRoundTrip checks the frame header survives encode/decode.
func TestDownstreamFrameRoundTrip(t *testing.T) {
	frame := encodeDownstreamFrame(42, 7, []byte("payload-bytes"))
	seq, skipTo, payload, ok := decodeDownstreamFrame(frame)
	if !ok || seq != 42 || skipTo != 7 || string(payload) != "payload-bytes" {
		t.Fatalf("frame round-trip failed: seq=%d skipTo=%d payload=%q ok=%v", seq, skipTo, payload, ok)
	}
	if _, _, _, ok := decodeDownstreamFrame([]byte("short")); ok {
		t.Fatalf("expected decode failure on too-short buffer")
	}
}

// testPollQName is a representative poll query name: short, because a poll carries no
// upstream chunk label, which is what leaves room for the downstream payload.
const testPollQName = "1.0.P.0.-.0123456789abcdef.tunnel.test.local"

// TestServerDownstreamRetransmitThenGiveUp covers the stall fix: an unacked chunk is
// retransmitted, but once it ages past the give-up window it is abandoned and the
// server tells the client to skip forward instead of blocking the stream forever.
func TestServerDownstreamRetransmitThenGiveUp(t *testing.T) {
	sess := newDnsSession("test", "tcp", "127.0.0.1:1", nil)
	sess.serverBuf.WriteString("AAAA")

	// First serve: seq=1, retained in serverOut pending the client's ACK.
	first := sess.serveDownstream(dns.TypeTXT, testPollQName)
	s1, skip1, p1, ok := decodeDownstreamFrame(first)
	if !ok || s1 != 1 || skip1 != 0 || string(p1) != "AAAA" {
		t.Fatalf("first frame mismatch: seq=%d skipTo=%d payload=%q ok=%v", s1, skip1, p1, ok)
	}

	// Still unacked: the same chunk must be retransmitted.
	again := sess.serveDownstream(dns.TypeTXT, testPollQName)
	s2, skip2, p2, _ := decodeDownstreamFrame(again)
	if s2 != 1 || skip2 != 0 || string(p2) != "AAAA" {
		t.Fatalf("expected retransmit of seq 1, got seq=%d skipTo=%d payload=%q", s2, skip2, p2)
	}

	// Age it past the give-up window, then make sure fresh data can flow again.
	sess.serverOut[1].firstSent = time.Now().Add(-dnsTunnelDownstreamGiveUp - time.Second)
	sess.serverBuf.WriteString("BBBB")

	third := sess.serveDownstream(dns.TypeTXT, testPollQName)
	s3, skip3, p3, _ := decodeDownstreamFrame(third)
	if s3 != 2 || skip3 != 2 || string(p3) != "BBBB" {
		t.Fatalf("after give-up expected seq=2 skipTo=2 payload=%q, got seq=%d skipTo=%d payload=%q", "BBBB", s3, skip3, p3)
	}
	if _, stillThere := sess.serverOut[1]; stillThere {
		t.Fatalf("abandoned chunk must be removed from the retransmit buffer")
	}
}

// TestClientDownstreamSkipOnGiveUp verifies the client honours skipTo: it jumps past
// chunks the server abandoned instead of waiting for them forever.
func TestClientDownstreamSkipOnGiveUp(t *testing.T) {
	tun := newTestTunnel()

	// seq 1 never arrives; the server later announces it gave up and skips to 2.
	tun.deliverDownstream(encodeDownstreamFrame(2, 2, []byte("BBBB")))

	if got := tun.inBuf.String(); got != "BBBB" {
		t.Fatalf("skip delivery mismatch: got %q want %q", got, "BBBB")
	}
	if tun.recvNext != 3 {
		t.Fatalf("recvNext=%d, want 3", tun.recvNext)
	}
}

// TestClientDownstreamSkipDropsStaleOutOfOrder makes sure a skip discards buffered
// chunks below the skip point, and that delivery resumes coherently afterwards.
func TestClientDownstreamSkipDropsStaleOutOfOrder(t *testing.T) {
	tun := newTestTunnel()

	// Chunk 2 arrives early and is buffered because 1 is missing.
	tun.deliverDownstream(encodeDownstreamFrame(2, 0, []byte("BBBB")))
	if tun.inBuf.Len() != 0 {
		t.Fatalf("out-of-order chunk must not be delivered yet, got %q", tun.inBuf.String())
	}

	// Server abandons 1..3 and jumps to 4; the stale buffered 2 must be dropped.
	tun.deliverDownstream(encodeDownstreamFrame(5, 4, []byte("EEEE")))
	if tun.inBuf.Len() != 0 {
		t.Fatalf("nothing should be delivered yet, got %q", tun.inBuf.String())
	}

	// Chunk 4 arrives: 4 and the buffered 5 become contiguous and both deliver.
	tun.deliverDownstream(encodeDownstreamFrame(4, 0, []byte("DDDD")))
	if got, want := tun.inBuf.String(), "DDDDEEEE"; got != want {
		t.Fatalf("after skip recovery: got %q want %q", got, want)
	}
	if tun.recvNext != 6 {
		t.Fatalf("recvNext=%d, want 6", tun.recvNext)
	}
}

// TestSeqLessWraparound guards the wraparound-safe sequence comparison: a plain `<`
// would misread sequence numbers once the uint32 counter wraps, silently treating a
// fresh chunk as a stale duplicate (or vice versa).
func TestSeqLessWraparound(t *testing.T) {
	if !seqLess(1, 2) || seqLess(2, 1) {
		t.Fatalf("seqLess broken for ordinary values")
	}
	// 0xFFFFFFFE is three steps behind 1 across the wrap, so it must compare older.
	if !seqLess(0xFFFFFFFE, 1) {
		t.Fatalf("0xFFFFFFFE must compare older than 1 across the wrap")
	}
	if seqLess(1, 0xFFFFFFFE) {
		t.Fatalf("1 must compare newer than 0xFFFFFFFE across the wrap")
	}
}

func newTestTunnel() *DNSClientTunnel {
	return &DNSClientTunnel{
		qtype:    dns.TypeTXT,
		inBuf:    new(bytes.Buffer),
		recvNext: 1,
		recvOOO:  make(map[uint32][]byte),
	}
}
