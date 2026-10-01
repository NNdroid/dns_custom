package dnstunnel

import (
	"bytes"
	"testing"

	"github.com/miekg/dns"
)

func newQNameBudgetSessionForTest(t *testing.T, payload []byte) *dnsSession {
	t.Helper()
	sess := newDnsSession("qname-budget-test", "tcp", "127.0.0.1:1", false, nil, nopLogger, nil)
	sess.mu.Lock()
	_, _ = sess.serverBuf.Write(payload)
	sess.mu.Unlock()
	return sess
}

// A downstream chunk created for a short poll must not be retransmitted inside
// a near-maximum data QNAME when the resulting 512-byte DNS response would not
// fit. The chunk stays outstanding and is retransmitted by the next short poll.
func TestServeDownstreamSkipsRetransmitThatDoesNotFitQName(t *testing.T) {
	sess := newQNameBudgetSessionForTest(t, bytes.Repeat([]byte{0x5a}, 32))

	first := sess.serveDownstream(dns.TypeTXT, 80, dnsTunnelMaxUDPResponse)
	if len(first) == 0 {
		t.Fatal("short poll did not produce downstream data")
	}
	if got := len(sess.serverOut); got != 1 {
		t.Fatalf("outstanding chunks=%d, want 1", got)
	}

	if got := sess.serveDownstream(dns.TypeTXT, dnsTunnelMaxQueryNameLen, dnsTunnelMaxUDPResponse); len(got) != 0 {
		t.Fatalf("oversized-QNAME retransmit produced %d bytes, want 0", len(got))
	}
	if got := len(sess.serverOut); got != 1 {
		t.Fatalf("oversized-QNAME attempt removed outstanding chunk: %d", got)
	}

	retry := sess.serveDownstream(dns.TypeTXT, 80, dnsTunnelMaxUDPResponse)
	if !bytes.Equal(retry, first) {
		t.Fatalf("short poll did not retransmit the preserved chunk: got=%d want=%d", len(retry), len(first))
	}
}

// A long upstream data QNAME may have no room for piggy-backed downstream data,
// but it must not poison the session. A later short poll still gets the buffered
// backend payload at the normal response budget.
func TestServeDownstreamLongQNameDoesNotBlockLaterPoll(t *testing.T) {
	payload := bytes.Repeat([]byte{0xa5}, 64)
	sess := newQNameBudgetSessionForTest(t, payload)

	if got := sess.serveDownstream(dns.TypeTXT, dnsTunnelMaxQueryNameLen, dnsTunnelMaxUDPResponse); len(got) != 0 {
		t.Fatalf("long QNAME unexpectedly carried %d downstream bytes", len(got))
	}
	sess.mu.Lock()
	remaining := sess.serverBuf.Len()
	sess.mu.Unlock()
	if remaining != len(payload) {
		t.Fatalf("long QNAME consumed backend bytes: remaining=%d want=%d", remaining, len(payload))
	}

	got := sess.serveDownstream(dns.TypeTXT, 80, dnsTunnelMaxUDPResponse)
	if len(got) == 0 {
		t.Fatal("short poll did not resume downstream delivery")
	}
}
