package dnstunnel

import (
	"testing"
	"time"

	"github.com/miekg/dns"
)

// TestRawExchangeRate measures the raw miekg DNS exchange latency on loopback
// for UDP and TCP, isolating transport cost from all tunnel logic. It exists to
// diagnose throughput surprises, not to assert anything but sanity.
func TestRawExchangeRate(t *testing.T) {
	handler := dns.HandlerFunc(func(w dns.ResponseWriter, req *dns.Msg) {
		reply := new(dns.Msg)
		reply.SetReply(req)
		reply.Authoritative = true
		_ = w.WriteMsg(reply)
	})

	for _, network := range []string{"udp", "tcp"} {
		t.Run(network, func(t *testing.T) {
			var addr string
			if network == "udp" {
				addr = startTestDNSServer(t, handler)
			} else {
				addr = startTestDNSTCPServer(t, handler)
			}
			path := newDNSPath(network+"://"+addr, nil, nil)
			defer path.close()
			if network == "udp" {
				path.addr = addr // udp:// prefix is not a path scheme; use the bare addr
			}

			m := new(dns.Msg)
			m.SetQuestion("probe.example.", dns.TypeTXT)

			// warmup
			for i := 0; i < 20; i++ {
				if _, err := path.exchange(t.Context(), m); err != nil {
					t.Fatalf("warmup exchange: %v", err)
				}
			}
			const n = 300
			start := time.Now()
			for i := 0; i < n; i++ {
				if _, err := path.exchange(t.Context(), m); err != nil {
					t.Fatalf("exchange: %v", err)
				}
			}
			per := time.Since(start) / n
			t.Logf("%s: %v per exchange", network, per)
			if per > 5*time.Millisecond {
				t.Errorf("%s exchange latency %v exceeds 5ms on loopback", network, per)
			}
		})
	}
}
