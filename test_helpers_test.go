package dnstunnel

import (
	"context"
	"net"
	"testing"

	"github.com/miekg/dns"
)

// parseQueryName is a test convenience wrapper for parseQueryNameForMarkers
// with the built-in marker set. Production code calls parseQueryNameForMarkers
// directly with the server's configured marker set.
func parseQueryName(domain, name string) (session string, querySeq, ack, dataSeq uint32, flag byte, data []byte, err error) {
	return parseQueryNameForMarkers(domain, len(dns.SplitDomainName(domain)), name, markerSetFor(""))
}

// newTestTunnel opens a tunnel session with the defaults the test matrix uses
// (TXT record type, no Noise, silent logger). Knobs beyond that stay opt-in:
// pass tunnel options, or build clientTunnelParams directly for exotic cases.
func newTestTunnelSession(ctx context.Context, servers []string, domain, sessionPrefix string, edns bool, events *eventDispatcher[ClientEvent], opts ...tunnelOption) (*DNSClientTunnel, error) {
	p := clientTunnelParams{
		servers:       servers,
		domain:        domain,
		recordType:    "txt",
		sessionPrefix: sessionPrefix,
		edns0:         edns,
		log:           nopLogger,
		events:        events,
	}
	for _, o := range opts {
		o(&p.tuning)
	}
	return newDNSClientTunnel(ctx, p)
}

// startTestDNSServer binds before returning, avoiding fixed-port collisions and
// readiness sleeps throughout the integration tests.
func startTestDNSServer(tb testing.TB, handler dns.Handler) string {
	tb.Helper()
	packetConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		tb.Fatalf("listen for test DNS server: %v", err)
	}
	server := &dns.Server{PacketConn: packetConn, Handler: handler}
	go func() {
		_ = server.ActivateAndServe()
	}()
	tb.Cleanup(func() {
		_ = server.Shutdown()
		_ = packetConn.Close()
	})
	return packetConn.LocalAddr().String()
}

// startTestDNSTCPServer is startTestDNSServer over TCP: queries arriving there
// exercise the server's TCP response budget (large chunks).
func startTestDNSTCPServer(tb testing.TB, handler dns.Handler) string {
	tb.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		tb.Fatalf("listen for test TCP DNS server: %v", err)
	}
	server := &dns.Server{Listener: ln, Handler: handler}
	go func() {
		_ = server.ActivateAndServe()
	}()
	tb.Cleanup(func() {
		_ = server.Shutdown()
		_ = ln.Close()
	})
	return ln.Addr().String()
}
