package dnstunnel

import (
	"net"
	"testing"

	"github.com/miekg/dns"
)

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
