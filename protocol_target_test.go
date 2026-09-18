package dnstunnel

import (
	"bufio"
	"bytes"
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// innerDNSHandler answers every A query with 1.2.3.4 — a stand-in for a real
// authoritative DNS server used as the tunnel's UDP target.
func innerDNSHandler() dns.Handler {
	return dns.HandlerFunc(func(w dns.ResponseWriter, req *dns.Msg) {
		reply := new(dns.Msg)
		reply.SetReply(req)
		rr := &dns.A{
			Hdr: dns.RR_Header{Name: req.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 0},
			A:   net.IPv4(1, 2, 3, 4).To4(),
		}
		reply.Answer = append(reply.Answer, rr)
		_ = w.WriteMsg(reply)
	})
}

// TestUDPTargetRealDNSServer forwards DNS queries through the tunnel to a real
// (loopback) DNS server as the UDP target. The datagram path must preserve the
// query/response pairing: ten queries over ONE tunnel session, each answered
// with a parseable DNS message carrying the expected A record.
func TestUDPTargetRealDNSServer(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	innerDNS := startTestDNSServer(t, innerDNSHandler())
	dnsAddr := pickFreeUDPPort(t)

	srv, err := NewServer(ServerConfig{
		ListenAddr: dnsAddr,
		Domain:     "udpdns.test.local",
		TargetAddr: "udp://" + innerDNS,
	})
	if err != nil {
		t.Fatalf("NewDNSServer failed: %v", err)
	}
	go func() { _ = srv.Run(ctx) }()
	waitForDNSServer(t, dnsAddr)

	cli, err := NewClient(ClientConfig{
		Domain:     "udpdns.test.local",
		Servers:    []string{dnsAddr},
		RecordType: "txt",
	})
	if err != nil {
		t.Fatalf("NewClient failed: %v", err)
	}

	pconn, err := cli.DialUDP(ctx)
	if err != nil {
		t.Fatalf("DialUDP failed: %v", err)
	}
	defer pconn.Close()
	if err := pconn.SetReadDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatalf("SetReadDeadline failed: %v", err)
	}

	query := new(dns.Msg)
	query.SetQuestion("echo.test.", dns.TypeA)
	wire, err := query.Pack()
	if err != nil {
		t.Fatalf("pack query: %v", err)
	}

	for i := 0; i < 10; i++ {
		if _, err := pconn.WriteTo(wire, nil); err != nil {
			t.Fatalf("iteration %d: WriteTo failed: %v", i, err)
		}
		buf := make([]byte, 1500)
		n, _, err := pconn.ReadFrom(buf)
		if err != nil {
			t.Fatalf("iteration %d: ReadFrom failed: %v", i, err)
		}
		resp := new(dns.Msg)
		if err := resp.Unpack(buf[:n]); err != nil {
			t.Fatalf("iteration %d: response is not a valid DNS message (%d bytes): %v", i, n, err)
		}
		if resp.Rcode != dns.RcodeSuccess || len(resp.Answer) != 1 {
			t.Fatalf("iteration %d: unexpected response: rcode=%d answers=%d", i, resp.Rcode, len(resp.Answer))
		}
		a, ok := resp.Answer[0].(*dns.A)
		if !ok || !a.A.Equal(net.IPv4(1, 2, 3, 4).To4()) {
			t.Fatalf("iteration %d: unexpected answer record %v", i, resp.Answer[0])
		}
	}
}

// TestTCPTargetRealHTTPServer forwards HTTP requests through the tunnel to a
// real (loopback) HTTP server as the TCP target. Ten sequential requests ride
// the SAME tunnel session (and the same backend keep-alive connection), each
// answered with a parseable HTTP response.
func TestTCPTargetRealHTTPServer(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	httpSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("hello through the tunnel"))
	}))
	defer httpSrv.Close()
	dnsAddr := pickFreeUDPPort(t)

	srv, err := NewServer(ServerConfig{
		ListenAddr: dnsAddr,
		Domain:     "tcphttp.test.local",
		TargetAddr: "tcp://" + httpSrv.Listener.Addr().String(),
	})
	if err != nil {
		t.Fatalf("NewDNSServer failed: %v", err)
	}
	go func() { _ = srv.Run(ctx) }()
	waitForDNSServer(t, dnsAddr)

	cli, err := NewClient(ClientConfig{
		Domain:     "tcphttp.test.local",
		Servers:    []string{dnsAddr},
		RecordType: "txt",
	})
	if err != nil {
		t.Fatalf("NewClient failed: %v", err)
	}

	conn, err := cli.Dial(ctx)
	if err != nil {
		t.Fatalf("Dial failed: %v", err)
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatalf("SetDeadline failed: %v", err)
	}

	reader := bufio.NewReader(conn)
	for i := 0; i < 10; i++ {
		req := "GET /hello HTTP/1.1\r\nHost: tunnel.test\r\nConnection: keep-alive\r\n\r\n"
		if _, err := io.WriteString(conn, req); err != nil {
			t.Fatalf("iteration %d: write request failed: %v", i, err)
		}
		resp, err := http.ReadResponse(reader, &http.Request{Method: http.MethodGet})
		if err != nil {
			t.Fatalf("iteration %d: response is not valid HTTP: %v", i, err)
		}
		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			t.Fatalf("iteration %d: read body failed: %v", i, err)
		}
		if resp.StatusCode != http.StatusOK || !bytes.Equal(body, []byte("hello through the tunnel")) {
			t.Fatalf("iteration %d: unexpected response: status=%d body=%q", i, resp.StatusCode, body)
		}
	}
}
