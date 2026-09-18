package dnstunnel

import (
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

// dohResponseWriter adapts a DNS handler to an HTTP request so a tunnel server
// can be exposed over DoH inside tests without TLS plumbing.
type dohResponseWriter struct {
	header http.Header
	buf    bytes.Buffer
	local  net.Addr
	remote net.Addr
}

func (w *dohResponseWriter) LocalAddr() net.Addr  { return w.local }
func (w *dohResponseWriter) RemoteAddr() net.Addr { return w.remote }
func (w *dohResponseWriter) WriteMsg(m *dns.Msg) error {
	b, err := m.Pack()
	w.buf.Write(b)
	return err
}
func (w *dohResponseWriter) Write(b []byte) (int, error)      { return w.buf.Write(b) }
func (w *dohResponseWriter) Close() error                     { return nil }
func (w *dohResponseWriter) TsigStatus() error                { return nil }
func (w *dohResponseWriter) TsigTimersOnly(bool)              {}
func (w *dohResponseWriter) Hijack()                          {}
func (w *dohResponseWriter) Header() http.Header              { return w.header }
func (w *dohResponseWriter) WriteBytes(b []byte) (int, error) { return w.buf.Write(b) }

// startUpstreamDNSForBench exposes the tunnel DNS handler over the given
// upstream scheme: "udp" (bare address), "tcp" (tcp://address), "doh"
// (http:// URL via httptest, plain-HTTP DoH so no TLS plumbing is needed).
func startUpstreamDNSForBench(b *testing.B, handler dns.Handler, upstream string) []string {
	b.Helper()
	var addr string
	switch upstream {
	case "udp":
		addr = startTestDNSServer(b, handler)
	case "tcp":
		addr = "tcp://" + startTestDNSTCPServer(b, handler)
	case "doh":
		remote, _ := net.ResolveUDPAddr("udp", "127.0.0.1:0")
		httpSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			body, err := io.ReadAll(r.Body)
			if err != nil {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			m := new(dns.Msg)
			if err := m.Unpack(body); err != nil {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			dw := &dohResponseWriter{header: http.Header{}, local: remote, remote: remote}
			handler.ServeDNS(dw, m)
			w.Header().Set("Content-Type", "application/dns-message")
			_, _ = w.Write(dw.buf.Bytes())
		}))
		b.Cleanup(httpSrv.Close)
		addr = httpSrv.URL
	default:
		b.Fatalf("unknown upstream %q", upstream)
	}
	if upstream == "udp" {
		return []string{addr}
	}
	return []string{addr}
}

// startUDPEchoBackendForBench runs a UDP echo target for datagram benches.
func startUDPEchoBackendForBench(b *testing.B) string {
	b.Helper()
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		b.Fatalf("udp echo listen failed: %v", err)
	}
	b.Cleanup(func() { _ = conn.Close() })
	go func() {
		buf := make([]byte, 65535)
		for {
			n, raddr, err := conn.ReadFrom(buf)
			if err != nil {
				return
			}
			if _, err := conn.WriteTo(buf[:n], raddr); err != nil {
				return
			}
		}
	}()
	return conn.LocalAddr().String()
}

// benchmarkMatrix runs one throughput benchmark for a given upstream transport
// (udp/tcp/doh) and target transport (tcp echo / udp echo). Every upstream
// protocol gets both target protocols so the matrix shows where each one wins.
func benchmarkMatrix(b *testing.B, upstream string, udpTarget bool) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	domain := "matrix.bench.local"

	var tunnelSrv *Server
	var err error
	if udpTarget {
		udpEcho := startUDPEchoBackendForBench(b)
		tunnelSrv, err = NewServer(ServerConfig{
			Domain:     domain,
			ListenAddr: "127.0.0.1:0",
			TargetAddr: "udp://" + udpEcho,
		})
	} else {
		tcpEcho := startTCPEchoBackendForBench(b)
		tunnelSrv, err = NewServer(ServerConfig{
			Domain:     domain,
			ListenAddr: "127.0.0.1:0",
			TargetAddr: "tcp://" + tcpEcho,
		})
	}
	if err != nil {
		b.Fatal(err)
	}
	servers := startUpstreamDNSForBench(b, tunnelSrv.handler, upstream)

	if udpTarget {
		pconn, err := cliDialUDPForBench(ctx, servers, domain)
		if err != nil {
			b.Fatal(err)
		}
		defer pconn.Close()

		const datagramSize = 1024
		const datagrams = 64
		payload := make([]byte, datagramSize)
		recv := make([]byte, datagramSize)

		b.SetBytes(datagrams * datagramSize)
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			for d := 0; d < datagrams; d++ {
				payload[0] = byte(d)
				if _, err := pconn.WriteTo(payload, nil); err != nil {
					b.Fatalf("WriteTo: %v", err)
				}
			}
			for d := 0; d < datagrams; d++ {
				pconn.SetReadDeadline(deadlineForBench())
				n, _, err := pconn.ReadFrom(recv)
				if err != nil {
					b.Fatalf("ReadFrom: %v", err)
				}
				if n != datagramSize || recv[0] != byte(d) {
					b.Fatalf("datagram %d mismatch: n=%d first=%d", d, n, recv[0])
				}
			}
		}
		return
	}

	conn, err := cliDialForBench(ctx, servers, domain)
	if err != nil {
		b.Fatal(err)
	}
	defer conn.Close()

	const size = 65536
	payload := make([]byte, size)
	recv := make([]byte, size)
	b.SetBytes(size)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := conn.Write(payload); err != nil {
			b.Fatalf("write: %v", err)
		}
		if _, err := io.ReadFull(conn, recv); err != nil {
			b.Fatalf("read: %v", err)
		}
	}
}

// deadlineForBench and timeNow/timeSecond keep the helper readable without an
// extra import alias.
func deadlineForBench() time.Time {
	return time.Now().Add(30 * time.Second)
}

// cliDialForBench opens one stream session against the given upstream servers.
func cliDialForBench(ctx context.Context, servers []string, domain string) (net.Conn, error) {
	t, err := newDNSClientTunnel(ctx, servers, domain, "txt", "", "", "", "", false, nopLogger, nil, nil, nil, nil)
	if err != nil {
		return nil, err
	}
	return t, nil
}

// cliDialUDPForBench opens one datagram session against the given upstreams.
func cliDialUDPForBench(ctx context.Context, servers []string, domain string) (net.PacketConn, error) {
	t, err := newDNSClientTunnel(ctx, servers, domain, "txt", "", udpSessionPrefix, "", "", false, nopLogger, nil, nil, nil, nil)
	if err != nil {
		return nil, err
	}
	return &tunnelPacketConn{stream: t}, nil
}

func BenchmarkUpUDPTargetTCP(b *testing.B) { benchmarkMatrix(b, "udp", false) }
func BenchmarkUpUDPTargetUDP(b *testing.B) { benchmarkMatrix(b, "udp", true) }
func BenchmarkUpTCPTargetTCP(b *testing.B) { benchmarkMatrix(b, "tcp", false) }
func BenchmarkUpTCPTargetUDP(b *testing.B) { benchmarkMatrix(b, "tcp", true) }
func BenchmarkUpDoHTargetTCP(b *testing.B) { benchmarkMatrix(b, "doh", false) }
func BenchmarkUpDoHTargetUDP(b *testing.B) { benchmarkMatrix(b, "doh", true) }

// startTCPEchoBackendForBench runs a TCP echo target for stream benches.
func startTCPEchoBackendForBench(b *testing.B) string {
	b.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		b.Fatalf("tcp echo listen failed: %v", err)
	}
	b.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_, _ = io.Copy(c, c)
			}(conn)
		}
	}()
	return ln.Addr().String()
}
