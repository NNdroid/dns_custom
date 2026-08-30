package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"fmt"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// latencyHandler simulates a path with real round-trip latency, which is what a
// public resolver adds and what the adaptive upstream window has to react to.
type latencyHandler struct {
	inner dns.Handler
	d     time.Duration
}

func (h latencyHandler) ServeDNS(w dns.ResponseWriter, req *dns.Msg) {
	time.Sleep(h.d)
	h.inner.ServeDNS(w, req)
}

// benchmarkLatencyThroughput measures a transfer over paths with a real round trip.
// Run with: go test -run '^$' -bench 'LatencyThroughput' -benchtime 3x
//
// Note that every path here points at the same server, so this measures how well the
// window adapts, not the gain from genuinely independent resolvers.
func benchmarkLatencyThroughput(b *testing.B, paths int, rtt time.Duration) {
	echoLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		b.Fatalf("echo listen failed: %v", err)
	}
	defer echoLn.Close()
	go func() {
		for {
			conn, err := echoLn.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_, _ = io.Copy(c, c)
			}(conn)
		}
	}()

	domain := fmt.Sprintf("tunnel.latbench%d.local", paths)
	dnsAddr := fmt.Sprintf("127.0.0.1:2968%d", paths)
	srv := NewDNSServer(ServerConfig{ListenAddr: dnsAddr, Domain: domain, TargetAddr: echoLn.Addr().String()})
	udpServer := &dns.Server{Addr: dnsAddr, Net: "udp", Handler: latencyHandler{inner: srv, d: rtt}}
	go func() { _ = udpServer.ListenAndServe() }()
	defer udpServer.Shutdown()
	time.Sleep(100 * time.Millisecond)

	servers := make([]string, 0, paths)
	for i := 0; i < paths; i++ {
		servers = append(servers, dnsAddr)
	}

	const size = 16384
	payload := make([]byte, size)
	recv := make([]byte, size)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	b.SetBytes(size)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		tunnel, err := NewDNSClientTunnel(ctx, servers, domain, "txt", "")
		if err != nil {
			b.Fatalf("NewDNSClientTunnel failed: %v", err)
		}
		if _, err := tunnel.Write(payload); err != nil {
			b.Fatalf("write failed: %v", err)
		}
		if _, err := io.ReadFull(tunnel, recv); err != nil {
			b.Fatalf("read failed: %v", err)
		}
		if !bytes.Equal(recv, payload) {
			b.Fatalf("payload corrupted on round %d", i)
		}
		if i == 0 {
			b.ReportMetric(float64(tunnel.upstreamWindow()), "window")
		}
		_ = tunnel.Close()
	}
}

func BenchmarkLatencyThroughput1Path(b *testing.B) {
	benchmarkLatencyThroughput(b, 1, 20*time.Millisecond)
}
func BenchmarkLatencyThroughput2Path(b *testing.B) {
	benchmarkLatencyThroughput(b, 2, 20*time.Millisecond)
}
func BenchmarkLatencyThroughput4Path(b *testing.B) {
	benchmarkLatencyThroughput(b, 4, 20*time.Millisecond)
}

// TestTransferOverLatencyPath pushes a multi-chunk payload over a delayed path and
// checks both integrity and that the adaptive window stayed inside its bounds.
func TestTransferOverLatencyPath(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	echoLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("echo listen failed: %v", err)
	}
	defer echoLn.Close()
	go func() {
		for {
			conn, err := echoLn.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_, _ = io.Copy(c, c)
			}(conn)
		}
	}()

	domain := "tunnel.latency.local"
	dnsAddr := "127.0.0.1:29560"
	srv := NewDNSServer(ServerConfig{ListenAddr: dnsAddr, Domain: domain, TargetAddr: echoLn.Addr().String()})
	udpServer := &dns.Server{Addr: dnsAddr, Net: "udp", Handler: latencyHandler{inner: srv, d: 20 * time.Millisecond}}
	go func() { _ = udpServer.ListenAndServe() }()
	defer udpServer.Shutdown()
	time.Sleep(100 * time.Millisecond)

	tunnel, err := NewDNSClientTunnel(ctx, []string{dnsAddr}, domain, "txt", "")
	if err != nil {
		t.Fatalf("NewDNSClientTunnel failed: %v", err)
	}
	defer tunnel.Close()

	const size = 4096
	payload := make([]byte, size)
	if _, err := rand.Read(payload); err != nil {
		t.Fatalf("payload generation failed: %v", err)
	}
	if _, err := tunnel.Write(payload); err != nil {
		t.Fatalf("tunnel write failed: %v", err)
	}
	recv := make([]byte, size)
	if _, err := io.ReadFull(tunnel, recv); err != nil {
		t.Fatalf("tunnel read failed: %v", err)
	}
	if !bytes.Equal(recv, payload) {
		t.Fatalf("payload corrupted over a latency path")
	}

	w := tunnel.upstreamWindow()
	if w < dnsTunnelMinUpstreamWindow || w > dnsTunnelMaxUpstreamWindow {
		t.Fatalf("adaptive window out of bounds: %d", w)
	}
	t.Logf("adaptive upstream window settled at %d (bounds %d..%d)",
		w, dnsTunnelMinUpstreamWindow, dnsTunnelMaxUpstreamWindow)
}

// TestWindowBacksOffOnFailure makes sure a failing path shrinks the window instead of
// leaving a wide one that would keep flooding a path that is already dropping queries.
func TestWindowBacksOffOnFailure(t *testing.T) {
	tun := newTestTunnelWithPaths(1)
	atomic.StoreInt32(&tun.window, dnsTunnelMaxUpstreamWindow)
	for i := 0; i < 3; i++ {
		tun.onWindowSample(false, 0)
	}
	if got := tun.upstreamWindow(); got != dnsTunnelMinUpstreamWindow {
		t.Fatalf("window after failures = %d, want %d", got, dnsTunnelMinUpstreamWindow)
	}

	// A healthy path that keeps answering at its best RTT must grow back.
	atomic.StoreInt32(&tun.window, dnsTunnelMinUpstreamWindow)
	for i := 0; i < 2000; i++ {
		tun.onWindowSample(true, 10*time.Millisecond)
	}
	if got := tun.upstreamWindow(); got != dnsTunnelMaxUpstreamWindow {
		t.Fatalf("window after sustained success = %d, want %d", got, dnsTunnelMaxUpstreamWindow)
	}

	// A path that suddenly gets three times slower must shrink again.
	for i := 0; i < 500; i++ {
		tun.onWindowSample(true, 100*time.Millisecond)
	}
	if got := tun.upstreamWindow(); got != dnsTunnelMinUpstreamWindow {
		t.Fatalf("window after slowdown = %d, want %d", got, dnsTunnelMinUpstreamWindow)
	}
	t.Logf("window clamping verified across failure, recovery and slowdown")
}

// TestWindowDecaysWhenCongested checks the middle band: slower than best, but not
// failing. Holding steady is not enough there - a path that queues without failing
// would keep a window that is too wide forever - so the window decays slowly.
func TestWindowDecaysWhenCongested(t *testing.T) {
	tun := newTestTunnelWithPaths(1)
	atomic.StoreInt32(&tun.window, 8)
	// Establish a best RTT, skipping the cold-start window.
	for i := 0; i <= dnsTunnelWindowWarmup; i++ {
		tun.onWindowSample(true, 10*time.Millisecond)
	}
	atomic.StoreInt32(&tun.window, 16)
	for i := 0; i < 2000; i++ {
		tun.onWindowSample(true, 18*time.Millisecond) // 1.8x best: congested band
	}
	if got := tun.upstreamWindow(); got != dnsTunnelMinUpstreamWindow {
		t.Fatalf("window did not decay in the congested band: %d, want %d",
			got, dnsTunnelMinUpstreamWindow)
	}
}

// newTestTunnelWithPaths builds a tunnel whose only real state is the number of
// upstream paths, which is what bounds the adaptive window.
func newTestTunnelWithPaths(paths int) *DNSClientTunnel {
	return &DNSClientTunnel{paths: make([]*dnsPath, paths)}
}
