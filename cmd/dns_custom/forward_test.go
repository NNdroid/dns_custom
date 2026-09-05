package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"io"
	"net"
	"testing"
	"time"

	dnstunnel "github.com/NNdroid/dns_custom"
)

// startEchoTCP runs a TCP echo backend and returns its address.
func startEchoTCP(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("tcp echo listen failed: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				_, _ = io.Copy(conn, conn)
			}(c)
		}
	}()
	return ln.Addr().String()
}

// startEchoUDP runs a UDP echo backend and returns its address.
func startEchoUDP(t *testing.T) string {
	t.Helper()
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("udp echo listen failed: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
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

// pickListenPort reserves a free port and releases it for the forwarder to bind.
func pickListenPort(t *testing.T, network string) string {
	t.Helper()
	if network == "udp" {
		pc, err := net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("reserve udp port failed: %v", err)
		}
		addr := pc.LocalAddr().String()
		_ = pc.Close()
		return addr
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve tcp port failed: %v", err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	return addr
}

// newTestTunnelClient builds a client pointed at an in-process tunnel server.
func newTestTunnelClient(t *testing.T, dnsAddr, domain string) *dnstunnel.Client {
	t.Helper()
	cli, err := dnstunnel.NewClient(dnstunnel.ClientConfig{
		Domain:     domain,
		Servers:    []string{dnsAddr},
		RecordType: "txt",
	})
	if err != nil {
		t.Fatalf("NewClient failed: %v", err)
	}
	return cli
}

// TestRunTCPForwardClientLoop exercises the CLI TCP forward loop end to end:
// local bytes go through the tunnel to the backend echo and come back.
func TestRunTCPForwardClientLoop(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	backend := startEchoTCP(t)
	dnsAddr := pickListenPort(t, "udp")

	srv, err := dnstunnel.NewServer(dnstunnel.ServerConfig{
		ListenAddr: dnsAddr,
		TargetAddr: "tcp://" + backend,
		Domain:     "cli-fwd.test.local",
	})
	if err != nil {
		t.Fatalf("NewServer failed: %v", err)
	}
	go func() { _ = srv.Run(ctx) }()

	listen := pickListenPort(t, "tcp")
	go runTCPForwardClient(ctx, newTestTunnelClient(t, dnsAddr, "cli-fwd.test.local"), listen)

	payload := []byte("local TCP forwarder round trip through the DNS tunnel")
	got := make([]byte, len(payload))
	ok := false
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		c, err := net.DialTimeout("tcp", listen, time.Second)
		if err != nil {
			time.Sleep(150 * time.Millisecond) // forwarder not bound yet
			continue
		}
		if _, err := c.Write(payload); err != nil {
			c.Close()
			continue // tunnel session failed during setup; retry
		}
		if err := c.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
			c.Close()
			continue
		}
		_, err = io.ReadFull(c, got) // echo backends never close; read exactly the payload
		c.Close()
		if err == nil {
			ok = true
			break
		}
	}
	if !ok {
		t.Fatal("TCP forwarder round trip never succeeded")
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("TCP roundtrip mismatch: got %q", string(got))
	}
}

// TestRunUDPForwardClientLoop exercises the CLI UDP forward loop end to end:
// datagrams stay boundary-preserved through the tunnel and the echo comes back.
func TestRunUDPForwardClientLoop(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	backend := startEchoUDP(t)
	dnsAddr := pickListenPort(t, "udp")

	srv, err := dnstunnel.NewServer(dnstunnel.ServerConfig{
		ListenAddr: dnsAddr,
		TargetAddr: "udp://" + backend,
		Domain:     "cli-udpfwd.test.local",
	})
	if err != nil {
		t.Fatalf("NewServer failed: %v", err)
	}
	go func() { _ = srv.Run(ctx) }()

	listen := pickListenPort(t, "udp")
	go runUDPForwardClient(ctx, newTestTunnelClient(t, dnsAddr, "cli-udpfwd.test.local"), listen)

	c, err := net.Dial("udp", listen)
	if err != nil {
		t.Fatalf("local udp dial failed: %v", err)
	}
	defer c.Close()

	payload := make([]byte, 120)
	if _, err := rand.Read(payload); err != nil {
		t.Fatalf("payload generation failed: %v", err)
	}
	buf := make([]byte, len(payload)+64)
	got := []byte(nil)
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := c.Write(payload); err != nil {
			t.Fatalf("udp write failed: %v", err)
		}
		if err := c.SetReadDeadline(time.Now().Add(400 * time.Millisecond)); err != nil {
			t.Fatalf("SetReadDeadline failed: %v", err)
		}
		n, err := c.Read(buf)
		if err == nil && n == len(payload) {
			got = buf[:n]
			break
		}
		// The first datagram may race tunnel session setup; resend.
	}
	if got == nil {
		t.Fatal("UDP forwarder round trip never succeeded")
	}
	if !bytes.Equal(got, payload) {
		t.Fatal("UDP datagram content mismatch")
	}
}
