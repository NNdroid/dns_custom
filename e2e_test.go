package main

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"testing"
)

func TestDNSCustom_Plain_E2E(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	echoLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("echo listen failed: %v", err)
	}
	defer echoLn.Close()
	echoAddr := echoLn.Addr().String()

	go func() {
		for {
			conn, err := echoLn.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				io.Copy(c, c)
			}(conn)
		}
	}()

	domain := "tunnel.plain.local"
	srv := NewDNSServer(ServerConfig{
		Domain:     domain,
		TargetAddr: echoAddr,
	})
	dnsServerAddr := startTestDNSServer(t, srv)

	recordTypes := []string{"txt", "null", "cname", "a", "aaaa", "mx", "srv", "ns"}

	for _, rtype := range recordTypes {
		t.Run("RecordType_"+rtype, func(t *testing.T) {
			tunnel, err := NewDNSClientTunnel(ctx, []string{dnsServerAddr}, domain, rtype, "")
			if err != nil {
				t.Fatalf("NewDNSClientTunnel failed: %v", err)
			}
			defer tunnel.Close()

			testMsg := []byte(fmt.Sprintf("Hello dns_custom with type [%s]!", rtype))
			if rtype == "a" {
				// An A record carries exactly 4 bytes (one IPv4 address).
				testMsg = []byte("ping")
			} else if rtype == "aaaa" {
				// An AAAA record carries exactly 16 bytes (one IPv6 address).
				testMsg = []byte("1234567890123456")
			}

			if _, err := tunnel.Write(testMsg); err != nil {
				t.Fatalf("tunnel write failed: %v", err)
			}

			recvBuf := make([]byte, len(testMsg))
			if _, err := io.ReadFull(tunnel, recvBuf); err != nil {
				t.Fatalf("tunnel read failed: %v", err)
			}

			if !bytes.Equal(recvBuf, testMsg) {
				t.Fatalf("mismatch: got %q, want %q", string(recvBuf), string(testMsg))
			}
			t.Logf("✅ RecordType [%s] E2E Passed!", rtype)
		})
	}
}

func TestDNSCustom_Noise_Encrypted_E2E(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	echoLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("echo listen failed: %v", err)
	}
	defer echoLn.Close()
	echoAddr := echoLn.Addr().String()

	go func() {
		for {
			conn, err := echoLn.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				io.Copy(c, c)
			}(conn)
		}
	}()

	kp, err := GenerateNoiseKeyPair()
	if err != nil {
		t.Fatalf("gen noise keys failed: %v", err)
	}
	privHex, _ := FormatNoiseKey(kp.PrivateKey)
	pubHex, _ := FormatNoiseKey(kp.PublicKey)

	domain := "tunnel.noise.local"
	srv := NewDNSServer(ServerConfig{
		Domain:     domain,
		TargetAddr: echoAddr,
		PrivateKey: privHex,
	})
	dnsServerAddr := startTestDNSServer(t, srv)

	tunnel, err := NewDNSClientTunnel(ctx, []string{dnsServerAddr}, domain, "txt", pubHex)
	if err != nil {
		t.Fatalf("NewDNSClientTunnel with noise failed: %v", err)
	}
	defer tunnel.Close()

	testMsg := []byte("Noise encrypted super-secret payload over DNS!")
	if _, err := tunnel.Write(testMsg); err != nil {
		t.Fatalf("tunnel write failed: %v", err)
	}

	recvBuf := make([]byte, len(testMsg))
	if _, err := io.ReadFull(tunnel, recvBuf); err != nil {
		t.Fatalf("tunnel read failed: %v", err)
	}

	if !bytes.Equal(recvBuf, testMsg) {
		t.Fatalf("noise decrypt mismatch: got %q, want %q", string(recvBuf), string(testMsg))
	}
	t.Logf("✅ Noise_NK Encrypted E2E Passed!")
}

func TestDNSCustom_UDPTarget_E2E(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	udpEchoConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("udp echo listen failed: %v", err)
	}
	defer udpEchoConn.Close()
	udpEchoAddr := udpEchoConn.LocalAddr().String()

	go func() {
		buf := make([]byte, 2048)
		for {
			n, raddr, err := udpEchoConn.ReadFrom(buf)
			if err != nil {
				return
			}
			_, _ = udpEchoConn.WriteTo(buf[:n], raddr)
		}
	}()

	domain := "tunnel.udptarget.local"
	srv := NewDNSServer(ServerConfig{
		Domain:     domain,
		TargetAddr: "udp://" + udpEchoAddr,
	})
	dnsServerAddr := startTestDNSServer(t, srv)

	tunnel, err := NewDNSClientTunnel(ctx, []string{dnsServerAddr}, domain, "txt", "")
	if err != nil {
		t.Fatalf("NewDNSClientTunnel failed: %v", err)
	}
	defer tunnel.Close()

	testMsg := []byte("UDP Target packet through DNS tunnel!")
	if _, err := tunnel.Write(testMsg); err != nil {
		t.Fatalf("tunnel write failed: %v", err)
	}

	recvBuf := make([]byte, len(testMsg))
	if _, err := io.ReadFull(tunnel, recvBuf); err != nil {
		t.Fatalf("tunnel read failed: %v", err)
	}

	if !bytes.Equal(recvBuf, testMsg) {
		t.Fatalf("udp target mismatch: got %q, want %q", string(recvBuf), string(testMsg))
	}
	t.Logf("✅ UDP Target E2E Passed!")
}
