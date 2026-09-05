package dnstunnel

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync/atomic"
	"testing"

	"github.com/miekg/dns"
)

// startEchoBackend starts a TCP echo server used as the tunnel's forwarding target.
func startEchoBackend(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("echo listen failed: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
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

// startTunnelServer boots a DNSServer on an OS-assigned UDP port.
func startTunnelServer(t *testing.T, domain, target, privKey string) string {
	t.Helper()
	srv, err := NewDNSServer(ServerConfig{
		Domain:     domain,
		TargetAddr: target,
		PrivateKey: privKey,
	})
	if err != nil {
		t.Fatalf("NewDNSServer failed: %v", err)
	}
	return startTestDNSServer(t, srv)
}

// TestNoiseNonceIsSequenceDerived locks in the P0 fix: the AEAD nonce must be derived
// from the sequence number, so chunks decrypt in any order, more than once, and a
// repeated chunk is byte-identical (which is what lets retransmits be deduped).
func TestNoiseNonceIsSequenceDerived(t *testing.T) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("key generation failed: %v", err)
	}
	cs, err := newNoiseCipherState(key)
	if err != nil {
		t.Fatalf("newNoiseCipherState failed: %v", err)
	}

	ct1 := cs.Encrypt(1, []byte("chunk-one"))
	ct2 := cs.Encrypt(2, []byte("chunk-two"))

	// Out-of-order arrival: with a stream counter the second decryption would already
	// be off by one and the whole direction would be dead.
	got2, err := cs.Decrypt(2, ct2)
	if err != nil || string(got2) != "chunk-two" {
		t.Fatalf("out-of-order decrypt failed: got %q err %v", got2, err)
	}
	got1, err := cs.Decrypt(1, ct1)
	if err != nil || string(got1) != "chunk-one" {
		t.Fatalf("out-of-order decrypt failed: got %q err %v", got1, err)
	}

	// Duplicate arrival (retransmit) decrypts to the same plaintext.
	dup, err := cs.Decrypt(1, ct1)
	if err != nil || string(dup) != "chunk-one" {
		t.Fatalf("duplicate decrypt failed: got %q err %v", dup, err)
	}

	// Deterministic sealing: same seq + same plaintext -> same ciphertext.
	if !bytes.Equal(ct1, cs.Encrypt(1, []byte("chunk-one"))) {
		t.Fatalf("encryption must be deterministic for a given seq")
	}

	// Wrong seq must still be rejected.
	if _, err := cs.Decrypt(3, ct1); err == nil {
		t.Fatalf("decrypt with a wrong nonce must fail")
	}
}

// TestNoiseNonceSurvivesReorderedDownstream drives the client reassembly with chunks
// that arrive shuffled and duplicated, which is what concurrent pollers produce.
func TestNoiseNonceSurvivesReorderedDownstream(t *testing.T) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("key generation failed: %v", err)
	}
	send, err := newNoiseCipherState(key)
	if err != nil {
		t.Fatalf("newNoiseCipherState failed: %v", err)
	}
	recv, err := newNoiseCipherState(key)
	if err != nil {
		t.Fatalf("newNoiseCipherState failed: %v", err)
	}

	tun := newTestTunnel()
	tun.noiseSession = &NoiseSession{SendCipher: send, RecvCipher: recv}

	// Server-side sealing of chunks 1..3, delivered as 2, 1, 3, 1(dup), 2(dup).
	frames := []uint32{2, 1, 3, 1, 2}
	for _, seq := range frames {
		payload := []byte(fmt.Sprintf("payload-%d;", seq))
		ct := send.Encrypt(uint64(seq), payload)
		tun.deliverDownstream(encodeDownstreamFrame(seq, 0, ct))
	}

	want := "payload-1;payload-2;payload-3;"
	if got := tun.inBuf.String(); got != want {
		t.Fatalf("reordered noisy delivery mismatch: got %q want %q", got, want)
	}
	if ack := atomic.LoadUint32(&tun.ack); ack != 3 {
		t.Fatalf("ack=%d, want 3", ack)
	}
}

// TestMultiServerPathsAddUp runs a tunnel over two upstream paths that both reach the
// same authoritative server. It must work with a dead path in either position: the
// live path carries the session while the dead one is retried and skipped.
func TestMultiServerPathsAddUp(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	echoAddr := startEchoBackend(t)
	domain := "tunnel.multipath.local"
	dnsAddr := startTunnelServer(t, domain, echoAddr, "")

	dead := "127.0.0.1:1" // nothing listens, so the exchange fails fast
	for _, servers := range [][]string{
		{dead, dnsAddr},
		{dnsAddr, dead},
		{dnsAddr, dnsAddr},
	} {
		tunnel, err := NewDNSClientTunnel(ctx, servers, domain, "txt", "")
		if err != nil {
			t.Fatalf("NewDNSClientTunnel with servers %v failed: %v", servers, err)
		}

		testMsg := []byte("Multipath round trip through " + fmt.Sprint(len(servers)) + " servers!")
		if _, err := tunnel.Write(testMsg); err != nil {
			t.Fatalf("tunnel write failed: %v", err)
		}
		recvBuf := make([]byte, len(testMsg))
		if _, err := io.ReadFull(tunnel, recvBuf); err != nil {
			t.Fatalf("tunnel read failed: %v", err)
		}
		if !bytes.Equal(recvBuf, testMsg) {
			t.Fatalf("mismatch with servers %v: got %q want %q", servers, recvBuf, testMsg)
		}
		_ = tunnel.Close()
	}
}

// TestConcurrentNoiseTransfer pushes a payload far larger than one chunk so the
// upstream window and the downstream sliding window both have to work, with Noise
// enabled (i.e. decrypting chunks that arrive out of order).
func TestConcurrentNoiseTransfer(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	echoAddr := startEchoBackend(t)
	kp, err := GenerateNoiseKeyPair()
	if err != nil {
		t.Fatalf("gen noise keys failed: %v", err)
	}
	privHex, _ := FormatNoiseKey(kp.PrivateKey)
	pubHex, _ := FormatNoiseKey(kp.PublicKey)

	domain := "tunnel.concurrent.local"
	dnsAddr := startTunnelServer(t, domain, echoAddr, privHex)

	tunnel, err := NewDNSClientTunnel(ctx, []string{dnsAddr}, domain, "txt", pubHex)
	if err != nil {
		t.Fatalf("NewDNSClientTunnel with noise failed: %v", err)
	}
	defer tunnel.Close()

	const size = 2048
	payload := make([]byte, size)
	if _, err := rand.Read(payload); err != nil {
		t.Fatalf("payload generation failed: %v", err)
	}

	if _, err := tunnel.Write(payload); err != nil {
		t.Fatalf("tunnel write failed: %v", err)
	}
	recvBuf := make([]byte, size)
	if _, err := io.ReadFull(tunnel, recvBuf); err != nil {
		t.Fatalf("tunnel read failed: %v", err)
	}
	if !bytes.Equal(recvBuf, payload) {
		diff := firstDiff(recvBuf, payload)
		start := diff - 16
		if start < 0 {
			start = 0
		}
		end := diff + 32
		if end > len(payload) {
			end = len(payload)
		}
		t.Fatalf("concurrent noisy transfer corrupted at byte %d: got[%d:%d]=%x want=%x",
			diff, start, end, recvBuf[start:end], payload[start:end])
	}
}

// TestNoiseRejectsAddressRecordTypes makes sure A/AAAA - which cannot carry a framed,
// authenticated payload - are rejected up front instead of silently truncating data.
func TestNoiseRejectsAddressRecordTypes(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	kp, err := GenerateNoiseKeyPair()
	if err != nil {
		t.Fatalf("gen noise keys failed: %v", err)
	}
	_, pubHex := FormatNoiseKey(kp.PublicKey)

	for _, rtype := range []string{"a", "aaaa"} {
		if _, err := NewDNSClientTunnel(ctx, []string{"127.0.0.1:53"}, "tunnel.reject.local", rtype, pubHex); err == nil {
			t.Fatalf("record type %q with Noise must be rejected", rtype)
		}
	}
}

// TestDownstreamCap matches the per-record-type capacity against what an answer can
// actually hold, so the sender never chunks into a silent truncation.
func TestDownstreamCap(t *testing.T) {
	cases := []struct {
		qtype    uint16
		noise    bool
		want     int
		maxLabel int
	}{
		{dns.TypeA, false, 4, 0},
		{dns.TypeAAAA, false, 16, 0},
		{dns.TypeCNAME, false, 39, 63},
		{dns.TypeMX, false, 39, 63},
		{dns.TypeSRV, false, 39, 63},
		{dns.TypeNS, false, 39, 63},
		{dns.TypeCNAME, true, 19, 63},
		{dns.TypeNULL, false, dnsTunnelMaxServerChunk, 0},
	}
	for _, c := range cases {
		got := downstreamCap(c.qtype, c.noise)
		if got != c.want {
			t.Fatalf("downstreamCap(%s, noise=%v)=%d, want %d", qTypeToDnsType(c.qtype), c.noise, got, c.want)
		}
		// Label-based records must stay inside the 63-character DNS label limit.
		if c.maxLabel > 0 {
			frame := c.want
			if c.noise {
				frame += nonTxtNoiseHeaderSize + 16
			}
			if b32 := len(dnsTunnelB32.EncodeToString(make([]byte, frame))); b32 > c.maxLabel {
				t.Fatalf("%s frame encodes to %d base32 chars, over the %d label limit",
					qTypeToDnsType(c.qtype), b32, c.maxLabel)
			}
		}
	}
}

// TestDownstreamAnswerFitsUDP guards the 512-byte UDP budget: the query name is
// echoed in the answer, so a data query (which carries the upstream chunk in its name)
// plus a full-size chunk used to overrun the client's receive buffer and kill the
// whole exchange. The sender must size chunks against that budget.
func TestDownstreamAnswerFitsUDP(t *testing.T) {
	// Worst case names: a data query with a full upstream chunk label, and a short poll.
	dataQName := buildQueryName(dns.Fqdn("tunnel.example.com"), "0123456789abcdef", 123456, 654321, 4242, flagData, make([]byte, 32))
	pollQName := buildQueryName(dns.Fqdn("tunnel.example.com"), "0123456789abcdef", 123456, 654321, 0, flagPoll, nil)

	for _, qname := range []string{dataQName, pollQName} {
		for _, qtype := range []uint16{dns.TypeTXT, dns.TypeNULL, dns.TypeCNAME, dns.TypeMX, dns.TypeSRV, dns.TypeNS, dns.TypeA, dns.TypeAAAA} {
			for _, noise := range []bool{false, true} {
				if noise && (qtype == dns.TypeA || qtype == dns.TypeAAAA) {
					continue // rejected up front; cannot carry framed data at all
				}
				payload := make([]byte, maxDownstreamPayload(qtype, noise, qname))
				if qtype != dns.TypeTXT && qtype != dns.TypeNULL && len(payload) == 0 {
					t.Fatalf("%s: no capacity left for a plain UDP answer", qTypeToDnsType(qtype))
				}

				// Rebuild what the server puts on the wire for this chunk.
				ct := append([]byte(nil), payload...)
				if noise {
					ct = append(ct, make([]byte, noiseTagSize)...)
				}
				var wire []byte
				switch {
				case qtype == dns.TypeTXT:
					wire = encodeDownstreamFrame(1, 0, ct)
				case noise:
					wire = make([]byte, nonTxtNoiseHeaderSize+len(ct))
					binary.BigEndian.PutUint32(wire[:nonTxtNoiseHeaderSize], 1)
					copy(wire[nonTxtNoiseHeaderSize:], ct)
				default:
					wire = payload
				}

				query := new(dns.Msg)
				query.SetQuestion(qname, qtype)
				reply := new(dns.Msg)
				reply.SetReply(query)
				reply.Authoritative = true
				reply.Answer = append(reply.Answer, makeAnswer(qname, qtype, wire, dns.Fqdn("tunnel.example.com")))

				if reply.Len() > dnsTunnelMaxUDPResponse {
					t.Fatalf("%s (noise=%v, qname len %d): response is %d bytes, over the %d byte UDP budget",
						qTypeToDnsType(qtype), noise, len(qname), reply.Len(), dnsTunnelMaxUDPResponse)
				}
			}
		}
	}
}

// BenchmarkTunnelThroughput* measures end-to-end throughput over one vs. several
// upstream paths. Run with: go test -run '^$' -bench 'TunnelThroughput' -benchtime 5x
func benchmarkTunnelThroughput(b *testing.B, paths int) {
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

	domain := "tunnel.bench.local"
	srv, err := NewDNSServer(ServerConfig{Domain: domain, TargetAddr: echoLn.Addr().String()})
	if err != nil {
		b.Fatal(err)
	}
	dnsAddr := startTestDNSServer(b, srv)

	servers := make([]string, 0, paths)
	for i := 0; i < paths; i++ {
		servers = append(servers, dnsAddr)
	}

	const size = 65536
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

func BenchmarkTunnelThroughput1Path(b *testing.B) { benchmarkTunnelThroughput(b, 1) }
func BenchmarkTunnelThroughput2Path(b *testing.B) { benchmarkTunnelThroughput(b, 2) }
func BenchmarkTunnelThroughput4Path(b *testing.B) { benchmarkTunnelThroughput(b, 4) }

func firstDiff(a, b []byte) int {
	for i := range a {
		if i >= len(b) || a[i] != b[i] {
			return i
		}
	}
	return len(a)
}
