package dnstunnel

import (
	"bytes"
	"fmt"
	"strings"
	"testing"

	"github.com/miekg/dns"
)

func upstreamQNameLen(domain, marker, session string, plain int, noise bool) int {
	wire := plain
	if noise {
		wire += noiseTagSize
	}
	return len(buildQueryName(marker, domain, session, ^uint32(0), ^uint32(0), ^uint32(0), flagData, make([]byte, wire)))
}

// Exercise every remaining QNAME budget, including the point where an AEAD
// tag leaves no room for data. Pack and parse actual worst-case DNS questions
// so the test also checks label separators and the wire-format size ceiling.
func TestUpstreamChunkWireBoundaries(t *testing.T) {
	const session = "0123456789abcdef"
	for domainLen := 1; domainLen <= 190; domainLen++ {
		var labels []string
		for remaining := domainLen; remaining > 0; {
			n := remaining
			if n > 50 {
				n = 50
			}
			labels = append(labels, strings.Repeat("a", n))
			remaining -= n
		}
		domain := strings.Join(labels, ".") + "."
		for _, marker := range []string{dnsTunnelMarker, "custommarker"} {
			for _, noise := range []bool{false, true} {
				t.Run(fmt.Sprintf("%d/%s/noise=%t", domainLen, marker, noise), func(t *testing.T) {
					n := maxUpstreamPlainChunk(domain, marker, session, noise)
					if n == 0 {
						if upstreamQNameLen(domain, marker, session, 1, noise) <= dnsTunnelMaxQNameTextLen {
							t.Fatal("one-byte payload fits but chunk size is zero")
						}
						return
					}
					wireSize := n
					if noise {
						wireSize += noiseTagSize
					}
					payload := bytes.Repeat([]byte{0xa5}, wireSize)
					name := buildQueryNameRandomized(marker, domain, session, ^uint32(0), ^uint32(0), ^uint32(0), flagData, payload)
					if len(name) > dnsTunnelMaxQNameTextLen || upstreamQNameLen(domain, marker, session, n+1, noise) <= dnsTunnelMaxQNameTextLen {
						t.Fatalf("chunk %d does not maximize safe QNAME budget", n)
					}
					msg := new(dns.Msg)
					msg.SetQuestion(name, dns.TypeTXT)
					packed, err := msg.Pack()
					if err != nil {
						t.Fatal(err)
					}
					if len(packed)-12-4 > 255 {
						t.Fatalf("wire QNAME exceeds 255 bytes: %d", len(packed)-12-4)
					}
					_, _, _, _, _, got, err := parseQueryNameForMarkers(domain, len(labels), name, markerSetFor(marker))
					if err != nil || !bytes.Equal(got, payload) {
						t.Fatalf("payload roundtrip failed: %v", err)
					}
				})
			}
		}
	}
}

func TestMaxUpstreamPlainChunkUsesMultiLabelBudget(t *testing.T) {
	const session = "0123456789abcdef"
	for _, tc := range []struct {
		name  string
		noise bool
		old   int
	}{
		{name: "plain", old: dnsTunnelDefaultChunk},
		{name: "noise", noise: true, old: 22},
	} {
		t.Run(tc.name, func(t *testing.T) {
			n := maxUpstreamPlainChunk("matrix.bench.local", dnsTunnelMarker, session, tc.noise)
			if n <= tc.old {
				t.Fatalf("dynamic chunk=%d did not exceed old fixed chunk=%d", n, tc.old)
			}
			if got := upstreamQNameLen("matrix.bench.local", dnsTunnelMarker, session, n, tc.noise); got > dnsTunnelMaxQNameTextLen {
				t.Fatalf("chunk=%d produced qname len=%d > %d", n, got, dnsTunnelMaxQNameTextLen)
			}
			if got := upstreamQNameLen("matrix.bench.local", dnsTunnelMarker, session, n+1, tc.noise); got <= dnsTunnelMaxQNameTextLen {
				t.Fatalf("chunk=%d was not maximal: chunk+1 qname len=%d still fits", n, got)
			}
		})
	}
}

func TestMaxUpstreamPlainChunkShrinksForLongDomain(t *testing.T) {
	const session = "0123456789abcdef"
	short := maxUpstreamPlainChunk("x.test", dnsTunnelMarker, session, false)
	longDomain := strings.Repeat("a", 50) + "." + strings.Repeat("b", 50) + ".example"
	long := maxUpstreamPlainChunk(longDomain, dnsTunnelMarker, session, false)
	if short <= long {
		t.Fatalf("short-domain chunk=%d, long-domain chunk=%d; expected long domain to reduce capacity", short, long)
	}
	if long <= 0 {
		t.Fatalf("long but valid test domain left no payload budget")
	}
}

func TestMaxUpstreamPlainChunkNoiseReservesTag(t *testing.T) {
	const session = "0123456789abcdef"
	plain := maxUpstreamPlainChunk("example.com", dnsTunnelMarker, session, false)
	noise := maxUpstreamPlainChunk("example.com", dnsTunnelMarker, session, true)
	if noise >= plain {
		t.Fatalf("noise chunk=%d should be smaller than plaintext chunk=%d", noise, plain)
	}
	if plain-noise < noiseTagSize-1 {
		t.Fatalf("noise tag reservation unexpectedly small: plain=%d noise=%d tag=%d", plain, noise, noiseTagSize)
	}
}

func BenchmarkBuildQueryNameDynamicChunk(b *testing.B) {
	const session = "0123456789abcdef"
	for _, noise := range []bool{false, true} {
		name := "plain"
		if noise {
			name = "noise"
		}
		b.Run(name, func(b *testing.B) {
			n := maxUpstreamPlainChunk("matrix.bench.local", dnsTunnelMarker, session, noise)
			wire := n
			if noise {
				wire += noiseTagSize
			}
			payload := make([]byte, wire)
			b.SetBytes(int64(n))
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				_ = buildQueryName(dnsTunnelMarker, "matrix.bench.local", session, uint32(i), uint32(i), uint32(i), flagData, payload)
			}
		})
	}
}
