package dnstunnel

import (
	"strings"
	"testing"
)

func upstreamQNameLen(domain, marker, session string, plain int, noise bool) int {
	wire := plain
	if noise {
		wire += noiseTagSize
	}
	return len(buildQueryName(marker, domain, session, ^uint32(0), ^uint32(0), ^uint32(0), flagData, make([]byte, wire)))
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
