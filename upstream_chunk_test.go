package dnstunnel

import (
	"bytes"
	"testing"
)

func TestMaxUpstreamChunkSizeFitsQName(t *testing.T) {
	tests := []struct {
		name    string
		domain  string
		session string
		marker  string
		noise   bool
	}{
		{name: "plain-short", domain: "bench.local", session: "0123456789abcdef", marker: dnsTunnelMarker},
		{name: "noise-short", domain: "bench.local", session: "0123456789abcdef", marker: dnsTunnelMarker, noise: true},
		{name: "udp-session", domain: "matrix.bench.local", session: "u0123456789abcdef", marker: dnsTunnelMarker, noise: true},
		{name: "custom-marker", domain: "very.long.test.domain.example", session: "0123456789abcdef", marker: "custommarker123", noise: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			chunk := maxUpstreamChunkSize(tc.domain, tc.session, tc.marker, tc.noise)
			if chunk <= 0 {
				t.Fatalf("chunk=%d", chunk)
			}

			wireLen := chunk
			if tc.noise {
				wireLen += noiseTagSize
			}
			payload := bytes.Repeat([]byte{0x5a}, wireLen)
			name := buildQueryName(tc.marker, tc.domain, tc.session, ^uint32(0), ^uint32(0), ^uint32(0), flagData, payload)
			if got := len(name); got > dnsTunnelMaxQueryNameLen {
				t.Fatalf("max chunk produced %d-byte qname, limit=%d", got, dnsTunnelMaxQueryNameLen)
			}

			// The returned value is maximal: one more plaintext byte must no
			// longer fit the conservative QNAME ceiling.
			wireLen++
			payload = bytes.Repeat([]byte{0x5a}, wireLen)
			name = buildQueryName(tc.marker, tc.domain, tc.session, ^uint32(0), ^uint32(0), ^uint32(0), flagData, payload)
			if got := len(name); got <= dnsTunnelMaxQueryNameLen {
				t.Fatalf("chunk+1 still fits: qname=%d limit=%d", got, dnsTunnelMaxQueryNameLen)
			}
		})
	}
}

func TestDynamicUpstreamChunkUsesMoreThanTwoLabels(t *testing.T) {
	const (
		domain  = "bench.local"
		session = "0123456789abcdef"
	)

	plainChunk := maxUpstreamChunkSize(domain, session, dnsTunnelMarker, false)
	noiseChunk := maxUpstreamChunkSize(domain, session, dnsTunnelMarker, true)
	if plainChunk <= 2*dnsTunnelPayloadLabelLen*5/8 {
		t.Fatalf("plain chunk=%d did not improve beyond legacy two-label budget", plainChunk)
	}
	if noiseChunk <= 2*dnsTunnelPayloadLabelLen*5/8-noiseTagSize {
		t.Fatalf("noise chunk=%d did not improve beyond legacy two-label budget", noiseChunk)
	}
}

func TestDynamicUpstreamChunkRoundTrip(t *testing.T) {
	const (
		domain  = "bench.local"
		session = "0123456789abcdef"
	)
	chunk := maxUpstreamChunkSize(domain, session, dnsTunnelMarker, false)
	payload := bytes.Repeat([]byte("x"), chunk)
	name := buildQueryName(dnsTunnelMarker, domain, session, 7, 8, 9, flagData, payload)

	gotSession, querySeq, ack, dataSeq, flag, got, err := parseQueryName(domain, name)
	if err != nil {
		t.Fatal(err)
	}
	if gotSession != session || querySeq != 7 || ack != 8 || dataSeq != 9 || flag != flagData {
		t.Fatalf("metadata mismatch: session=%q query=%d ack=%d data=%d flag=%q", gotSession, querySeq, ack, dataSeq, flag)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("payload mismatch: got=%d want=%d", len(got), len(payload))
	}
}
