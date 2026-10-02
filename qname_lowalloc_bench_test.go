package dnstunnel

import (
	"bytes"
	"testing"
)

func TestBuildQueryNameRandomizedRoundTrip(t *testing.T) {
	payload := bytes.Repeat([]byte{0xa5}, 96)
	for i := 0; i < 32; i++ {
		name := buildQueryNameRandomized(dnsTunnelMarker, "example.com", "0123456789abcdef", 123, 45, 67, flagData, payload)
		session, seq, ack, dataSeq, flag, got, err := parseQueryName("example.com", name)
		if err != nil {
			t.Fatalf("parse randomized query: %v", err)
		}
		if session != "0123456789abcdef" || seq != 123 || ack != 45 || dataSeq != 67 || flag != flagData || !bytes.Equal(got, payload) {
			t.Fatalf("round trip mismatch: session=%q seq=%d ack=%d dataSeq=%d flag=%q payload=%d", session, seq, ack, dataSeq, flag, len(got))
		}
	}
}

func BenchmarkQNameHotPath(b *testing.B) {
	payload := make([]byte, 96)
	b.ReportAllocs()
	b.SetBytes(int64(len(payload)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = buildQueryNameRandomized(dnsTunnelMarker, "matrix.bench.local", "0123456789abcdef", uint32(i), uint32(i), uint32(i), flagData, payload)
	}
}
