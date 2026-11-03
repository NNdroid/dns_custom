package dnstunnel

import (
	"sync"
)

// queryEncodingBufferPool holds the temporary Base32 run used while
// inserting DNS label separators. Keeping this separate from the final
// QNAME pool lets concurrent query builders reuse both independently.
var queryEncodingBufferPool = sync.Pool{New: func() any {
	buf := make([]byte, 0, 512)
	return &buf
}}

// randomizeQNameCaseBytes applies DNS 0x20 encoding in-place. The hot
// path calls this before the final []byte -> string conversion, avoiding
// the old string -> []byte -> string round trip on every query.
//
// The coin flips come from the in-process stream (fastRandBytes) rather than
// crypto/rand: this runs once per query, and a syscall per query was pure
// overhead on top of an already per-query-syscall-heavy path.
func randomizeQNameCaseBytes(b []byte) {
	if len(b) == 0 {
		return
	}
	var coins [32]byte // 256 bits; DNS names are at most 253 text bytes.
	n := (len(b) + 7) / 8
	if n > len(coins) {
		n = len(coins)
	}
	fastRandBytes(coins[:n])
	bit := 0
	for i := range b {
		if b[i] < 'a' || b[i] > 'z' {
			continue
		}
		if coins[bit>>3]&(1<<uint(bit&7)) != 0 {
			b[i] ^= 0x20
		}
		bit++
	}
}
