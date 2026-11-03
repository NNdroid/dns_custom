package dnstunnel

import (
	crand "crypto/rand"
	mrand "math/rand/v2"
	"sync"
)

// fastRandPool hands out ChaCha8 streams for the anti-spoofing material every
// query carries: the DNS transaction ID and the 0x20 case bits of the QNAME.
//
// Both used to read crypto/rand directly. That is a syscall per read on Windows
// (ProcessPrng) and there are two reads per query, which made it the largest
// avoidable cost on the client's query path: every query paid it twice before a
// single byte reached the network.
//
// What those bits actually need is unpredictability to an off-path attacker, not
// a freshly drawn OS secret per query. One ChaCha8 stream seeded from
// crypto/rand is a real stream cipher, so an observer cannot predict the next
// draws from the bits it sees on the wire, and unlike PCG (invertible, so its
// state is recoverable from its own output) it cannot be reconstructed at all.
//
// A pool rather than one shared stream keeps this off the lock contention path:
// each pooled instance is seeded independently, so the session's concurrent
// pollers and write workers never serialize on it. Losing an instance to a GC
// cycle only costs one reseed.
var fastRandPool = sync.Pool{New: func() any {
	var seed [32]byte
	if _, err := crand.Read(seed[:]); err != nil {
		// crypto/rand does not fail on modern platforms. This fallback only
		// weakens anti-spoofing (Noise keys are derived separately and never
		// touch this), so degrade quietly instead of panicking a hot path.
		seed = [32]byte{0x9e, 0x37, 0x79, 0xb9, 0x7f, 0x4a, 0x7c, 0x15,
			0x2d, 0x8e, 0x91, 0x3b, 0x56, 0xc4, 0x0f, 0xa7,
			0x1c, 0x64, 0xd8, 0x35, 0xeb, 0x02, 0x9a, 0x47,
			0x70, 0xbe, 0x13, 0x5f, 0xc9, 0x26, 0x8d, 0xf1}
	}
	return mrand.NewChaCha8(seed)
}}

// fastRandBytes fills p with unpredictable bytes without touching the OS. It is
// not for key material - it exists for the per-query anti-spoofing bits, where
// the threat is an off-path attacker guessing them, not a cryptanalyst.
func fastRandBytes(p []byte) {
	src := fastRandPool.Get().(*mrand.ChaCha8)
	_, _ = src.Read(p)
	fastRandPool.Put(src)
}
