package dnstunnel

import "github.com/miekg/dns"

const (
	// DNS names are limited to 255 octets on the wire. For an ordinary textual
	// absolute name the encoded wire form is one octet longer than the string,
	// so keeping the FQDN at or below 253 bytes leaves one octet of headroom as
	// well as the root label. This conservative ceiling is widely accepted by
	// recursive resolvers and avoids relying on their edge-case 254-byte rules.
	dnsTunnelMaxQueryNameLen = 253

	// buildQueryName deliberately uses labels shorter than the protocol maximum
	// so middleboxes that append/inspect names have a little margin per label.
	dnsTunnelPayloadLabelLen = 61
)

// maxUpstreamChunkSize returns the largest PLAINTEXT data chunk that still
// produces a query name within dnsTunnelMaxQueryNameLen for every uint32 query,
// acknowledgement and data sequence value. buildQueryName already splits the
// Base32 payload over as many 61-byte labels as necessary, so the correct limit
// is the whole QNAME budget rather than one DNS label.
//
// domain may be relative or absolute; marker and session are fixed for the
// lifetime of a tunnel. noise adds the AEAD tag before Base32 encoding.
func maxUpstreamChunkSize(domain, session, marker string, noise bool) int {
	domain = dns.Fqdn(domain)
	if marker == "" {
		marker = dnsTunnelMarker
	}

	// Worst-case decimal widths are used so a long-lived session does not
	// suddenly exceed the QNAME limit when a sequence crosses a power of ten.
	// Layout:
	//   session.seq.ack.flag.dataSeq.[payload labels.]marker.domain.
	fixed := len(session) + 1 +
		10 + 1 +
		10 + 1 +
		1 + 1 +
		10 + 1 +
		len(marker) + 1 +
		len(domain)
	if fixed >= dnsTunnelMaxQueryNameLen {
		return 0
	}

	tag := 0
	if noise {
		tag = noiseTagSize
	}

	fits := func(plain int) bool {
		if plain <= 0 {
			return fixed <= dnsTunnelMaxQueryNameLen
		}
		encoded := dnsTunnelB32.EncodedLen(plain + tag)
		labels := (encoded + dnsTunnelPayloadLabelLen - 1) / dnsTunnelPayloadLabelLen
		// Each payload label contributes one separating dot.
		return fixed+encoded+labels <= dnsTunnelMaxQueryNameLen
	}

	// Base32 expands 5 input bytes into 8 output bytes; using the remaining
	// text budget as an upper bound keeps the binary search tiny while still
	// comfortably covering the exact answer.
	remaining := dnsTunnelMaxQueryNameLen - fixed
	high := remaining*5/8 + 1
	if noise {
		high -= tag
		if high < 1 {
			return 0
		}
	}
	low := 0
	for low < high {
		mid := low + (high-low+1)/2
		if fits(mid) {
			low = mid
		} else {
			high = mid - 1
		}
	}
	return low
}
