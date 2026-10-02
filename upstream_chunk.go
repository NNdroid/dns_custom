package dnstunnel

import "github.com/miekg/dns"

const (
	// A DNS name may occupy at most 255 wire octets including label-length
	// bytes and the root terminator. For an FQDN string, len(name)+1 is the
	// corresponding uncompressed wire size, so 253 leaves one octet of margin
	// below the protocol ceiling while still using essentially the full QNAME.
	dnsTunnelMaxQNameTextLen = 253

	// Payload labels deliberately stay below the 63-octet DNS label ceiling.
	// buildQueryName uses the same split width.
	dnsTunnelPayloadLabelChars = 61
)

// maxUpstreamPlainChunk returns the largest plaintext DATA chunk whose
// worst-case query name still fits the DNS name limit. It reserves ten decimal
// digits for each uint32 field so the chosen size remains valid for the whole
// session as sequence and acknowledgement numbers grow.
//
// With Noise enabled, the AEAD tag is part of the Base32-encoded QNAME, so it
// consumes name budget even though it is not application payload.
func maxUpstreamPlainChunk(domain, marker, session string, noise bool) int {
	domain = dns.Fqdn(domain)
	if marker == "" {
		marker = dnsTunnelMarker
	}

	// session.seq.ack.flag.dataSeq.<payload labels>.marker.domain.
	fixed := len(session) + 1 +
		10 + 1 +
		10 + 1 +
		1 + 1 +
		10 + 1 +
		len(marker) + 1 +
		len(domain)
	if fixed >= dnsTunnelMaxQNameTextLen {
		return 0
	}

	tag := 0
	if noise {
		tag = noiseTagSize
	}
	fits := func(plain int) bool {
		if plain <= 0 {
			return false
		}
		encoded := dnsTunnelB32.EncodedLen(plain + tag)
		labels := (encoded + dnsTunnelPayloadLabelChars - 1) / dnsTunnelPayloadLabelChars
		// Each payload label contributes one separator dot in the FQDN.
		return fixed+encoded+labels <= dnsTunnelMaxQNameTextLen
	}

	// The QNAME itself bounds the answer tightly; 256 is already above what a
	// 253-octet name can encode after fixed tunnel fields. Keep the search bound
	// explicit so an accidental arithmetic change cannot create huge chunks.
	lo, hi := 0, 256
	for lo < hi {
		mid := lo + (hi-lo+1)/2
		if fits(mid) {
			lo = mid
		} else {
			hi = mid - 1
		}
	}
	return lo
}
