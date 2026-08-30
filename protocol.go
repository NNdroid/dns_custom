package main

import (
	"bytes"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/miekg/dns"
)

const (
	dnsTunnelDefaultChunk = 32
	dnsTunnelQueryTimeout = 5 * time.Second
	dnsTunnelPollInterval = 150 * time.Millisecond
	// dnsTunnelMaxServerChunk is the nominal downstream chunk size. The actual size
	// is always capped by maxDownstreamPayload, which shrinks the chunk until the
	// answer fits the 512-byte UDP budget for this particular query name.
	dnsTunnelMaxServerChunk = 200
	dnsTunnelCloseTimeout   = 2 * time.Second
	dnsTunnelMarker         = "tunnel"
	// dnsTunnelDownstreamWindow bounds how many downstream chunks may be
	// outstanding (unacked) at once. Concurrent polls each fetch one chunk, so the
	// window is what lets several upstream servers add up to more throughput
	// instead of every poll getting a retransmit of the same oldest chunk. It also
	// caps how many answers one session can have in flight, which is what keeps the
	// query rate and the per-session retransmit buffer bounded.
	dnsTunnelDownstreamWindow = 16
	// dnsTunnelUpstreamWindow* bound the adaptive in-flight window for upstream chunks.
	// Chunks carry their own dataSeq, so the server dedups and reorder-assembles them
	// no matter which path delivers them - but how many may be in flight at once has no
	// universally correct value. Measured on a loopback link 8 is already the peak
	// (more in flight makes every query slower and throughput falls), while on a 20 ms
	// path 16 nearly doubles throughput. The window therefore adapts from the RTT of
	// the queries themselves instead of being hardcoded.
	dnsTunnelUpstreamWindow    = 8 // per path, initial
	dnsTunnelMinUpstreamWindow = 4 // per path
	dnsTunnelMaxUpstreamWindow = 16
	// dnsTunnelMaxTotalWindow caps the window across every path, so a long server list
	// cannot turn into an unbounded query flood.
	dnsTunnelMaxTotalWindow = 64
	// dnsTunnelWindowWarmup is how many leading upstream samples the adaptive window
	// ignores, so cold-start latency is never mistaken for the path's best RTT.
	dnsTunnelWindowWarmup = 16
	// dnsTunnelPollBusyInterval paces a poller that just received data. On a real
	// network the round trip dominates anyway; this only stops a zero-RTT peer from
	// turning into a busy loop.
	dnsTunnelPollBusyInterval = time.Millisecond
	// dnsTunnelDownstreamBacklog is how much undelivered data the pollers buffer
	// before they stop asking for more, so a slow reader cannot make the tunnel hoard
	// answers in memory.
	dnsTunnelDownstreamBacklog = 64 * 1024
	// A downstream chunk still unacked after this long is abandoned and a gap is
	// accepted. Without this, one response that a resolver keeps dropping would
	// stall the whole stream forever (the server retransmits the oldest chunk and
	// never serves anything else).
	dnsTunnelDownstreamGiveUp = 30 * time.Second
)

const (
	flagData  = 'D'
	flagPoll  = 'P'
	flagClose = 'C'
)

// seqLess compares two sequence numbers safely across uint32 wraparound.
// Plain `<` would misread a fresh chunk as a stale duplicate once the counter
// wraps, silently killing the stream.
func seqLess(a, b uint32) bool { return int32(a-b) < 0 }

var dnsTunnelB32 = base32.NewEncoding("abcdefghijklmnopqrstuvwxyz234567").WithPadding(base32.NoPadding)

func dnsTypeToQType(t string) (uint16, error) {
	switch strings.ToLower(strings.TrimSpace(t)) {
	case "", "txt":
		return dns.TypeTXT, nil
	case "null":
		return dns.TypeNULL, nil
	case "cname":
		return dns.TypeCNAME, nil
	case "a":
		return dns.TypeA, nil
	case "aaaa":
		return dns.TypeAAAA, nil
	case "mx":
		return dns.TypeMX, nil
	case "srv":
		return dns.TypeSRV, nil
	case "ns":
		return dns.TypeNS, nil
	default:
		return 0, fmt.Errorf("unsupported dns record type: %q (supported: txt/null/cname/a/aaaa/mx/srv/ns)", t)
	}
}

func qTypeToDnsType(qtype uint16) string {
	switch qtype {
	case dns.TypeTXT:
		return "TXT"
	case dns.TypeNULL:
		return "NULL"
	case dns.TypeCNAME:
		return "CNAME"
	case dns.TypeA:
		return "A"
	case dns.TypeAAAA:
		return "AAAA"
	case dns.TypeMX:
		return "MX"
	case dns.TypeSRV:
		return "SRV"
	case dns.TypeNS:
		return "NS"
	default:
		return "TXT"
	}
}

// buildQueryName encodes a tunnel query. The name layout is:
//
//	{querySeq}.{ack}.{flag}.{dataSeq}.{b32data}.{session}.tunnel.{domain}
//
// querySeq : unique per query, defeats DNS caching (monotonic)
// ack      : highest contiguous downstream serverSeq the client has received (for retransmit buffer freeing)
// flag     : D/P/C (data/poll/close)
// dataSeq  : per-data-chunk upstream ordering sequence (used for server-side dedup + in-order reassembly)
func buildQueryName(domain, session string, querySeq, ack, dataSeq uint32, flag byte, data []byte) string {
	seqStr := strconv.FormatUint(uint64(querySeq), 10)
	ackStr := strconv.FormatUint(uint64(ack), 10)
	dataSeqStr := strconv.FormatUint(uint64(dataSeq), 10)
	b32Str := "-"
	if len(data) > 0 {
		b32Str = dnsTunnelB32.EncodeToString(data)
	}
	return strings.Join([]string{
		seqStr,
		ackStr,
		string(flag),
		dataSeqStr,
		b32Str,
		session,
		dnsTunnelMarker,
		dns.Fqdn(domain),
	}, ".")
}

// Downstream framing for the reliable-ordered TXT transport:
//
//	[serverSeq:4 BE][skipTo:4 BE][payload...]
//
// serverSeq lets the client reassemble out-of-order / lost downstream chunks.
// skipTo (0 = none) tells the client the server gave up on every chunk below it,
// so the client jumps forward instead of blocking forever on an unrecoverable gap.
// A gap corrupts the byte stream for the current session, but the app (e.g. SSH)
// reconnects with a clean session, which is strictly better than a dead tunnel.
//
// The header is always plaintext, and with Noise enabled only the payload is
// encrypted (nonce = serverSeq). The header has to stay readable: it carries the
// sequence number the client needs to reconstruct the nonce.
const downstreamHeaderSize = 8

// Non-TXT frames carry no skipTo (best-effort, no retransmission) and only exist
// when Noise is enabled, for the same reason: the client needs the sequence number
// before it can decrypt anything.
const nonTxtNoiseHeaderSize = 4

// dnsTunnelMaxUDPResponse is the largest UDP response a client can actually receive
// without EDNS0: resolvers and DNS client libraries buffer exactly 512 bytes, and a
// larger datagram is dropped or fails the read outright (the query name is echoed in
// the answer, so a data query plus a full-size chunk easily overruns this).
const dnsTunnelMaxUDPResponse = 512

// encodedRdataSize is the wire size of an answer's rdata for n payload bytes.
func encodedRdataSize(n int, qtype uint16) int {
	switch qtype {
	case dns.TypeNULL:
		return n // raw rdata bytes
	case dns.TypeA, dns.TypeAAAA:
		return 0 // fixed-size rdata; the payload length never inflates the answer
	case dns.TypeTXT:
		b32 := (n*8 + 4) / 5
		// One length byte per TXT string, strings capped at 248 chars by splitTxt.
		return b32 + (b32+247)/248
	default:
		// CNAME / MX / SRV / NS: a single base32 label -> one length byte + chars.
		return 1 + (n*8+4)/5
	}
}

// fitDownstreamPayload shrinks n until the complete answer fits inside a plain
// 512-byte UDP response. The query name is echoed in the answer, so a data query -
// which carries the upstream chunk inside its name - leaves much less room for the
// downstream payload than a short poll does.
func fitDownstreamPayload(qname string, n int, qtype uint16) int {
	if n <= 0 {
		return 0
	}
	// Header (12) + question (name + 4) + answer header (name echoed + 10).
	fixed := 12 + (len(qname) + 2) + 4 + (len(qname) + 2) + 10
	budget := dnsTunnelMaxUDPResponse - fixed
	for n > 0 && encodedRdataSize(n, qtype) > budget {
		n--
	}
	return n
}

// maxDownstreamPayload is the largest plaintext payload one answer may carry: the
// record type capacity, minus the framing overhead the receiver has to see, shrunk
// until the whole response fits on the wire.
func maxDownstreamPayload(qtype uint16, noise bool, qname string) int {
	capacity := downstreamCap(qtype, noise)
	overhead := 0
	switch {
	case qtype == dns.TypeTXT:
		overhead = downstreamHeaderSize
		if noise {
			overhead += noiseTagSize
		}
	default:
		if noise {
			overhead = nonTxtNoiseHeaderSize + noiseTagSize
		}
	}
	avail := fitDownstreamPayload(qname, capacity+overhead, qtype) - overhead
	if avail > capacity {
		avail = capacity
	}
	if avail < 0 {
		avail = 0
	}
	return avail
}

// downstreamCap is the largest plaintext payload one answer of the given record
// type can carry. Serving more than this silently truncates the chunk (A/AAAA only
// hold one address, and label-based records are bounded by the 63-byte DNS label
// limit), so the sender must chunk to the record type, not to a fixed 32 bytes.
func downstreamCap(qtype uint16, noise bool) int {
	switch qtype {
	case dns.TypeNULL:
		// NULL RDATA is raw bytes, bounded only by the 512-byte UDP response.
		return dnsTunnelMaxServerChunk
	case dns.TypeA:
		return 4
	case dns.TypeAAAA:
		return 16
	default:
		// CNAME / MX / SRV / NS: the whole payload is base32'd into a single
		// label, so 63 label chars == 39 bytes of frame.
		if noise {
			// [seq:4] + ciphertext(payload + 16 byte AEAD tag).
			return 19
		}
		return 39
	}
}

func encodeDownstreamFrame(serverSeq, skipTo uint32, payload []byte) []byte {
	buf := make([]byte, downstreamHeaderSize+len(payload))
	binary.BigEndian.PutUint32(buf[0:4], serverSeq)
	binary.BigEndian.PutUint32(buf[4:8], skipTo)
	copy(buf[downstreamHeaderSize:], payload)
	return buf
}

func decodeDownstreamFrame(buf []byte) (serverSeq, skipTo uint32, payload []byte, ok bool) {
	if len(buf) < downstreamHeaderSize {
		return 0, 0, nil, false
	}
	serverSeq = binary.BigEndian.Uint32(buf[0:4])
	skipTo = binary.BigEndian.Uint32(buf[4:8])
	payload = buf[downstreamHeaderSize:]
	return serverSeq, skipTo, payload, true
}

func parseQueryName(domain, name string) (session string, querySeq, ack, dataSeq uint32, flag byte, data []byte, err error) {
	labels := dns.SplitDomainName(name)
	domainLabels := dns.SplitDomainName(domain)
	if len(labels) < 6+len(domainLabels)+1 {
		return "", 0, 0, 0, 0, nil, fmt.Errorf("malformed query name %q", name)
	}
	markerIndex := len(labels) - len(domainLabels) - 1
	if markerIndex < 6 || !strings.EqualFold(labels[markerIndex], dnsTunnelMarker) {
		return "", 0, 0, 0, 0, nil, fmt.Errorf("tunnel marker not found in %q", name)
	}
	session = labels[markerIndex-1]
	b32Str := labels[markerIndex-2]
	if flagStr := labels[markerIndex-4]; len(flagStr) > 0 {
		flag = flagStr[0]
	} else {
		return "", 0, 0, 0, 0, nil, fmt.Errorf("empty flag in %q", name)
	}
	if ds, e := strconv.ParseUint(labels[markerIndex-3], 10, 32); e == nil {
		dataSeq = uint32(ds)
	}
	if ak, e := strconv.ParseUint(labels[markerIndex-5], 10, 32); e == nil {
		ack = uint32(ak)
	}
	seqU, perr := strconv.ParseUint(labels[markerIndex-6], 10, 32)
	if perr != nil {
		return "", 0, 0, 0, 0, nil, fmt.Errorf("bad seq in %q: %w", name, perr)
	}
	querySeq = uint32(seqU)
	data, derr := dnsTunnelB32.DecodeString(strings.ToLower(b32Str))
	if derr != nil {
		data = nil
	}
	return session, querySeq, ack, dataSeq, flag, data, nil
}

func splitTxt(s string) []string {
	const max = 255
	const step = 248
	if len(s) <= max {
		return []string{s}
	}
	var out []string
	for i := 0; i < len(s); i += step {
		end := i + step
		if end > len(s) {
			end = len(s)
		}
		out = append(out, s[i:end])
	}
	return out
}

func encodeTunnelLabel(data []byte, domain string) string {
	b32s := dnsTunnelB32.EncodeToString(data)
	if len(b32s) > 63 {
		b32s = b32s[:63]
	}
	return b32s + "." + dnsTunnelMarker + "." + dns.Fqdn(domain)
}

func decodeTunnelLabel(name string) []byte {
	labels := dns.SplitDomainName(name)
	if len(labels) == 0 {
		return nil
	}
	if d, e := dnsTunnelB32.DecodeString(strings.ToLower(labels[0])); e == nil {
		return d
	}
	return nil
}

func makeAnswer(qname string, qtype uint16, data []byte, domain string) dns.RR {
	hdr := dns.RR_Header{Name: qname, Rrtype: qtype, Class: dns.ClassINET, Ttl: 0}
	switch qtype {
	case dns.TypeTXT:
		return &dns.TXT{Hdr: hdr, Txt: splitTxt(dnsTunnelB32.EncodeToString(data))}
	case dns.TypeNULL:
		return &dns.NULL{Hdr: hdr, Data: string(data)}
	case dns.TypeCNAME:
		b32s := dnsTunnelB32.EncodeToString(data)
		if len(b32s) > 63 {
			b32s = b32s[:63]
		}
		target := b32s + "." + dnsTunnelMarker + "." + dns.Fqdn(domain)
		return &dns.CNAME{Hdr: hdr, Target: target}
	case dns.TypeA:
		ip := net.IPv4zero.To4()
		if len(data) >= 4 {
			ip = net.IP(append([]byte(nil), data[:4]...)).To4()
		}
		return &dns.A{Hdr: hdr, A: ip}
	case dns.TypeAAAA:
		ip := net.IPv6zero.To16()
		if len(data) >= 16 {
			ip = net.IP(append([]byte(nil), data[:16]...)).To16()
		}
		return &dns.AAAA{Hdr: hdr, AAAA: ip}
	case dns.TypeMX:
		return &dns.MX{Hdr: hdr, Preference: 0, Mx: encodeTunnelLabel(data, domain)}
	case dns.TypeSRV:
		return &dns.SRV{Hdr: hdr, Priority: 0, Weight: 0, Port: 0, Target: encodeTunnelLabel(data, domain)}
	case dns.TypeNS:
		return &dns.NS{Hdr: hdr, Ns: encodeTunnelLabel(data, domain)}
	default:
		return &dns.TXT{Hdr: hdr, Txt: splitTxt(dnsTunnelB32.EncodeToString(data))}
	}
}

func extractAnswer(rr dns.RR) []byte {
	switch v := rr.(type) {
	case *dns.TXT:
		var sb strings.Builder
		for _, s := range v.Txt {
			sb.WriteString(s)
		}
		fullStr := strings.ToLower(sb.String())
		if d, e := dnsTunnelB32.DecodeString(fullStr); e == nil {
			return d
		}
		return nil
	case *dns.NULL:
		return []byte(v.Data)
	case *dns.CNAME:
		return decodeTunnelLabel(v.Target)
	case *dns.A:
		if v.A.Equal(net.IPv4zero) {
			return nil
		}
		return v.A.To4()
	case *dns.AAAA:
		if bytes.Equal(v.AAAA, net.IPv6zero) {
			return nil
		}
		return v.AAAA.To16()
	case *dns.MX:
		return decodeTunnelLabel(v.Mx)
	case *dns.SRV:
		return decodeTunnelLabel(v.Target)
	case *dns.NS:
		return decodeTunnelLabel(v.Ns)
	}
	return nil
}
