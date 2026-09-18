package dnstunnel

import (
	"strings"
	"testing"

	"github.com/miekg/dns"
)

// TestV2QueryNameRoundTrip locks in the v2 wire layout: a multi-label upstream
// payload must survive build -> parse with every field intact, and empty
// payloads (polls) must produce no data labels at all.
func TestV2QueryNameRoundTrip(t *testing.T) {
	domain := "tunnel.example.com."
	session := "u0123456789abcdef"
	payload := make([]byte, 76)
	for i := range payload {
		payload[i] = byte(i)
	}

	name := buildQueryName("tunnel2", domain, session, 42, 7, 9, flagData, payload)
	if !strings.Contains(name, "tunnel2.") {
		t.Fatalf("v2 name lacks the tunnel2 marker: %q", name)
	}
	if strings.Count(name, ".") > 127 || len(name) > 253 {
		t.Fatalf("v2 name exceeds DNS limits: %d chars", len(name))
	}

	gotSession, seq, ack, dataSeq, flag, gotData, err := parseQueryNameV2(
		dns.SplitDomainName(name), len(dns.SplitDomainName(name))-len(dns.SplitDomainName(domain))-1, name)
	if err != nil {
		t.Fatalf("parse v2 name: %v", err)
	}
	if gotSession != session || seq != 42 || ack != 7 || dataSeq != 9 || flag != flagData {
		t.Fatalf("v2 header mismatch: session=%q seq=%d ack=%d dataSeq=%d flag=%q",
			gotSession, seq, ack, dataSeq, flag)
	}
	if string(gotData) != string(payload) {
		t.Fatalf("v2 payload corrupted: got %d bytes, want %d", len(gotData), len(payload))
	}

	// Polls carry no payload and therefore no data labels.
	pollName := buildQueryName("tunnel2", domain, session, 43, 7, 128, flagPoll, nil)
	labels := dns.SplitDomainName(pollName)
	markerIndex := len(labels) - len(dns.SplitDomainName(domain)) - 1
	if markerIndex != 5 {
		t.Fatalf("v2 poll should have zero data labels: markerIndex=%d", markerIndex)
	}
	if _, _, _, _, _, got, err := parseQueryNameV2(labels, markerIndex, pollName); err != nil || len(got) != 0 {
		t.Fatalf("v2 poll parse: data=%q err=%v", got, err)
	}

	// The full parser dispatches v2 names through the same entry point as v1.
	s2, _, _, _, f2, d2, err := parseQueryName(domain, name)
	if err != nil || s2 != session || f2 != flagData || string(d2) != string(payload) {
		t.Fatalf("parseQueryName v2 dispatch failed: %v", err)
	}
}

// TestV2QueryNameRejectsGarbage keeps the v2 parser as strict as the v1 one.
func TestV2QueryNameRejectsGarbage(t *testing.T) {
	domain := "t.example.com."
	good := buildQueryName("tunnel2", domain, "uabcd", 1, 0, 1, flagPoll, nil)
	labels := dns.SplitDomainName(good)
	markerIndex := len(labels) - len(dns.SplitDomainName(domain)) - 1

	bad := append([]string(nil), labels...)
	bad[3] = "XY" // flag must be a single character
	if _, _, _, _, _, _, err := parseQueryNameV2(bad, markerIndex, strings.Join(bad, ".")); err == nil {
		t.Fatal("invalid flag accepted")
	}

	bad = append([]string(nil), labels...)
	bad[1] = "not-a-number" // seq must be numeric
	if _, _, _, _, _, _, err := parseQueryNameV2(bad, markerIndex, strings.Join(bad, ".")); err == nil {
		t.Fatal("non-numeric seq accepted")
	}

	// Data names carry payload labels between dataSeq and the marker; corrupt
	// the first payload label with characters outside the base32 alphabet.
	dataName := buildQueryName("tunnel2", domain, "uabcd", 1, 0, 1, flagData, []byte("payload"))
	dLabels := dns.SplitDomainName(dataName)
	dMarker := len(dLabels) - len(dns.SplitDomainName(domain)) - 1
	bad = append([]string(nil), dLabels...)
	bad[5] = "0000"
	if _, _, _, _, _, _, err := parseQueryNameV2(bad, dMarker, strings.Join(bad, ".")); err == nil {
		t.Fatal("invalid payload base32 accepted")
	}
}
