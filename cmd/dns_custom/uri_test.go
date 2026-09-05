package main

import (
	"encoding/base64"
	"encoding/json"
	"net/url"
	"testing"
)

// The Stun Android / TV client rejects envelopes whose version, compression flag,
// salt length, nonce length or ciphertext length are out of range; decryptStunURI
// must do the same instead of panicking or accepting garbage.
func TestDecryptStunURIRejectsMalformedEnvelope(t *testing.T) {
	encode := func(env shareEnvelope) string {
		raw, err := json.Marshal(env)
		if err != nil {
			t.Fatal(err)
		}
		return "stun://" + base64.StdEncoding.EncodeToString(raw)
	}
	validField := func(n int) string { return base64.StdEncoding.EncodeToString(make([]byte, n)) }
	cases := map[string]shareEnvelope{
		"compression flag": {V: 1, G: 2, S: validField(shareSaltLen), I: validField(shareIvLen), C: validField(16)},
		"salt length":      {V: 1, S: validField(1), I: validField(shareIvLen), C: validField(16)},
		"nonce length":     {V: 1, S: validField(shareSaltLen), I: validField(1), C: validField(16)},
		"ciphertext":       {V: 1, S: validField(shareSaltLen), I: validField(shareIvLen), C: validField(1)},
	}
	for name, env := range cases {
		t.Run(name, func(t *testing.T) {
			defer func() {
				if recovered := recover(); recovered != nil {
					t.Fatalf("malformed envelope panicked: %v", recovered)
				}
			}()
			if _, err := decryptStunURI(encode(env), "123456"); err == nil {
				t.Fatal("malformed envelope was accepted")
			}
		})
	}
}

func TestDirectProtocolURIEscapesQueryValues(t *testing.T) {
	servers := "https://dns.example/dns-query,1.1.1.1:53"
	pubKey := "a+b/c=="
	raw := generateDirectProtocolURI("tunnel.example", pubKey, servers, "txt")
	parsed, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parse generated URI: %v", err)
	}
	if parsed.Scheme != "dnsc" || parsed.Host != "tunnel.example" {
		t.Fatalf("unexpected URI authority: %s", raw)
	}
	if got := parsed.Query().Get("servers"); got != servers {
		t.Fatalf("servers round trip = %q, want %q", got, servers)
	}
	if got := parsed.Query().Get("pubkey"); got != pubKey {
		t.Fatalf("pubkey round trip = %q, want %q", got, pubKey)
	}
}
