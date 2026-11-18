package main

import (
	"encoding/json"
	"fmt"
	"net/url"

	"github.com/skip2/go-qrcode"

	dnstunnel "github.com/NNdroid/dns_custom"
)

type StunProfile struct {
	ID                string `json:"id"`
	Name              string `json:"name"`
	SSHAddr           string `json:"sshAddr"`
	User              string `json:"user"`
	Pass              string `json:"pass"`
	AuthType          string `json:"authType"`
	TunnelType        string `json:"tunnelType"`
	ProxyAddr         string `json:"proxyAddr"`
	CustomHost        string `json:"customHost"`
	ServerName        string `json:"serverName"`
	CustomPath        string `json:"customPath"`
	EnableCustomPath  bool   `json:"enableCustomPath"`
	ProxyAuthRequired bool   `json:"proxyAuthRequired"`
	ProxyAuthToken    string `json:"proxyAuthToken"`
	DNSTunnelDomain   string `json:"dnsTunnelDomain"`
	DNSTunnelServers  string `json:"dnsTunnelServers"`
	DNSTunnelType     string `json:"dnsTunnelType"`
	NoisePublicKey    string `json:"noisePublicKey"`
}

// GenerateDNSCustomURI builds both sharing artifacts for the Stun Android / TV
// client: the PIN-encrypted stun:// envelope (plus the PIN that opens it) and
// the plaintext dnsc:// URI for non-Stun clients. It only builds; printing is
// the caller's job so the output appears exactly once and in one place.
func GenerateDNSCustomURI(domain, pubKey, servers, recordType, remark, pin string) (stunURI, protoURI, usedPIN string, err error) {
	pubHex, pubB64 := "", ""
	if pubKey != "" {
		if pk, err := dnstunnel.ParseNoiseKey(pubKey); err == nil {
			pubHex, pubB64 = dnstunnel.FormatNoiseKey(pk)
		}
	}

	rawPub := pubB64
	if rawPub == "" {
		rawPub = pubHex
	}

	name := remark
	if name == "" {
		name = "DNS Custom - " + domain
	}

	// Official Stun Sharing Link (stun://, encrypted like the Stun Android / TV
	// client). A failed encryption is a hard error, not a downgrade: the
	// fallback to a plaintext stun:// would silently ship the profile (domain,
	// resolvers, pubkey) to whoever scans the QR code, and an encryption
	// failure usually means something is wrong with the environment. Fail
	// loudly instead.
	prof := StunProfile{
		Name:             name,
		SSHAddr:          "127.0.0.1:22",
		User:             "root",
		AuthType:         "password",
		TunnelType:       "dns_custom",
		DNSTunnelDomain:  domain,
		DNSTunnelServers: servers,
		DNSTunnelType:    recordType,
		NoisePublicKey:   rawPub,
	}
	profJSON, mErr := json.Marshal(prof)
	if mErr != nil {
		return "", "", "", fmt.Errorf("marshal share profile: %w", mErr)
	}
	stunURI, usedPIN, err = encryptStunURI(profJSON, pin)
	if err != nil {
		return "", "", usedPIN, err
	}

	// Direct Protocol URI (plaintext, for non-Stun clients).
	protoURI = generateDirectProtocolURI(domain, rawPub, servers, recordType)
	return stunURI, protoURI, usedPIN, nil
}

func generateDirectProtocolURI(domain, pubKey, servers, recordType string) string {
	query := make(url.Values, 3)
	query.Set("servers", servers)
	query.Set("type", recordType)
	if pubKey != "" {
		query.Set("pubkey", pubKey)
	}
	return (&url.URL{Scheme: "dnsc", Host: domain, RawQuery: query.Encode()}).String()
}

// PrintTerminalQR renders the share URI as a half-block terminal QR code so the
// Stun Android / TV app can scan it straight off the screen instead of typing
// out a several-hundred-character URI. A rendering failure degrades to pointing
// at the URI printed above rather than aborting the share.
func PrintTerminalQR(text string) {
	qr, err := qrcode.New(text, qrcode.Medium)
	if err != nil {
		fmt.Printf("\n(QR rendering failed: %v — scan or copy the URI above)\n", err)
		return
	}
	fmt.Println("\nScan in Stun Android / TV App (Supports stun:// and direct scan):")
	fmt.Println(qr.ToSmallString(false))
}
