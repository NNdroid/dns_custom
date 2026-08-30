package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
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

func GenerateDNSCustomURI(domain, pubKey, servers, recordType, remark, pin string) string {
	pubHex, pubB64 := "", ""
	if pubKey != "" {
		if pk, err := ParseNoiseKey(pubKey); err == nil {
			pubHex, pubB64 = FormatNoiseKey(pk)
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

	// 1. Official Stun Sharing Link (stun://, encrypted like the Stun Android / TV client)
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
	profJSON, _ := json.Marshal(prof)
	stunURI, usedPin, err := encryptStunURI(profJSON, pin)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Warning: failed to encrypt share URI (%v); falling back to plaintext stun://.\n", err)
		stunURI = "stun://" + base64.StdEncoding.EncodeToString(profJSON)
	}

	// 2. Direct Protocol URI (plaintext, for non-Stun clients)
	protoURI := fmt.Sprintf("dnsc://%s?servers=%s&type=%s", domain, servers, recordType)
	if rawPub != "" {
		protoURI += "&pubkey=" + rawPub
	}

	fmt.Printf("\n[1] Official Stun Sharing Link (stun://, encrypted):\n  %s\n", stunURI)
	if pin == "" {
		fmt.Printf("\n[PIN] %s  <- share this PIN with the importer (Stun App will ask for it)\n", usedPin)
	} else {
		fmt.Printf("\n[PIN] (using provided PIN)\n")
	}
	fmt.Printf("\n[2] Direct Protocol URI (plaintext):\n  %s\n\n", protoURI)

	return stunURI
}

func PrintTerminalQR(text string) {
	fmt.Println("Scan in Stun Android / TV App (Supports stun:// and direct scan):")
	fmt.Printf("\n  %s\n\n", text)
}
