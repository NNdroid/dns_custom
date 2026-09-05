package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDNSCustom_JSONConfigParsing(t *testing.T) {
	tempDir := t.TempDir()

	// 1. Test Server Config Parsing
	serverJSON := `{
		"mode": "server",
		"listen": ":15353",
		"target": "tcp://127.0.0.1:2222",
		"domain": "test.example.com",
		"privkey": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		"log_level": "debug"
	}`
	serverConfPath := filepath.Join(tempDir, "server.json")
	if err := os.WriteFile(serverConfPath, []byte(serverJSON), 0644); err != nil {
		t.Fatalf("write server.json failed: %v", err)
	}

	sCfg, err := loadConfigFile(serverConfPath)
	if err != nil {
		t.Fatalf("load server config failed: %v", err)
	}
	if sCfg.Mode != "server" || sCfg.Listen != ":15353" || sCfg.Target != "tcp://127.0.0.1:2222" || sCfg.Domain != "test.example.com" || sCfg.LogLevel != "debug" {
		t.Fatalf("parsed server config mismatch: %+v", sCfg)
	}

	// 2. Test Client Config Parsing with Array Servers & Type Alias
	clientJSON := `{
		"mode": "client",
		"listen": "127.0.0.1:1080",
		"domain": "test.example.com",
		"pubkey": "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
		"servers": [
			"8.8.8.8:53",
			"1.1.1.1:53",
			"https://1.1.1.1/dns-query"
		],
		"type": "null",
		"log_level": "warn"
	}`
	clientConfPath := filepath.Join(tempDir, "client.json")
	if err := os.WriteFile(clientConfPath, []byte(clientJSON), 0644); err != nil {
		t.Fatalf("write client.json failed: %v", err)
	}

	cCfg, err := loadConfigFile(clientConfPath)
	if err != nil {
		t.Fatalf("load client config failed: %v", err)
	}
	if cCfg.Mode != "client" || cCfg.Listen != "127.0.0.1:1080" || cCfg.Domain != "test.example.com" || cCfg.RecordType != "null" || cCfg.LogLevel != "warn" {
		t.Fatalf("parsed client config mismatch: %+v", cCfg)
	}
	if len(cCfg.Servers) != 3 || cCfg.Servers[0] != "8.8.8.8:53" || cCfg.Servers[2] != "https://1.1.1.1/dns-query" {
		t.Fatalf("parsed client servers array mismatch: %+v", cCfg.Servers)
	}

	// 3. Test Client Config with Comma-separated Servers String
	clientStringServersJSON := `{
		"mode": "client",
		"servers": "9.9.9.9:53, 149.112.112.112:53",
		"record_type": "cname"
	}`
	clientStrPath := filepath.Join(tempDir, "client_str.json")
	if err := os.WriteFile(clientStrPath, []byte(clientStringServersJSON), 0644); err != nil {
		t.Fatalf("write client_str.json failed: %v", err)
	}
	cStrCfg, err := loadConfigFile(clientStrPath)
	if err != nil {
		t.Fatalf("load client string servers config failed: %v", err)
	}
	if len(cStrCfg.Servers) != 2 || cStrCfg.Servers[0] != "9.9.9.9:53" || cStrCfg.Servers[1] != "149.112.112.112:53" || cStrCfg.RecordType != "cname" {
		t.Fatalf("parsed client string servers mismatch: %+v", cStrCfg.Servers)
	}

	// 4. Client target declaration syntax: udp scheme selects datagram forwarding.
	udpTargetJSON := `{
		"mode": "client",
		"target": "udp://10.8.0.1:51820",
		"domain": "test.example.com"
	}`
	udpPath := filepath.Join(tempDir, "udp.json")
	if err := os.WriteFile(udpPath, []byte(udpTargetJSON), 0644); err != nil {
		t.Fatalf("write udp.json failed: %v", err)
	}
	uCfg, err := loadConfigFile(udpPath)
	if err != nil {
		t.Fatalf("load udp config failed: %v", err)
	}
	if uCfg.Target != "udp://10.8.0.1:51820" {
		t.Fatalf("target declaration not parsed: %+v", uCfg)
	}

	// 5. Server allow_targets list parsing (comma-separated env style comes via
	// applyEnvOverrides; JSON gives the array form).
	aclJSON := `{
		"mode": "server",
		"target": "tcp://127.0.0.1:22",
		"allow_targets": ["tcp://127.0.0.1:*", "udp://10.8.0.*:51820"]
	}`
	aclPath := filepath.Join(tempDir, "acl.json")
	if err := os.WriteFile(aclPath, []byte(aclJSON), 0644); err != nil {
		t.Fatalf("write acl.json failed: %v", err)
	}
	aCfg, err := loadConfigFile(aclPath)
	if err != nil {
		t.Fatalf("load acl config failed: %v", err)
	}
	if len(aCfg.AllowTargets) != 2 || aCfg.AllowTargets[0] != "tcp://127.0.0.1:*" || aCfg.AllowTargets[1] != "udp://10.8.0.*:51820" {
		t.Fatalf("allow_targets mismatch: %+v", aCfg.AllowTargets)
	}
}
