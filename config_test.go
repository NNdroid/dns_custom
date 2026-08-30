package main

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
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
		t.Fatalf("parsed client string servers mismatch: %+v", cStrCfg)
	}
}

func TestDNSCustom_LiveE2E_FromJSONConfig(t *testing.T) {
	tempDir := t.TempDir()

	// 1. Echo Backend Target
	backendLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen echo backend failed: %v", err)
	}
	defer backendLn.Close()
	backendAddr := backendLn.Addr().String()

	go func() {
		for {
			conn, err := backendLn.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_, _ = io.Copy(c, c)
			}(conn)
		}
	}()

	// 2. Generate Noise Keypair
	kp, err := GenerateNoiseKeyPair()
	if err != nil {
		t.Fatalf("generate keypair failed: %v", err)
	}
	privHex, _ := FormatNoiseKey(kp.PrivateKey)
	pubHex, _ := FormatNoiseKey(kp.PublicKey)

	// 3. Find free UDP port for DNS Server
	dummyUDP, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen packet failed: %v", err)
	}
	dnsPort := dummyUDP.LocalAddr().(*net.UDPAddr).Port
	dummyUDP.Close()
	dnsAddr := fmt.Sprintf("127.0.0.1:%d", dnsPort)

	// 4. Create Server JSON Config
	domain := "jsoncfg.test.local"
	serverConf := fmt.Sprintf(`{
		"mode": "server",
		"listen": "%s",
		"target": "tcp://%s",
		"domain": "%s",
		"privkey": "%s",
		"log_level": "debug"
	}`, dnsAddr, backendAddr, domain, privHex)
	serverConfPath := filepath.Join(tempDir, "server_e2e.json")
	if err := os.WriteFile(serverConfPath, []byte(serverConf), 0644); err != nil {
		t.Fatalf("write server_e2e.json failed: %v", err)
	}

	// 5. Start Server from parsed Config
	sCfg, err := loadConfigFile(serverConfPath)
	if err != nil {
		t.Fatalf("load server_e2e.json failed: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go runServer(ctx, ServerConfig{
		ListenAddr: sCfg.Listen,
		TargetAddr: sCfg.Target,
		Domain:     sCfg.Domain,
		PrivateKey: sCfg.PrivKey,
		LogLevel:   sCfg.LogLevel,
	})
	time.Sleep(150 * time.Millisecond)

	// 6. Create Client JSON Config
	clientConf := fmt.Sprintf(`{
		"mode": "client",
		"domain": "%s",
		"pubkey": "%s",
		"servers": ["%s"],
		"record_type": "txt",
		"log_level": "debug"
	}`, domain, pubHex, dnsAddr)
	clientConfPath := filepath.Join(tempDir, "client_e2e.json")
	if err := os.WriteFile(clientConfPath, []byte(clientConf), 0644); err != nil {
		t.Fatalf("write client_e2e.json failed: %v", err)
	}

	cCfg, err := loadConfigFile(clientConfPath)
	if err != nil {
		t.Fatalf("load client_e2e.json failed: %v", err)
	}

	// 7. Establish Client Tunnel
	tunnel, err := NewDNSClientTunnel(ctx, cCfg.Servers, cCfg.Domain, cCfg.RecordType, cCfg.PubKey)
	if err != nil {
		t.Fatalf("NewDNSClientTunnel failed: %v", err)
	}
	defer tunnel.Close()

	// 8. Test Data Echo RoundTrip
	testPayload := []byte("Hello DNS Custom Tunnel via JSON Config!")
	if _, err := tunnel.Write(testPayload); err != nil {
		t.Fatalf("tunnel write failed: %v", err)
	}

	recvBuf := make([]byte, len(testPayload))
	if _, err := io.ReadFull(tunnel, recvBuf); err != nil {
		t.Fatalf("tunnel read failed: %v", err)
	}

	if string(recvBuf) != string(testPayload) {
		t.Fatalf("roundtrip payload mismatch: got %q, want %q", string(recvBuf), string(testPayload))
	}

	t.Logf("✅ Live E2E DNS Tunnel via JSON Config PASSED!")
}
