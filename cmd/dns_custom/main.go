// Command dns_custom is the CLI for the dnstunnel library: it loads the JSON
// configuration, injects logging and runs the tunnel as a standalone server or
// client process.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	dnstunnel "github.com/NNdroid/dns_custom"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

var zlog *zap.SugaredLogger = zap.NewNop().Sugar()

// udpClientPeerIdle is how long a UDP peer's tunnel session stays open without
// traffic before the client tears it down.
const udpClientPeerIdle = 5 * time.Minute

type Config struct {
	Mode         string   `json:"mode"`          // "server" or "client"
	Listen       string   `json:"listen"`        // Server listen address (e.g. ":53") or client listen address (e.g. "127.0.0.1:1080")
	Target       string   `json:"target"`        // Server default target; client: optional backend declaration ("tcp://host:port" / "udp://host:port"), validated by the server's allow list
	Domain       string   `json:"domain"`        // Authoritative tunnel domain (e.g. "tunnel.example.com")
	PrivKey      string   `json:"privkey"`       // Server static private key (Hex / Base64)
	PubKey       string   `json:"pubkey"`        // Client server public key (Hex / Base64)
	AllowTargets []string `json:"allow_targets"` // Server only: patterns granting client-declared targets (e.g. "tcp://127.0.0.1:*"); empty = default target only
	MaxSessions  int      `json:"max_sessions"`  // Server only: concurrent session cap (0 = unlimited)
	EDNS0        bool     `json:"edns0"`         // Announce 1232-byte UDP answers via EDNS0 (set on BOTH ends or the tunnel stalls)
	Servers      []string `json:"-"`             // Parsed upstream DNS servers
	RecordType   string   `json:"record_type"`   // DNS record type: txt, null, cname, a, aaaa, mx, srv, ns
	LogLevel     string   `json:"log_level"`     // debug, info, warn, error
}

func (c *Config) UnmarshalJSON(data []byte) error {
	type Alias Config
	aux := struct {
		*Alias
		RawServers interface{} `json:"servers"`
		RawType    string      `json:"type"`
	}{
		Alias: (*Alias)(c),
	}
	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}

	if aux.RawType != "" && c.RecordType == "" {
		c.RecordType = aux.RawType
	}

	if aux.RawServers != nil {
		switch v := aux.RawServers.(type) {
		case string:
			for _, s := range strings.Split(v, ",") {
				trimmed := strings.TrimSpace(s)
				if trimmed != "" {
					c.Servers = append(c.Servers, trimmed)
				}
			}
		case []interface{}:
			for _, item := range v {
				if s, ok := item.(string); ok {
					trimmed := strings.TrimSpace(s)
					if trimmed != "" {
						c.Servers = append(c.Servers, trimmed)
					}
				}
			}
		}
	}
	return nil
}

func applyEnvOverrides(cfg *Config) {
	getEnv := func(keys ...string) string {
		for _, k := range keys {
			if v := os.Getenv(k); v != "" {
				return strings.TrimSpace(v)
			}
		}
		return ""
	}

	if v := getEnv("DNSCUSTOM_MODE", "MODE"); v != "" {
		cfg.Mode = v
	}
	if v := getEnv("DNSCUSTOM_LISTEN", "LISTEN", "PORT"); v != "" {
		if !strings.Contains(v, ":") && len(v) < 6 {
			cfg.Listen = ":" + v
		} else {
			cfg.Listen = v
		}
	}
	if v := getEnv("DNSCUSTOM_TARGET", "TARGET"); v != "" {
		cfg.Target = v
	}
	if v := getEnv("DNSCUSTOM_DOMAIN", "DOMAIN"); v != "" {
		cfg.Domain = v
	}
	if v := getEnv("DNSCUSTOM_PRIVKEY", "PRIVKEY"); v != "" {
		cfg.PrivKey = v
	}
	if v := getEnv("DNSCUSTOM_PUBKEY", "PUBKEY"); v != "" {
		cfg.PubKey = v
	}
	if v := getEnv("DNSCUSTOM_SERVERS", "SERVERS"); v != "" {
		cfg.Servers = nil
		for _, s := range strings.Split(v, ",") {
			if trimmed := strings.TrimSpace(s); trimmed != "" {
				cfg.Servers = append(cfg.Servers, trimmed)
			}
		}
	}
	if v := getEnv("DNSCUSTOM_RECORD_TYPE", "RECORD_TYPE", "TYPE"); v != "" {
		cfg.RecordType = v
	}
	if v := getEnv("DNSCUSTOM_ALLOW_TARGETS", "ALLOW_TARGETS"); v != "" {
		cfg.AllowTargets = nil
		for _, s := range strings.Split(v, ",") {
			if trimmed := strings.TrimSpace(s); trimmed != "" {
				cfg.AllowTargets = append(cfg.AllowTargets, trimmed)
			}
		}
	}
	if v := getEnv("DNSCUSTOM_MAX_SESSIONS", "MAX_SESSIONS"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			cfg.MaxSessions = n
		}
	}
	if v := getEnv("DNSCUSTOM_EDNS0", "EDNS0"); v != "" {
		switch strings.ToLower(v) {
		case "1", "true", "yes", "y", "on":
			cfg.EDNS0 = true
		}
	}
	if v := getEnv("DNSCUSTOM_LOG_LEVEL", "LOG_LEVEL", "LOGLEVEL"); v != "" {
		cfg.LogLevel = v
	}
}

func initLogger(levelStr string) {
	var level zapcore.Level
	switch strings.ToLower(levelStr) {
	case "debug":
		level = zapcore.DebugLevel
	case "info":
		level = zapcore.InfoLevel
	case "warn":
		level = zapcore.WarnLevel
	case "error":
		level = zapcore.ErrorLevel
	default:
		level = zapcore.InfoLevel
	}

	encoderConfig := zap.NewProductionEncoderConfig()
	encoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder
	encoderConfig.EncodeLevel = zapcore.CapitalColorLevelEncoder

	core := zapcore.NewCore(
		zapcore.NewConsoleEncoder(encoderConfig),
		zapcore.AddSync(os.Stdout),
		level,
	)
	zlog = zap.New(core).Sugar()
}

func loadConfigFile(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}
	applyEnvOverrides(&cfg)
	return &cfg, nil
}

// loadRequiredConfig loads a configuration file that MUST be supplied via -c.
// Configuration files are never auto-discovered from the working directory, so the
// process can only ever run with the configuration the operator explicitly named.
func loadRequiredConfig(fs *flag.FlagSet, subcommand, path string) *Config {
	if path == "" {
		fmt.Fprintf(os.Stderr, "Error: %s requires a configuration file: dns_custom %s -c <config.json>\n", subcommand, subcommand)
		fs.Usage()
		os.Exit(1)
	}
	cfg, err := loadConfigFile(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load config file %s: %v\n", path, err)
		os.Exit(1)
	}
	return cfg
}

func main() {
	// The configuration file is introduced ONLY via -c. There is deliberately no
	// fallback that scans the working directory: silently picking up a stray
	// config.json / config.server.json / config.client.json made it impossible to
	// tell which configuration the process actually loaded.
	if len(os.Args) > 1 && (os.Args[1] == "-c" || strings.HasPrefix(os.Args[1], "-c=")) {
		confPath := ""
		if strings.Contains(os.Args[1], "=") {
			confPath = strings.SplitN(os.Args[1], "=", 2)[1]
		} else if len(os.Args) > 2 {
			confPath = os.Args[2]
		}
		if confPath == "" {
			fmt.Fprintln(os.Stderr, "Error: -c requires a configuration file path (e.g. -c /etc/dns_custom/config.json)")
			os.Exit(1)
		}
		runFromConfig(confPath)
		return
	}

	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		zlog.Info("Shutting down dns_custom gracefully with connection draining...")
		cancel()
	}()

	switch os.Args[1] {
	case "server":
		fs := flag.NewFlagSet("server", flag.ExitOnError)
		cfgPath := fs.String("c", "", "Path to configuration file (required)")
		_ = fs.Parse(os.Args[2:])

		fileCfg := loadRequiredConfig(fs, "server", *cfgPath)
		if fileCfg.Domain == "" {
			fmt.Fprintln(os.Stderr, "Error: domain is required (set via the configuration file's \"domain\" field)")
			fs.Usage()
			os.Exit(1)
		}

		runServer(ctx, fileCfg)

	case "client":
		fs := flag.NewFlagSet("client", flag.ExitOnError)
		cfgPath := fs.String("c", "", "Path to configuration file (required)")
		_ = fs.Parse(os.Args[2:])

		fileCfg := loadRequiredConfig(fs, "client", *cfgPath)
		if fileCfg.Domain == "" {
			fmt.Fprintln(os.Stderr, "Error: domain is required (set via the configuration file's \"domain\" field)")
			fs.Usage()
			os.Exit(1)
		}

		runClient(ctx, fileCfg)

	case "gen-keys":
		kp, err := dnstunnel.GenerateNoiseKeyPair()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to generate keypair: %v\n", err)
			os.Exit(1)
		}
		privHex, privB64 := dnstunnel.FormatNoiseKey(kp.PrivateKey)
		pubHex, pubB64 := dnstunnel.FormatNoiseKey(kp.PublicKey)
		fmt.Println("=== 🔑 Noise Curve25519 Keypair ===")
		fmt.Printf("Server Private Key (privkey):\n  Hex:    %s\n  Base64: %s\n\n", privHex, privB64)
		fmt.Printf("Client Public Key (pubkey):\n  Hex:    %s\n  Base64: %s\n", pubHex, pubB64)

	case "gen-uri":
		runGenURI(os.Args[2:])

	case "gen-systemd":
		runGenSystemd(os.Args[2:])

	case "version", "-v", "--version":
		fmt.Printf("dns_custom version %s\n", dnstunnel.Version)

	case "help", "-h", "--help":
		printUsage()

	default:
		fmt.Printf("Unknown subcommand: %s\n", os.Args[1])
		printUsage()
		os.Exit(1)
	}
}

func runGenURI(args []string) {
	fs := flag.NewFlagSet("gen-uri", flag.ExitOnError)
	cfgPath := fs.String("c", "", "Path to configuration file")
	domain := fs.String("domain", "", "Authoritative tunnel domain")
	pubKey := fs.String("pubkey", "", "Server Noise public key")
	servers := fs.String("servers", "", "Upstream DNS servers (comma-separated)")
	recordType := fs.String("type", "", "Record type")
	remark := fs.String("name", "", "Node remark name")
	pin := fs.String("pin", "", "Share PIN (6 digits). Empty = auto-generate a random PIN")
	_ = fs.Parse(args)

	// Values from the config file seed the defaults; an explicit command-line flag
	// always wins. A -c file that cannot be read or parsed is a hard error:
	// silently ignoring a config the operator explicitly named would quietly build
	// the URI from built-in defaults instead of the intended settings.
	if *cfgPath != "" {
		fileCfg, err := loadConfigFile(*cfgPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to load config file %s: %v\n", *cfgPath, err)
			os.Exit(1)
		}
		if *domain == "" {
			*domain = fileCfg.Domain
		}
		if *pubKey == "" {
			*pubKey = fileCfg.PubKey
		}
		if *servers == "" && len(fileCfg.Servers) > 0 {
			*servers = strings.Join(fileCfg.Servers, ",")
		}
		if *recordType == "" {
			*recordType = fileCfg.RecordType
		}
	}

	// Built-in fallbacks for fields neither the config file nor a flag provided.
	if *domain == "" {
		fmt.Fprintln(os.Stderr, "Error: -domain parameter or config file is required")
		os.Exit(1)
	}
	if *servers == "" {
		*servers = "8.8.8.8:53,1.1.1.1:53"
	}
	if *recordType == "" {
		*recordType = "txt"
	}
	if *remark == "" {
		*remark = "DNS Custom Node"
	}

	uri := GenerateDNSCustomURI(*domain, *pubKey, *servers, *recordType, *remark, *pin)
	fmt.Printf("=== 📱 dns_custom Sharing URI (encrypted stun://) ===\n\n%s\n", uri)
	PrintTerminalQR(uri)
}

func buildServerConfig(cfg *Config) dnstunnel.ServerConfig {
	sc := dnstunnel.ServerConfig{
		ListenAddr:   cfg.Listen,
		TargetAddr:   cfg.Target,
		Domain:       cfg.Domain,
		PrivateKey:   cfg.PrivKey,
		AllowTargets: cfg.AllowTargets,
		MaxSessions:  cfg.MaxSessions,
		EDNS0:        cfg.EDNS0,
		Logger:       zlog,
	}
	if sc.ListenAddr == "" {
		sc.ListenAddr = ":53"
	}
	if sc.TargetAddr == "" {
		sc.TargetAddr = "tcp://127.0.0.1:22"
	}
	return sc
}

func buildClientConfig(cfg *Config) dnstunnel.ClientConfig {
	cc := dnstunnel.ClientConfig{
		Domain:     cfg.Domain,
		Servers:    cfg.Servers,
		RecordType: cfg.RecordType,
		PublicKey:  cfg.PubKey,
		Target:     cfg.Target,
		EDNS0:      cfg.EDNS0,
		Logger:     zlog,
	}
	if cc.RecordType == "" {
		cc.RecordType = "txt"
	}
	if len(cc.Servers) == 0 {
		cc.Servers = []string{"8.8.8.8:53", "1.1.1.1:53"}
	}
	return cc
}

func runFromConfig(path string) {
	cfg, err := loadConfigFile(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to read config file %s: %v\n", path, err)
		os.Exit(1)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		zlog.Info("Shutting down dns_custom gracefully...")
		cancel()
	}()

	// runServer / runClient initialize the logger from cfg.LogLevel.
	//
	// Require an explicit mode. Falling back to "server" on a missing or misspelled
	// mode would silently start an authoritative DNS server from a client config,
	// which is both confusing and, on port 53, potentially disruptive.
	switch strings.ToLower(strings.TrimSpace(cfg.Mode)) {
	case "client":
		runClient(ctx, cfg)
	case "server":
		runServer(ctx, cfg)
	default:
		fmt.Fprintf(os.Stderr, "Error: config file %s must set \"mode\" to \"server\" or \"client\" (got %q)\n", path, cfg.Mode)
		os.Exit(1)
	}
}

func runServer(ctx context.Context, cfg *Config) {
	initLogger(cfg.LogLevel)
	defer func() { _ = zlog.Sync() }()

	srv, err := dnstunnel.NewServer(buildServerConfig(cfg))
	if err != nil {
		zlog.Fatalf("Failed to create server: %v", err)
	}
	if err := srv.Run(ctx); err != nil {
		zlog.Fatalf("Server exited with error: %v", err)
	}
}

func runClient(ctx context.Context, cfg *Config) {
	initLogger(cfg.LogLevel)
	defer func() { _ = zlog.Sync() }()

	cc := buildClientConfig(cfg)
	cli, err := dnstunnel.NewClient(cc)
	if err != nil {
		zlog.Fatalf("Failed to create client: %v", err)
	}

	listen := cfg.Listen
	if listen == "" {
		listen = "127.0.0.1:1080"
	}

	// The local listen transport follows the backend: a declared udp:// target
	// means the client binds UDP and forwards datagrams, everything else binds
	// TCP. With no declared target, ask the server what its default target is.
	useUDP := false
	if cfg.Target != "" {
		if strings.HasPrefix(cfg.Target, "udp://") {
			useUDP = true
		} else if strings.Contains(cfg.Target, "://") && !strings.HasPrefix(cfg.Target, "tcp://") {
			zlog.Fatalf("Invalid target %q: only tcp:// and udp:// schemes are supported", cfg.Target)
		}
	} else {
		transport, err := cli.DefaultTarget(ctx)
		if err != nil {
			zlog.Warnf("Could not query the server default target (%v); assuming TCP", err)
		} else if transport != "" {
			useUDP = transport == "udp"
			zlog.Infof("Server default target transport: %s", transport)
		}
	}

	zlog.Infof("🚀 Starting dns_custom client v%s", dnstunnel.Version)
	zlog.Infof("🌐 Upstream DNS Servers: %v (Domain: %s, Type: %s)", cc.Servers, cfg.Domain, cc.RecordType)
	if useUDP {
		zlog.Infof("🎧 Listening locally on UDP %s (datagram forwarding)", listen)
		runUDPForwardClient(ctx, cli, listen)
		return
	}
	zlog.Infof("🎧 Listening locally on TCP %s", listen)
	runTCPForwardClient(ctx, cli, listen)
}

// runTCPForwardClient accepts local TCP connections; each one gets its own tunnel
// session and is piped to the server's backend byte stream.
func runTCPForwardClient(ctx context.Context, cli *dnstunnel.Client, listen string) {
	ln, err := net.Listen("tcp", listen)
	if err != nil {
		zlog.Fatalf("Failed to listen on %s: %v", listen, err)
	}
	defer ln.Close()

	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()

	for {
		c, err := ln.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return
			default:
				zlog.Errorf("Accept failed: %v", err)
				continue
			}
		}

		go func(conn net.Conn) {
			defer conn.Close()
			tunnel, err := cli.Dial(ctx)
			if err != nil {
				zlog.Errorf("Failed to establish DNS tunnel: %v", err)
				return
			}
			defer tunnel.Close()

			go func() {
				_, _ = io.Copy(tunnel, conn)
				_ = tunnel.Close()
			}()
			_, _ = io.Copy(conn, tunnel)
		}(c)
	}
}

// udpPeer is one remote peer of the local UDP listener together with its tunnel
// session. Each distinct peer address gets its own session, which the server
// maps to its own connected UDP socket at the backend.
type udpPeer struct {
	stream     net.PacketConn
	lastActive time.Time
}

// runUDPForwardClient listens on a local UDP socket and forwards datagrams through
// the tunnel: every datagram received from a peer is delivered as exactly one
// datagram at the server's backend and vice versa. Idle peers are reaped after
// udpClientPeerIdle so abandoned source ports do not keep sessions alive forever.
func runUDPForwardClient(ctx context.Context, cli *dnstunnel.Client, listen string) {
	pc, err := net.ListenPacket("udp", listen)
	if err != nil {
		zlog.Fatalf("Failed to listen on %s: %v", listen, err)
	}
	defer pc.Close()

	go func() {
		<-ctx.Done()
		_ = pc.Close()
	}()

	var mu sync.Mutex
	peers := make(map[string]*udpPeer)
	dropPeer := func(key string) {
		mu.Lock()
		delete(peers, key)
		mu.Unlock()
	}

	// Idle reaper: close peer sessions that have not seen traffic recently.
	go func() {
		ticker := time.NewTicker(time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				now := time.Now()
				var stale []*udpPeer
				mu.Lock()
				for key, p := range peers {
					if now.Sub(p.lastActive) > udpClientPeerIdle {
						stale = append(stale, p)
						delete(peers, key)
					}
				}
				mu.Unlock()
				for _, p := range stale {
					_ = p.stream.Close()
				}
			}
		}
	}()

	buf := make([]byte, 65535)
	for {
		n, raddr, err := pc.ReadFrom(buf)
		if err != nil {
			select {
			case <-ctx.Done():
				return
			default:
				zlog.Errorf("UDP read failed: %v", err)
				continue
			}
		}

		key := raddr.String()
		mu.Lock()
		p, ok := peers[key]
		if ok {
			p.lastActive = time.Now()
		}
		mu.Unlock()

		if !ok {
			stream, derr := cli.DialUDP(ctx)
			if derr != nil {
				zlog.Errorf("Failed to establish UDP tunnel for %s: %v", key, derr)
				continue
			}
			p = &udpPeer{stream: stream, lastActive: time.Now()}
			mu.Lock()
			peers[key] = p
			mu.Unlock()
			go pumpUDPPeer(pc, raddr, stream, key, dropPeer)
		}

		if _, err := p.stream.WriteTo(buf[:n], raddr); err != nil {
			zlog.Errorf("Forward to tunnel failed for %s: %v", key, err)
		}
	}
}

// pumpUDPPeer forwards datagrams from one peer's tunnel session back to the local
// peer and removes the peer when the session ends.
func pumpUDPPeer(pc net.PacketConn, raddr net.Addr, stream net.PacketConn, key string, dropPeer func(string)) {
	defer dropPeer(key)
	defer stream.Close()

	buf := make([]byte, 65535)
	for {
		n, _, err := stream.ReadFrom(buf)
		if err != nil {
			return
		}
		if _, err := pc.WriteTo(buf[:n], raddr); err != nil {
			return
		}
	}
}

func printUsage() {
	fmt.Println("Usage: dns_custom -c <config.json> | dns_custom <command> -c <config.json>")
	fmt.Println("\nConfiguration:")
	fmt.Println("  -c <file>    The ONLY way to load a configuration file. Config files are never")
	fmt.Println("               auto-discovered from the working directory. Required for the")
	fmt.Println("               top-level form and for the server/client subcommands; optional for")
	fmt.Println("               gen-uri (which also accepts explicit -domain/-pubkey/-servers).")
	fmt.Println("               DNSCUSTOM_* environment variables only override fields that are")
	fmt.Println("               already present in the file loaded via -c.")
	fmt.Println("\nCommands:")
	fmt.Println("  server       Start authoritative DNS tunnel server (forward to TCP/UDP target)")
	fmt.Println("  client       Start DNS tunnel client (open local port for forwarding; the")
	fmt.Println("               local transport follows the target: declare \"target\": \"udp://host:port\"")
	fmt.Println("               for datagram forwarding, or probe the server default)")
	fmt.Println("  gen-keys     Generate Curve25519 keypair for Noise encryption")
	fmt.Println("  gen-uri      Generate Stun client sharing URI link (encrypted stun://, PIN-protected) & QR Code")
	fmt.Println("  gen-systemd  Generate Linux systemd service configuration")
	fmt.Println("  version      Show version information")
	fmt.Println("  help         Show help message")
	fmt.Println("\nExamples:")
	fmt.Println("  dns_custom -c /etc/dns_custom/config.server.json")
	fmt.Println("  dns_custom server -c /etc/dns_custom/config.server.json")
	fmt.Println("  dns_custom client -c /etc/dns_custom/config.client.json")
	fmt.Println("  dns_custom gen-uri -c /etc/dns_custom/config.client.json")
}
