package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

var Version = "1.2.0"
var zlog *zap.SugaredLogger = zap.NewNop().Sugar()

type Config struct {
	Mode       string   `json:"mode"`        // "server" or "client"
	Listen     string   `json:"listen"`      // Server listen address (e.g. ":53") or client listen address (e.g. "127.0.0.1:1080")
	Target     string   `json:"target"`      // Server target address (e.g. "tcp://127.0.0.1:22" or "udp://127.0.0.1:51820")
	Domain     string   `json:"domain"`      // Authoritative tunnel domain (e.g. "tunnel.example.com")
	PrivKey    string   `json:"privkey"`     // Server static private key (Hex / Base64)
	PubKey     string   `json:"pubkey"`      // Client server public key (Hex / Base64)
	Servers    []string `json:"-"`           // Parsed upstream DNS servers
	RecordType string   `json:"record_type"` // DNS record type: txt, null, cname, a, aaaa, mx, srv, ns
	LogLevel   string   `json:"log_level"`   // debug, info, warn, error
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

		runServer(ctx, buildServerConfig(fileCfg))

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

		runClient(ctx, buildClientConfig(fileCfg))

	case "gen-keys":
		kp, err := GenerateNoiseKeyPair()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to generate keypair: %v\n", err)
			os.Exit(1)
		}
		privHex, privB64 := FormatNoiseKey(kp.PrivateKey)
		pubHex, pubB64 := FormatNoiseKey(kp.PublicKey)
		fmt.Println("=== 🔑 Noise Curve25519 Keypair ===")
		fmt.Printf("Server Private Key (privkey):\n  Hex:    %s\n  Base64: %s\n\n", privHex, privB64)
		fmt.Printf("Client Public Key (pubkey):\n  Hex:    %s\n  Base64: %s\n", pubHex, pubB64)

	case "gen-uri":
		runGenURI(os.Args[2:])

	case "gen-systemd":
		runGenSystemd(os.Args[2:])

	case "version", "-v", "--version":
		fmt.Printf("dns_custom version %s\n", Version)

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

func buildServerConfig(cfg *Config) ServerConfig {
	sc := ServerConfig{
		ListenAddr: cfg.Listen,
		TargetAddr: cfg.Target,
		Domain:     cfg.Domain,
		PrivateKey: cfg.PrivKey,
		LogLevel:   cfg.LogLevel,
	}
	if sc.ListenAddr == "" {
		sc.ListenAddr = ":53"
	}
	if sc.TargetAddr == "" {
		sc.TargetAddr = "tcp://127.0.0.1:22"
	}
	return sc
}

func buildClientConfig(cfg *Config) ClientConfig {
	cc := ClientConfig{
		ListenAddr: cfg.Listen,
		Domain:     cfg.Domain,
		Servers:    cfg.Servers,
		RecordType: cfg.RecordType,
		PublicKey:  cfg.PubKey,
		LogLevel:   cfg.LogLevel,
	}
	if cc.ListenAddr == "" {
		cc.ListenAddr = "127.0.0.1:1080"
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

	// Require an explicit mode. Falling back to "server" on a missing or misspelled
	// mode would silently start an authoritative DNS server from a client config,
	// which is both confusing and, on port 53, potentially disruptive.
	switch strings.ToLower(strings.TrimSpace(cfg.Mode)) {
	case "client":
		runClient(ctx, buildClientConfig(cfg))
	case "server":
		runServer(ctx, buildServerConfig(cfg))
	default:
		fmt.Fprintf(os.Stderr, "Error: config file %s must set \"mode\" to \"server\" or \"client\" (got %q)\n", path, cfg.Mode)
		os.Exit(1)
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
	fmt.Println("  client       Start DNS tunnel client (open local port for forwarding)")
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
