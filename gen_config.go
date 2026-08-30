package main

import (
	"flag"
	"fmt"
	"os"
)

func runGenSystemd(args []string) {
	fs := flag.NewFlagSet("gen-systemd", flag.ExitOnError)
	listen := fs.String("listen", ":53", "Listen address")
	target := fs.String("target", "tcp://127.0.0.1:22", "Target address (tcp://127.0.0.1:22 or udp://127.0.0.1:51820)")
	domain := fs.String("domain", "tunnel.example.com", "Authoritative domain")
	privKey := fs.String("privkey", "", "Noise private key")
	_ = fs.Parse(args)

	execPath, err := os.Executable()
	if err != nil {
		execPath = "/usr/local/bin/dns_custom"
	}

	// The `server` subcommand only accepts `-c` (per-parameter flags were removed),
	// so the unit always launches from an explicit config file.
	execLine := fmt.Sprintf("%s -c /etc/dns_custom/config.json", execPath)

	configSample := fmt.Sprintf(`{
  "mode": "server",
  "listen": %q,
  "target": %q,
  "domain": %q,
  "privkey": %q,
  "log_level": "info"
}`, *listen, *target, *domain, *privKey)

	content := fmt.Sprintf(`[Unit]
Description=dns_custom Authoritative DNS Tunnel Server
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/etc/dns_custom
ExecStart=%s
Restart=always
RestartSec=5s
LimitNOFILE=65535
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_BIND_SERVICE

[Install]
WantedBy=multi-user.target
`, execLine)

	fmt.Println(content)
	fmt.Println("# Place the following as /etc/dns_custom/config.json :")
	fmt.Println(configSample)
}
