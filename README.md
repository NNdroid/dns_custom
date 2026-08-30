# dns_custom

High-Performance Authoritative DNS Tunnel Server & Client with Noise_NK Curve25519 AEAD Encryption.

## Features

- **Noise Protocol Encryption**: Optional `Noise_NK_25519_ChaChaPoly_BLAKE2s` cryptographic channel.
- **Dual Target Forwarding**: Supports both TCP (`tcp://host:port`) and UDP (`udp://host:port`) backend services.
- **8 DNS Record Types**: Supports `TXT`, `NULL`, `CNAME`, `A`, `AAAA`, `MX`, `SRV`, and `NS`.
- **Upstream DNS Transports**: Client supports standard UDP/TCP DNS, DNS-over-TLS (`tls://` / `dot://`), and DNS-over-HTTPS (`https://` / `doh://`).
- **Unified JSON & Env Configuration**: Configuration is loaded **only** via `-c <config.json>` — config files are never auto-discovered from the working directory, so the process always runs with the config you named. `DNSCUSTOM_*` environment variables may *override* fields present in the loaded file (handy for Docker), but cannot replace the file itself.
- **Stun Node Sharing (`gen-uri`)**: One-click sharing URI and terminal ASCII QR code generation for Android & TV.
- **Zero-Downtime Hot-Reload**: Dynamic `SIGHUP` config reloading.

---

## One-Key Management (Linux Server & Client)

### 1. Server Installation (Default)
```bash
curl -fsSL https://raw.githubusercontent.com/NNdroid/dns_custom/master/scripts/install.sh | sudo bash -s install server
```

### 2. Client Installation (Linux)
```bash
curl -fsSL https://raw.githubusercontent.com/NNdroid/dns_custom/master/scripts/install.sh | sudo bash -s install client
```

### 3. Upgrade / Uninstall
```bash
# One-key Upgrade (Keeps existing config.json)
curl -fsSL https://raw.githubusercontent.com/NNdroid/dns_custom/master/scripts/install.sh | sudo bash -s upgrade

# One-key Uninstall
curl -fsSL https://raw.githubusercontent.com/NNdroid/dns_custom/master/scripts/install.sh | sudo bash -s uninstall
```

### 4. Service Management
```bash
systemctl start dns_custom    # Start service
systemctl stop dns_custom     # Stop service
systemctl restart dns_custom  # Restart service
systemctl status dns_custom   # Check status
journalctl -u dns_custom -f   # View live logs
```

---

## Configuration Reference (`config.json`)

| Field | Type | Default | Description |
| :--- | :--- | :--- | :--- |
| `mode` | `string` | `"server"` | Operational mode: `"server"` (authoritative DNS server) or `"client"` (local listener). |
| `listen` | `string` | `":53"` | Listen address (`":53"` for server; `"127.0.0.1:1080"` for client). |
| `target` | `string` | `"tcp://127.0.0.1:22"` | Target backend service on server (`tcp://127.0.0.1:22` or `udp://127.0.0.1:51820`). |
| `domain` | `string` | `""` | Authoritative DNS tunnel domain (e.g. `tunnel.example.com`). |
| `privkey` | `string` | `""` | Server static private key for Noise encryption (Hex or Base64). Generate with `dns_custom gen-keys`. |
| `pubkey` | `string` | `""` | Server static public key for Noise encryption in client mode (Hex or Base64). |
| `servers` | `array|string` | `["8.8.8.8:53", "1.1.1.1:53"]` | Upstream DNS servers (JSON array or comma-separated; supports UDP, TCP, DoT, DoH). |
| `record_type` | `string` | `"txt"` | Tunnel query DNS record type: `txt`, `null`, `cname`, `a`, `aaaa`, `mx`, `srv`, `ns`. |
| `log_level` | `string` | `"info"` | Logging output level: `debug`, `info`, `warn`, `error`. |

---

## Quick Start

### 1. Generate Noise Keypair (Optional)
```bash
dns_custom gen-keys
```

### 2. Export Stun QR Code & Sharing Link
```bash
dns_custom gen-uri -c /etc/dns_custom/config.json
```
