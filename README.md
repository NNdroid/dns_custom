# dns_custom

High-Performance Authoritative DNS Tunnel Server & Client with Noise_NK Curve25519 AEAD Encryption.

## Features

- **Noise Protocol Encryption**: Optional `Noise_NK_25519_ChaChaPoly_BLAKE2s` cryptographic channel.
- **Dual Target Forwarding**: Supports both TCP (`tcp://host:port`) and UDP (`udp://host:port`) backend services.
- **UDP Datagram Mode**: Client can tunnel UDP datagrams (`DialUDP` / `"target": "udp://..."`) with boundaries preserved via length framing — e.g. for WireGuard, QUIC or game servers. The local transport follows the target automatically; the server refuses transport mismatches.
- **Client-Declared Targets with ACL**: Clients can declare the backend they want per session; the server validates it against an `allow_targets` pattern list (`"tcp://127.0.0.1:*"`, `"udp://10.8.0.*:51820"`) and always answers with the transport that applies. One server can safely serve many different backends.
- **Embeddable Go Library**: The root package `dnstunnel` exposes `Server.Run(ctx)` / `Client.Dial(ctx) (net.Conn)` / `Client.DialUDP(ctx) (net.PacketConn)`, so external programs can borrow the tunnel through standard connection interfaces (see [Using as a Go Library](#using-as-a-go-library)).
- **8 DNS Record Types**: Supports `TXT`, `NULL`, `CNAME`, `A`, `AAAA`, `MX`, `SRV`, and `NS`.
- **Optional EDNS0**: With `"edns0": true` on both ends, answers announce a 1232-byte UDP budget instead of 512 — much larger downstream chunks and near-doubled throughput.
- **Upstream DNS Transports**: Client supports standard UDP/TCP DNS, DNS-over-TLS (`tls://` / `dot://`), and DNS-over-HTTPS (`https://` / `doh://`).
- **Unified JSON & Env Configuration**: Configuration is loaded **only** via `-c <config.json>` — config files are never auto-discovered from the working directory, so the process always runs with the config you named. `DNSCUSTOM_*` environment variables may *override* fields present in the loaded file (handy for Docker), but cannot replace the file itself.
- **Stun Node Sharing (`gen-uri`)**: One-click sharing URI and terminal ASCII QR code generation for Android & TV.

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

### 3. Pin a Release Version (Optional)
Leave `APP_VERSION` unset to install the latest release. To install a specific
raw-binary release, supply its tag (`v1.0.yyyyMMdd-<7-character-git-hash>`):
```bash
curl -fsSL https://raw.githubusercontent.com/NNdroid/dns_custom/master/scripts/install.sh | sudo env APP_VERSION=v1.0.20260904-1a2b3c4 bash -s install server
```

### 4. Upgrade / Uninstall
```bash
# One-key Upgrade (Keeps existing config.json)
curl -fsSL https://raw.githubusercontent.com/NNdroid/dns_custom/master/scripts/install.sh | sudo bash -s upgrade

# One-key Uninstall
curl -fsSL https://raw.githubusercontent.com/NNdroid/dns_custom/master/scripts/install.sh | sudo bash -s uninstall
```

### 5. Service Management
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
| `listen` | `string` | server `":53"`, client `"127.0.0.1:1080"` | Server: authoritative DNS listen address. Client: local address to bind — its transport (TCP or UDP) follows the backend automatically (declared `target` or server default). |
| `target` | `string` | `"tcp://127.0.0.1:22"` | Server: default backend (`tcp://host:port` or `udp://host:port`). Client: optional backend declaration — must pass the server's `allow_targets` list, or the session is rejected. |
| `allow_targets` | `array` | `[]` | Server only: patterns granting client-declared targets, e.g. `"tcp://127.0.0.1:*"`, `"udp://10.8.0.*:51820"`; scheme/host/port may each be `*`, host wildcards never cross a dot. Empty = default target only; `"*"` allows everything (dangerous). |
| `max_sessions` | `int` | `0` | Server only: concurrent session cap (each session holds up to ~600KB of buffers). `0` = unlimited. |
| `edns0` | `bool` | `false` | Announce 1232-byte UDP answers via EDNS0 instead of the 512-byte limit — much larger downstream chunks. Set on **both** ends or the tunnel stalls. |
| `domain` | `string` | `""` | Authoritative DNS tunnel domain (e.g. `tunnel.example.com`). |
| `privkey` | `string` | `""` | Server static private key for Noise encryption (Hex or Base64). Generate with `dns_custom gen-keys`. |
| `pubkey` | `string` | `""` | Server static public key for Noise encryption in client mode (Hex or Base64). |
| `servers` | `array|string` | `["8.8.8.8:53", "1.1.1.1:53"]` | Upstream DNS servers (JSON array or comma-separated; supports UDP, TCP, DoT, DoH). |
| `record_type` | `string` | `"txt"` | Tunnel query DNS record type: `txt`, `null`, `cname`, `a`, `aaaa`, `mx`, `srv`, `ns`. |
| `log_level` | `string` | `"info"` | Logging output level: `debug`, `info`, `warn`, `error`. |

---

## Deployment Examples

### SSH over the Tunnel (TCP)

Server forwards to a local sshd; the client exposes a local TCP port:

```json
// server config.json
{
  "mode": "server",
  "listen": ":53",
  "target": "tcp://127.0.0.1:22",
  "domain": "t.example.com",
  "privkey": "<server private key>"
}
```

```json
// client config.json
{
  "mode": "client",
  "listen": "127.0.0.1:1080",
  "domain": "t.example.com",
  "pubkey": "<server public key>",
  "servers": ["8.8.8.8:53", "1.1.1.1:53"],
  "record_type": "txt"
}
```

### WireGuard over the Tunnel (UDP Datagrams)

The client's local transport follows its target automatically: declaring a
`udp://` target binds a local **UDP** socket with boundary-preserving datagram
forwarding. Point the local WireGuard peer's endpoint at the client's
`listen` address:

```json
// server
{ "mode": "server", "target": "udp://127.0.0.1:51820", "...": "..." }

// client
{ "mode": "client", "listen": "127.0.0.1:51820", "target": "udp://127.0.0.1:51820", "...": "..." }
```

Omit the client `target` to use the server default — the client probes the
server at startup and binds TCP or UDP accordingly.

### Gateway Mode (Client-Declared Targets + ACL)

One server can serve several backends. Clients declare the backend they want;
the server honors only declarations that pass `allow_targets` and rejects the
rest with an explicit error:

```json
// server
{
  "mode": "server",
  "target": "tcp://127.0.0.1:22",
  "allow_targets": ["tcp://127.0.0.1:*", "udp://127.0.0.1:*"],
  "max_sessions": 256
}
```

```text
client A: "target": "tcp://127.0.0.1:22"    → local TCP listener
client B: "target": "udp://127.0.0.1:51820" → local UDP listener
```

An empty `allow_targets` (the default) refuses every declaration — only the
server default target is reachable. Patterns match literally against the
declared address; prefer IPs, since hostnames are never resolved during
matching.

## Environment Variables

`DNSCUSTOM_*` variables override fields present in the config file loaded via
`-c` (handy for Docker); short aliases exist for a few of them (`MODE`,
`LISTEN`, `PORT`, `TYPE`, `LOGLEVEL`):

| Variable | Overrides |
| :--- | :--- |
| `DNSCUSTOM_MODE` | `mode` |
| `DNSCUSTOM_LISTEN` | `listen` |
| `DNSCUSTOM_TARGET` | `target` |
| `DNSCUSTOM_DOMAIN` | `domain` |
| `DNSCUSTOM_PRIVKEY` | `privkey` |
| `DNSCUSTOM_PUBKEY` | `pubkey` |
| `DNSCUSTOM_SERVERS` | `servers` (comma-separated) |
| `DNSCUSTOM_RECORD_TYPE` | `record_type` |
| `DNSCUSTOM_ALLOW_TARGETS` | `allow_targets` (comma-separated) |
| `DNSCUSTOM_MAX_SESSIONS` | `max_sessions` |
| `DNSCUSTOM_EDNS0` | `edns0` (`1`/`true`/`yes`/`on`) |
| `DNSCUSTOM_LOG_LEVEL` | `log_level` |

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

---

## Using as a Go Library

The root package `dnstunnel` is a library; the CLI in `cmd/dns_custom` is just one consumer. External programs can borrow the tunnel for unified, encrypted access to backend services:

```go
import dnstunnel "github.com/NNdroid/dns_custom"

// Client: every Dial opens an independent tunnel session.
cli, err := dnstunnel.NewClient(dnstunnel.ClientConfig{
	Domain:     "tunnel.example.com",
	Servers:    []string{"8.8.8.8:53", "1.1.1.1:53"},
	RecordType: "txt",
	PublicKey:  serverPubKey, // optional Noise_NK key
})

conn, err := cli.Dial(ctx)     // stream access → net.Conn
pconn, err := cli.DialUDP(ctx) // datagram access → net.PacketConn

// Optionally declare which backend to reach; the server validates it against
// its allow_targets list. Without a declaration, ask the server what its
// default target transport is (e.g. to pick a local UDP or TCP bind):
cli2, _ := dnstunnel.NewClient(dnstunnel.ClientConfig{
	Domain:  "tunnel.example.com",
	Servers: []string{"8.8.8.8:53"},
	Target:  "udp://10.8.0.1:51820",
})
transport, _ := cli2.DefaultTarget(ctx) // "tcp" or "udp"

// Server: terminates sessions and forwards to the backend.
srv, err := dnstunnel.NewServer(dnstunnel.ServerConfig{
	ListenAddr:   ":53",
	TargetAddr:   "tcp://127.0.0.1:22", // or "udp://127.0.0.1:51820"
	Domain:       "tunnel.example.com",
	PrivateKey:   serverPrivKey,
	AllowTargets: []string{"tcp://127.0.0.1:*", "udp://127.0.0.1:*"},
})
err = srv.Run(ctx) // blocks; returns nil on clean ctx cancellation
```

`Dial` returns a `net.Conn` and `DialUDP` a `net.PacketConn`, so the tunnel plugs directly into `http.Transport.DialContext`, database drivers, SSH clients and anything else that consumes standard connection interfaces. Logging is injected via the config's `Logger` field (`*zap.SugaredLogger`; nil means a nop logger), so the library never touches global logger state or calls `os.Exit`.

Build the CLI from source with:

```bash
go build -o dns_custom ./cmd/dns_custom
```

## Development

```bash
go test ./...        # full test suite
go test -race ./...  # with race detector (needs CGO and a C toolchain)
```

CI (`.github/workflows/test.yml`) runs vet plus plain and race-enabled tests
on Linux, macOS and Windows for every push and pull request. Pushing a
`v1.0.yyyyMMdd-<short-sha>` tag triggers `.github/workflows/release.yml`,
which re-runs the tests and publishes raw binaries for 9 platforms.
