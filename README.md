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
- **Fast Lane over TCP**: Point the client's `servers` at a `tcp://` resolver (or any resolver forwarding over TCP) and the server serves ~8 KiB chunks — no datagram size limit applies. Measured ~2× over plain UDP on loopback.
- **Upstream DNS Transports**: Client supports standard UDP/TCP DNS, DNS-over-TLS (`tls://` / `dot://`), and DNS-over-HTTPS (`https://` / `doh://`).
- **Network-Change Recovery**: pooled DNS sockets are discarded after transport or DNS-response failures, polling survives resolver/interface outages, and an in-flight write retries with capped backoff until its context or write deadline expires. Authoritative `NXDOMAIN` is treated as an expired server session instead of a successful write.
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

To publish without calculating a tag, open GitHub **Actions → Release → Run
workflow**, select the branch and leave **publish_release** checked (the default).
After tests and builds pass, the workflow creates the Git-derived version tag
and publishes the binaries. Uncheck it for an artifact-only build. The run
summary shows the version and exact commit; manual runs also retain artifacts.

Leave `APP_VERSION` unset to install the latest release. To install a specific
raw-binary release, supply its tag (`v1.0.yyyyMMdd.<commit-count>-<7-character-git-hash>`):
```bash
curl -fsSL https://raw.githubusercontent.com/NNdroid/dns_custom/master/scripts/install.sh | sudo env APP_VERSION=v1.0.20260904.123-1a2b3c4 bash -s install server
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
| `edns0` | `bool` | `false` | Announce 1232-byte UDP answers via EDNS0 instead of the 512-byte limit — much larger downstream chunks. Set on **both** ends or the tunnel stalls. **Only takes effect on an authenticated session** (`pubkey`/Noise or `psk`): the server caps anonymous answers at the legacy 512-byte budget so an open deployment cannot be used as a big-pipe amplifier, so setting `edns0` without either buys bytes on every query for no gain and logs a warning. |
|  |  |  | *Throughput ladder (same server, loopback): plain UDP ≈ 1.6 MB/s, EDNS0 ≈ 2.8 MB/s, `tcp://` upstream ≈ 2.9 MB/s.* |
| `exchange_timeout` | `duration` | `4s` | Client only: how long one DNS exchange waits for its reply. A lost query burns exactly that much wall clock before the same chunk is retransmitted, so under loss this dominates throughput more than the query rate does. The wait is also clamped down to eight times the session's best observed round trip, floored at 500 ms, so a 200 ms path never spends 20× its RTT discovering one dropped query; a session with no measurement yet waits the floor, not the ceiling. Lower it to fail over a dead upstream faster, raise it for a very janky path. |
| `poll_interval` | `duration` | `50ms` | Client only: how often a downstream poll is sent when there is nothing queued. Downstream bytes arrive only as answers to the client's own polls, so on a clean path this interval — not bandwidth, not chunk size — sets the read rate. Lower it to trade idle DNS queries for lower read latency. |
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
| `DNSCUSTOM_EXCHANGE_TIMEOUT` | `exchange_timeout` (Go duration, e.g. `1s`, `800ms`) |
| `DNSCUSTOM_POLL_INTERVAL` | `poll_interval` (Go duration, e.g. `25ms`) |

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

// Both ends tune themselves to the path by default: the DNS exchange wait
// clamps down to the measured round trip, and the poll cadence sets the clean
// path's read rate. Override either in ClientConfig when a specific link needs
// it:
cli, _ = dnstunnel.NewClient(dnstunnel.ClientConfig{
	Domain:     "tunnel.example.com",
	Servers:    []string{"8.8.8.8:53"},
	RecordType: "txt",
	ExchangeTimeout: 1 * time.Second, // fail over a dead upstream sooner
	PollInterval:    20 * time.Millisecond, // lower read latency, more DNS traffic
})

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

Network recovery preserves the current session while the server still knows it:
temporary resolver, interface, UDP/TCP, DoT, and DoH failures cause queries to
move onto fresh transports and retry. Set a write deadline when the application
needs a bounded outage window. If the authoritative endpoint returns `NXDOMAIN`,
the server-side session and backend stream are gone; the connection terminates
with `ErrServerSessionGone` because silently attaching the existing byte stream
to a new backend would corrupt TCP semantics. The CLI's UDP forwarding mode
removes that failed peer generation and creates a new tunnel on its next local
datagram.

**Per-session backends** (`DialTarget` / `DialUDPTarget`): one `Client` can reach different backends on different sessions — e.g. SSH over a `tcp://` session and WireGuard over a `udp://` session — without constructing a client per backend. Each declaration is validated by the server's `allow_targets` list:

```go
sshConn, err := cli.DialTarget(ctx, "tcp://127.0.0.1:22")     // stream to sshd
wgConn, err := cli.DialUDPTarget(ctx, "udp://10.8.0.1:51820") // datagrams to WireGuard
```

**Custom TLS for DoT/DoH upstreams** (`ClientConfig.TLSConfig`): pass a `*tls.Config` to control the TLS layer of `tls://`/`dot://` resolvers and `https://` DoH endpoints — self-signed CAs, SNI, `InsecureSkipVerify`:

```go
cli, err := dnstunnel.NewClient(dnstunnel.ClientConfig{
	Domain:    "tunnel.example.com",
	Servers:   []string{"dot://dns.internal:853"},
	TLSConfig: &tls.Config{RootCAs: internalCAPool}, // or InsecureSkipVerify for tests
})
```

**Typed event callbacks** (`EventHandler`): instead of (or besides) logs, the library drives your application logic with strongly-typed events. Handlers run on a dedicated goroutine with per-event panic recovery and can never block the data path — events are queued (bounded, oldest dropped when overwhelmed):

```go
// Client side: session lifecycle + security signals.
cli, _ := dnstunnel.NewClient(dnstunnel.ClientConfig{
	Domain: "tunnel.example.com",
	Servers: []string{"8.8.8.8:53"},
	EventHandler: func(ev dnstunnel.ClientEvent) {
		switch ev.Kind {
		case dnstunnel.ClientTunnelEstablished: // handshake + declaration done
		case dnstunnel.ClientReconnecting:      // ev.Attempt, ev.Err
		case dnstunnel.ClientTunnelDied:        // ev.Reason ("closed by caller", "write deadline exceeded", ...)
		case dnstunnel.ClientTargetDenied:      // ev.Target refused by the allow list
		}
	},
})
// Or install later: cli.SetEventHandler(handler)
// Context-style death signaling on each session:
//   tunnel.Done() <-chan struct{}  — closed when the session dies
//   tunnel.Err() error             — why (nil for a deliberate Close)

// Server side: session lifecycle + SIEM-ready security kinds.
srv, _ := dnstunnel.NewServer(dnstunnel.ServerConfig{
	// ...
	EventHandler: func(ev dnstunnel.ServerEvent) {
		// SessionCreated / SessionClosed / AuthRejected / ReplayDropped / TargetDenied
	},
})
```

**Client authentication & anti-abuse** (`psks` / `query_rate_per_source`): configure `psks` on the server and a matching `psk` on the client — every session's capability probe must carry a valid HMAC proof, and data for unauthenticated sessions is refused. Anonymous plaintext sessions are capped at the legacy 512-byte response budget (big responses require Noise or PSK). `query_rate_per_source` adds RRL-style per-IP token-bucket rate limiting; plaintext servers without PSK refuse target declarations entirely (hijack hardening).

**Threat model note — plaintext mode has no on-path protection.** Without Noise, session IDs, target declarations and tunnel data all ride plaintext DNS: anyone who observes the traffic (resolvers, middleboxes, on-path attackers) can read it and, by replaying the visible session ID and sequence numbers, inject chunks into or tear down an existing session. PSK raises the bar for *anonymous* abuse but does not encrypt anything. Any deployment carrying real secrets must enable Noise (`privkey`/`pubkey`) — encrypted sessions authenticate the server via its static key and make every chunk AEAD-verified.

Build the CLI from source with:

```bash
go build -o dns_custom ./cmd/dns_custom
```

## Development

```bash
go test ./...        # full test suite
go test -race ./...  # with race detector (needs CGO and a C toolchain)
```

### Benchmarks

```bash
go test -run '^$' -bench . -benchtime 1x ./...        # everything, once
go test -run '^$' -bench BenchmarkTunnelThroughput -benchtime 5s .
./scripts/benchmark-weaknet.sh                         # degraded-path sweep
```

`weaknet_test.go` puts a real UDP relay between the client and a live DNS
server and degrades the path in both directions: per-packet delay, jitter,
loss, duplication, reordering and a token-bucket bandwidth cap. It is a relay
rather than a `net.Conn` wrapper, so the client's own dial pooling,
retransmission, deduplication and reorder assembly are what get measured.
Each profile reports goodput, `retries` (retransmitted upstream chunks per
iteration) and `window` (the adaptive in-flight window it settled at).

| profile      | degradation                                    |
|--------------|------------------------------------------------|
| `clean`      | baseline, loopback                             |
| `3g`         | 75 ms one-way, 2 % loss                        |
| `4g`         | 40 ms one-way, 1 % loss                        |
| `badWifi`    | 15 ms one-way + 40 ms jitter, 5 % loss         |
| `congested`  | 250 ms one-way, 10 % loss                      |
| `lossy`      | 10 % loss, no added latency                    |
| `reordered`  | 25 % of packets delivered twice, delayed       |
| `duplicated` | 30 % of packets delivered twice                |
| `2mbit`      | 2 Mbit/s cap                                   |
| `512kbit`    | 512 kbit/s cap                                 |

Loss and duplication are applied per leg, so a 10 % link still lets 91.8 % of
a round trip through. Payload size is tuned per profile rather than shared: the
client retransmits a lost chunk only after its DNS query times out, and that
wait — a 4 s ceiling clamped down to eight times the measured round trip, with
a 500 ms floor — is what a high-loss profile spends most of its time in. The
relay's own knobs are pinned by
`TestWeakLinkAppliesEveryDegradationMode`, `TestWeakLinkInjectsDelayAndReorder`
and `TestWeakLinkRateLimits`, which check each degradation against the wire
instead of trusting the injection code by convention.

Reference sweep on a 32-core runner (`benchtime 3x`, ~1 KiB per iteration):

| profile    | goodput | retries | window |
|------------|---------|---------|--------|
| `clean`    | 0.19 MB/s | 0    | 14 |
| `3g`       | 0.00 MB/s | 0.67  | 9  |
| `4g`       | 0.00 MB/s | 0.33  | 4  |
| `badWifi`  | 0.00 MB/s | 0     | 12 |
| `congested` | 0.00 MB/s | 0    | 12 |
| `lossy`    | 0.00 MB/s | 2.67  | 6  |
| `reordered` | 0.00 MB/s | 5.00 | 4  |
| `duplicated` | 0.01 MB/s | 0   | 13 |
| `2mbit`    | 0.04 MB/s | 0     | 4  |
| `512kbit`  | 0.01 MB/s | 0     | 4  |

Before the adaptive exchange wait, the same sweep measured 1.85 s for `clean`,
4.61 s for `3g`, 2.57 s for `4g`, 6.44 s for `congested` and 3.64 s for
`lossy`; it now measures 0.18 s, 2.97 s, 2.22 s, 4.21 s and 1.81 s
respectively.

### CI

`.github/workflows/test.yml` is the merge gate: vet plus plain and
race-enabled tests, and a one-iteration smoke of every benchmark, on Linux,
macOS and Windows for every push and pull request. A second job repeats vet,
tests and the benchmark smoke compiled for `GOARCH=386`, which is where
unaligned 64-bit atomics and integer truncation surface.

`.github/workflows/throughput.yml` compares a pull request's benchmark numbers
against its base using `benchstat`, across the UDP/TCP/DoH upstream by TCP/UDP
target matrix.

`.github/workflows/weaknet.yml` runs the degraded-path sweep on Linux, macOS
and Windows every Monday and on demand (`workflow_dispatch`, with a
`benchtime` input). It uploads the raw `go test` output and a CSV per runner as
artifacts and writes a markdown table to the run summary, so week-over-week
changes in the loss profiles are readable without digging through logs.

Pushing a `v1.0.yyyyMMdd.<commit-count>-<short-sha>` tag triggers
`.github/workflows/release.yml`, which re-runs the tests and publishes raw
binaries for 9 platforms. The workflow can also be run manually, in which case
it builds and uploads the binaries as an artifact instead of creating a release.
