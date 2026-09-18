// Package dnstunnel implements a high-performance DNS tunnel with optional
// Noise_NK Curve25519 AEAD encryption.
//
// # Embedding the tunnel in other programs
//
// The tunnel can be used as a library so external programs can borrow it for
// unified, encrypted access to backend services:
//
//	// Client side: every Dial opens an independent tunnel session.
//	cli, err := dnstunnel.NewClient(dnstunnel.ClientConfig{
//		Domain:     "tunnel.example.com",
//		Servers:    []string{"8.8.8.8:53", "1.1.1.1:53"},
//		RecordType: "txt",
//		PublicKey:  serverPubKey, // optional Noise_NK key
//	})
//	conn, err := cli.Dial(ctx)          // stream access (net.Conn)
//	pconn, err := cli.DialUDP(ctx)      // datagram access (net.PacketConn)
//
//	// Server side: terminates sessions and forwards to the backend.
//	srv, err := dnstunnel.NewServer(dnstunnel.ServerConfig{
//		ListenAddr: ":53",
//		TargetAddr: "tcp://127.0.0.1:22", // or "udp://127.0.0.1:51820"
//		Domain:     "tunnel.example.com",
//		PrivateKey: serverPrivKey,
//	})
//	err = srv.Run(ctx) // blocks; returns nil on clean ctx cancellation
//
// Dial returns a net.Conn and DialUDP a net.PacketConn, so the tunnel plugs
// directly into http.Transport.DialContext, database drivers, SSH clients and
// anything else that consumes standard connection interfaces.
//
// The server routes sessions by the marker inside the session ID: plain stream
// sessions follow the configured target scheme (tcp:// backends receive a byte
// stream), while sessions whose ID carries the UDP marker (created by DialUDP)
// are forwarded as length-framed datagrams over UDP. The session transport must
// match the target scheme — a UDP-marker session against a tcp:// target is
// refused, because datagram semantics cannot be preserved toward a stream
// backend. Stream sessions against udp:// targets are the legacy pre-datagram
// behavior (datagram boundaries are not preserved) and are kept only for
// compatibility with older clients.
//
// # Wire layout
//
// The query layout places the session label first and upstream payloads span
// multiple labels (~2.4× upstream bytes per query):
//
//	{session}.{seq}.{ack}.{flag}.{dataSeq}.{d1}...{dN}.marker.{domain}
//
// The probe rides the target-declaration exchange, so it costs no extra round
// trip.
//
// # Throughput paths
//
// Downstream throughput is bounded by the response budget of the upstream
// transport: ~200-byte chunks under the legacy 512-byte UDP limit, ~800-byte
// chunks with EDNS0 ("edns0" on both ends), and ~8 KiB chunks when queries
// arrive over TCP (tcp:// upstreams or resolvers forwarding over TCP — DNS/TCP
// messages are length-prefixed and not datagram-bound). Upstream pollers (three
// per path, additive in-flight windows on both directions) pipeline the round
// trips; clients advertise their downstream flow-control window in every poll.
//
// # Client-declared targets
//
// A client may declare the backend it wants per configuration (ClientConfig
// Target) or per session. The server validates the declaration against
// ServerConfig AllowTargets — a list of patterns such as "tcp://127.0.0.1:*" or
// "udp://10.8.0.*:51820" where each of scheme, host and port may be "*" and
// host wildcards never cross a dot. An empty AllowTargets list means clients
// cannot override the target. Every exchange answers with the transport that
// actually applies ("tcp" or "udp"), declared or default, so callers always
// know which kind of local socket to bind; Client.DefaultTarget probes it
// without declaring anything. DialTarget / DialUDPTarget declare the backend
// per session instead of per client, so one Client can reach several backends
// (e.g. SSH over tcp:// and WireGuard over udp://) validated by the same allow
// list. ClientConfig.TLSConfig customizes the TLS layer of tls://, dot:// and
// https:// upstream resolvers (root CAs, SNI, skip-verify).
//
// # Event callbacks
//
// Instead of (or besides) logs, embedders can drive business logic from typed
// events: ClientConfig.EventHandler / Client.SetEventHandler receive
// TunnelEstablished, Reconnecting, TunnelDied (with the death reason) and
// TargetDenied; ServerConfig.EventHandler / Server.SetEventHandler receive
// SessionCreated, SessionClosed and the SIEM-ready security kinds
// AuthRejected, ReplayDropped, TargetDenied. Handlers are dispatched on a
// dedicated goroutine with per-event panic recovery; publishing is bounded and
// never blocks the data path. Each client session also exposes Done()
// <-chan struct{} and Err() error, context-style, for death-only signaling.
package dnstunnel

// Version is the release version of the tool. Release builds override it via
// -ldflags "-X github.com/NNdroid/dns_custom.Version=<version>".
//
// Release builds follow the convention
//
//	v1.0.yyyyMMdd.<commit-count>-<short-sha>
//
// where yyyyMMdd is the UTC date, <commit-count> is the total number of commits
// (git rev-list --count HEAD) and <short-sha> is the first 7 hex digits of the
// current commit (git rev-parse --short=7 HEAD). scripts/build.sh and the
// .github/workflows/release.yml release pipeline generate it automatically. This
// default is only used for local dev builds (go run / go build without ldflags).
var Version = "v1.0.dev"
