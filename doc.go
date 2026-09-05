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
// without declaring anything.
package dnstunnel

// Version is the release version of the tool. Release builds override it via
// -ldflags "-X github.com/NNdroid/dns_custom.Version=<version>".
var Version = "1.4.0"
