// Client side of the DNS tunnel: dials out through upstream DNS resolvers.
package dnstunnel

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	mrand "math/rand"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
	"go.uber.org/zap"
)

// dnsTunnelMaxSendAttempts is how many times one upstream chunk is re-sent before
// the tunnel gives up on it. Retries reuse the same dataSeq (and therefore the same
// ciphertext), so duplicates are harmless on the server side.
const dnsTunnelMaxSendAttempts = 5

// dnsTunnelPathCooldown is how long a failing upstream path is skipped before it gets
// another chance. Without it a dead path still takes its round-robin turn on every
// chunk, and every other chunk pays the timeout.
const dnsTunnelPathCooldown = 2 * time.Second

// dnsTunnelConnPool is how many sockets each upstream path keeps warm. dns.Client.Exchange
// dials a fresh socket per query, and on most platforms that dial costs more than the
// query itself - it was the real ceiling on how much concurrency could buy.
const dnsTunnelConnPool = 32

// DNS over TCP has a 16-bit message length prefix, so a larger DoH body can
// never be a valid DNS message. Capping it prevents a bad endpoint from forcing
// an unbounded allocation in io.ReadAll.
const maxDNSWireMessageSize = 65535

// udpSessionPrefix marks a tunnel session as carrying length-framed UDP datagrams
// instead of a raw byte stream. It lives inside the session label of the query
// name, so the server learns the mode from the very first query without a
// protocol change. Hex session IDs generated for stream sessions can never start
// with "u", which keeps the two modes unambiguous on the same server.
const udpSessionPrefix = "u"

// nopLogger is the logger used when the embedder did not inject one.
var nopLogger = zap.NewNop().Sugar()

// dnsPath is one upstream resolver plus its warm socket pool. A pooled socket is owned
// exclusively by the query that is in flight on it: a shared socket would let one
// caller's read steal another caller's response.
type dnsPath struct {
	server  string
	dohURL  string
	network string
	addr    string
	dnsCli  *dns.Client
	httpCli *http.Client
	pool    chan *dns.Conn
	closed  atomic.Bool
}

func newDNSPath(server string, dialers ...*net.Dialer) *dnsPath {
	var dialer *net.Dialer
	if len(dialers) > 0 {
		dialer = dialers[0]
	}
	p := &dnsPath{
		server: server,
		pool:   make(chan *dns.Conn, dnsTunnelConnPool),
	}
	switch {
	case strings.HasPrefix(server, "https://"), strings.HasPrefix(server, "http://"):
		p.dohURL = server
	case strings.HasPrefix(server, "doh://"):
		p.dohURL = "https://" + strings.TrimPrefix(server, "doh://")
	case strings.HasPrefix(server, "tcp://"):
		p.network, p.addr = "tcp", strings.TrimPrefix(server, "tcp://")
	case strings.HasPrefix(server, "tls://"), strings.HasPrefix(server, "dot://"):
		p.network, p.addr = "tcp-tls", strings.TrimPrefix(strings.TrimPrefix(server, "tls://"), "dot://")
	default:
		p.network, p.addr = "udp", server
	}
	if p.dohURL != "" {
		transport := http.DefaultTransport.(*http.Transport).Clone()
		transport.MaxIdleConnsPerHost = dnsTunnelConnPool
		if dialer != nil {
			transport.DialContext = dialer.DialContext
		}
		p.httpCli = &http.Client{Transport: transport, Timeout: 4 * time.Second}
	} else {
		p.dnsCli = &dns.Client{Net: p.network, Timeout: 4 * time.Second, Dialer: dialer}
	}
	return p
}

// acquire returns a warm socket, dialing one if the pool is empty.
func (p *dnsPath) acquire() (*dns.Conn, error) {
	if p.closed.Load() {
		return nil, net.ErrClosed
	}
	select {
	case co := <-p.pool:
		return co, nil
	default:
	}
	co, err := p.dnsCli.Dial(p.addr)
	if err != nil {
		return nil, err
	}
	if p.closed.Load() {
		_ = co.Close()
		return nil, net.ErrClosed
	}
	return co, nil
}

func (p *dnsPath) release(co *dns.Conn) {
	if co == nil {
		return
	}
	if p.closed.Load() {
		_ = co.Close()
		return
	}
	select {
	case p.pool <- co:
	default:
		_ = co.Close() // pool is full; do not grow it without bound
	}
}

func (p *dnsPath) close() {
	if !p.closed.CompareAndSwap(false, true) {
		return
	}
	if p.httpCli != nil {
		p.httpCli.CloseIdleConnections()
	}
	for {
		select {
		case co := <-p.pool:
			_ = co.Close()
		default:
			return
		}
	}
}

func (p *dnsPath) exchange(ctx context.Context, m *dns.Msg) (*dns.Msg, error) {
	if p.dohURL != "" {
		return p.exchangeDoH(ctx, m)
	}
	co, err := p.acquire()
	if err != nil {
		return nil, err
	}
	resp, _, err := p.dnsCli.ExchangeWithConnContext(ctx, m, co)
	if err != nil {
		// Drop the socket: a pooled one may have gone stale (peer closed it, NAT
		// expired), and the next acquire dials a fresh one.
		_ = co.Close()
		return nil, err
	}
	p.release(co)
	return resp, nil
}

func (p *dnsPath) exchangeDoH(ctx context.Context, m *dns.Msg) (*dns.Msg, error) {
	raw, err := m.Pack()
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, "POST", p.dohURL, bytes.NewReader(raw))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")

	resp, err := p.httpCli.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("doh server returned status %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxDNSWireMessageSize+1))
	if err != nil {
		return nil, err
	}
	if len(body) > maxDNSWireMessageSize {
		return nil, fmt.Errorf("doh response is larger than %d bytes", maxDNSWireMessageSize)
	}
	reply := new(dns.Msg)
	if err := reply.Unpack(body); err != nil {
		return nil, err
	}
	return reply, nil
}

// ClientConfig configures a Client. Logger may be left nil for a silent client;
// the CLI injects its own zap logger here.
//
// Target optionally declares the backend the client wants sessions forwarded to
// ("tcp://host:port" or "udp://host:port"; host:port alone means tcp). The
// server only honors it when the target passes its allow_targets list, and the
// server's answer tells the caller which transport actually applies (see
// DefaultTarget and DNSClientTunnel.Transport). Leave empty to use whatever
// default target the server is configured with.
type ClientConfig struct {
	Domain     string             `json:"domain"`
	Servers    []string           `json:"servers"`
	RecordType string             `json:"record_type"`
	PublicKey  string             `json:"pubkey"`
	Target     string             `json:"target,omitempty"`
	EDNS0      bool               `json:"edns0,omitempty"`
	Logger     *zap.SugaredLogger `json:"-"`
	// Dialer optionally controls sockets used by UDP, TCP, DoT and DoH paths.
	Dialer *net.Dialer `json:"-"`
}

// Client is the library entry point for dialing out through the DNS tunnel. One
// Client can open any number of independent tunnel sessions via Dial / DialUDP.
type Client struct {
	servers    []string
	domain     string
	recordType string
	publicKey  string
	target     string
	edns0      bool
	log        *zap.SugaredLogger
	dialer     *net.Dialer
}

// NewClient validates the configuration and returns a Client. The public key,
// when set, is parsed once here so a typo fails at startup instead of on the
// first dial.
func NewClient(cfg ClientConfig) (*Client, error) {
	if strings.TrimSpace(cfg.Domain) == "" {
		return nil, errors.New("dnstunnel: domain is required")
	}
	if len(cfg.Servers) == 0 {
		return nil, errors.New("dnstunnel: at least one upstream DNS server is required")
	}
	if cfg.PublicKey != "" {
		if _, err := ParseNoiseKey(cfg.PublicKey); err != nil {
			return nil, fmt.Errorf("dnstunnel: invalid server public key: %w", err)
		}
	}
	qtype, err := dnsTypeToQType(cfg.RecordType)
	if err != nil {
		return nil, fmt.Errorf("dnstunnel: %w", err)
	}
	if cfg.PublicKey != "" && (qtype == dns.TypeA || qtype == dns.TypeAAAA) {
		return nil, fmt.Errorf("dnstunnel: record type %q cannot carry authenticated Noise frames (A/AAAA hold 4/16 bytes); use txt/null/cname/mx/srv/ns", cfg.RecordType)
	}
	log := cfg.Logger
	if log == nil {
		log = nopLogger
	}
	return &Client{
		servers:    cfg.Servers,
		domain:     cfg.Domain,
		recordType: cfg.RecordType,
		publicKey:  cfg.PublicKey,
		target:     strings.TrimSpace(cfg.Target),
		edns0:      cfg.EDNS0,
		log:        log,
		dialer:     cfg.Dialer,
	}, nil
}

// Dial opens a new tunnel session and returns it as a stream net.Conn. Each call
// establishes an independent session (Noise handshake, target declaration,
// pollers, adaptive window) terminated on the server's backend. When the client
// has a declared target it must be tcp:// — datagram targets need DialUDP.
func (c *Client) Dial(ctx context.Context) (net.Conn, error) {
	if c.target != "" && strings.HasPrefix(c.target, "udp://") {
		return nil, fmt.Errorf("dnstunnel: declared target %q is udp; use DialUDP", c.target)
	}
	return newDNSClientTunnel(ctx, c.servers, c.domain, c.recordType, c.publicKey, "", c.target, c.edns0, c.log, c.dialer)
}

// DialUDP opens a new tunnel session that carries UDP datagrams to the server's
// UDP backend. Datagrams are length-framed over the tunnel byte stream, so
// datagram boundaries survive the trip (unlike the legacy stream mode, which
// reassembles upstream chunks without preserving boundaries).
//
// When the client has a declared target it must be udp://; the declaration is
// validated by the server's allow list. Without a declaration the session uses
// the server's default target, which must itself be udp://.
func (c *Client) DialUDP(ctx context.Context) (net.PacketConn, error) {
	if c.target != "" && !strings.HasPrefix(c.target, "udp://") {
		return nil, fmt.Errorf("dnstunnel: declared target %q is tcp; use Dial", c.target)
	}
	t, err := newDNSClientTunnel(ctx, c.servers, c.domain, c.recordType, c.publicKey, udpSessionPrefix, c.target, c.edns0, c.log, c.dialer)
	if err != nil {
		return nil, err
	}
	return &tunnelPacketConn{stream: t}, nil
}

// DefaultTarget asks the server which transport its default target uses ("tcp"
// or "udp"). It opens a throwaway session, declares no target, and reads the
// server's answer — this is how a caller that has no declared target learns
// which local socket to bind. A server that predates target declarations (or
// refuses the empty declaration) yields an error.
func (c *Client) DefaultTarget(ctx context.Context) (string, error) {
	t, err := newDNSClientTunnel(ctx, c.servers, c.domain, c.recordType, c.publicKey, "", "", c.edns0, c.log, c.dialer)
	if err != nil {
		return "", err
	}
	defer t.Close()
	return t.declareTarget("")
}

// DNSClientTunnel is one tunnel session: a reliable ordered byte stream over DNS
// queries, optionally encrypted with Noise_NK. It implements net.Conn, so it can
// be handed directly to io.Copy, http.Transport.DialContext, database drivers
// and anything else that consumes connections.
type DNSClientTunnel struct {
	ctx          context.Context
	cancel       context.CancelFunc
	servers      []string
	domain       string
	qtype        uint16
	edns0        bool
	session      string
	chunkSize    int
	pollInterval time.Duration
	log          *zap.SugaredLogger
	dialer       *net.Dialer

	paths        []*dnsPath    // one per configured upstream server
	serverCursor uint32        // atomic; round-robin cursor over upstream servers
	failUntil    []int64       // atomic per element; deadline until a path is skipped
	seq          uint32        // atomic; per-query anti-cache sequence
	inMu         sync.Mutex    // guards inBuf
	inCond       *sync.Cond    // signals waiting Read() when inBuf receives data
	inBuf        *bytes.Buffer // downstream bytes ready for Read
	noiseSession *NoiseSession
	closed       atomic.Bool
	closeCh      chan struct{}

	// Deadlines for the net.Conn interface. The blocking waits check these after
	// every wake-up; armDeadline broadcasts the wait conditions on expiry.
	deadlineMu    sync.Mutex
	readDeadline  time.Time
	writeDeadline time.Time

	// Adaptive in-flight window for upstream chunks (see onWindowSample).
	window     int32 // atomic; current total in-flight window
	winCredit  int64 // atomic; successful samples since the last growth step
	winSamples int64 // atomic; samples seen so far, used to skip the cold-start ones
	bestRTT    int64 // atomic; best upstream round trip seen so far, in nanoseconds

	// Reliable-ordered transport: dedup plus in-order reassembly in both directions.
	dataSeq  uint32            // atomic; per-chunk upstream ordering sequence
	ack      uint32            // atomic; highest contiguous downstream serverSeq received (== recvNext-1)
	recvNext uint32            // next expected downstream serverSeq
	recvOOO  map[uint32][]byte // out-of-order downstream chunks buffered for in-order delivery
	recvMu   sync.Mutex
	writeMu  sync.Mutex // serializes Write calls so the byte-stream order is unambiguous

	// pollKick nudges idle pollers as soon as an upstream write completes, so the
	// server's fresh downstream data is fetched within one RTT instead of after
	// up to a full poll interval.
	pollKick chan struct{}

	// transport is the backend transport the server confirmed for this session
	// ("tcp"/"udp"), set by the target declaration before any data flows.
	transport string
}

func newDNSClientTunnel(ctx context.Context, servers []string, domain string, recordType string, pubKeyStr string, sessionPrefix string, declaredTarget string, edns0 bool, log *zap.SugaredLogger, dialer *net.Dialer) (*DNSClientTunnel, error) {
	if domain == "" || len(servers) == 0 {
		return nil, fmt.Errorf("domain and servers are required")
	}
	qtype, err := dnsTypeToQType(recordType)
	if err != nil {
		return nil, err
	}
	paths := make([]*dnsPath, 0, len(servers))
	for _, srv := range servers {
		paths = append(paths, newDNSPath(srv, dialer))
	}
	cctx, cancel := context.WithCancel(ctx)
	t := &DNSClientTunnel{
		ctx:          cctx,
		cancel:       cancel,
		servers:      servers,
		domain:       dns.Fqdn(domain),
		qtype:        qtype,
		edns0:        edns0,
		session:      sessionPrefix + fmt.Sprintf("%x", mrand.Uint64()),
		chunkSize:    dnsTunnelDefaultChunk,
		pollInterval: dnsTunnelPollInterval,
		log:          log,
		dialer:       dialer,
		inBuf:        new(bytes.Buffer),
		pollKick:     make(chan struct{}, len(paths)),
		closeCh:      make(chan struct{}),
		recvNext:     1,
		recvOOO:      make(map[uint32][]byte),
		failUntil:    make([]int64, len(servers)),
		paths:        paths,
		window:       dnsTunnelUpstreamWindow,
	}

	if pubKeyStr != "" {
		if qtype == dns.TypeA || qtype == dns.TypeAAAA {
			cancel()
			for _, p := range paths {
				p.close()
			}
			return nil, fmt.Errorf("record type %q cannot carry authenticated Noise frames (A/AAAA hold 4/16 bytes); use txt/null/cname/mx/srv/ns", recordType)
		}
		pk, err := ParseNoiseKey(pubKeyStr)
		if err != nil {
			cancel()
			for _, p := range paths {
				p.close()
			}
			return nil, fmt.Errorf("invalid server public key: %w", err)
		}
		ns, ePub, err := NewClientNoiseSession(pk)
		if err != nil {
			cancel()
			for _, p := range paths {
				p.close()
			}
			return nil, fmt.Errorf("create noise session failed: %w", err)
		}
		t.noiseSession = ns
		t.chunkSize = 22 // 22 bytes plain + 16 bytes AEAD tag = 38 bytes -> 61 Base32 chars (<= 63 DNS label limit)

		// The handshake is retried across servers under the SAME dataSeq. The server
		// anchors its in-order state on the handshake seq, so a retry must not
		// advance it - otherwise a slow-but-delivered first attempt leaves a hole
		// the peer would wait on forever.
		hsSeq := atomic.AddUint32(&t.dataSeq, 1)
		var hsErr error
		for i := range t.paths {
			if _, err := t.sendQuery(i, flagData, ePub, hsSeq); err != nil {
				hsErr = err
				continue
			}
			hsErr = nil
			break
		}
		if hsErr != nil {
			cancel()
			for _, p := range paths {
				p.close()
			}
			return nil, fmt.Errorf("noise handshake exchange failed: %w", hsErr)
		}
		t.log.Infof("🔐 Established Noise_NK encryption session with server")
	}

	// Declare the target (if any) before the pollers and before any data: the
	// server resolves the transport first and answers synchronously on this
	// query, and dials its backend only once data flows.
	if declaredTarget != "" {
		transport, err := t.declareTarget(declaredTarget)
		if err != nil {
			cancel()
			for _, p := range paths {
				p.close()
			}
			return nil, err
		}
		t.transport = transport
	}

	// One poller per upstream server. Polls are independent, each answer carries one
	// downstream frame, and reassembly is order-independent, so every configured path
	// contributes throughput instead of only serving as a failover spare.
	t.inCond = sync.NewCond(&t.inMu)

	for i := range t.servers {
		go t.pollLoop(i)
	}

	return t, nil
}

// NewDNSClientTunnel opens a single stream tunnel session. Library users usually
// want Client.Dial instead, which is this constructor behind a reusable,
// pre-validated Client.
func NewDNSClientTunnel(ctx context.Context, servers []string, domain string, recordType string, pubKeyStr string) (*DNSClientTunnel, error) {
	return newDNSClientTunnel(ctx, servers, domain, recordType, pubKeyStr, "", "", false, nopLogger, nil)
}

// sendQuery sends one tunnel query to a single upstream server and feeds any answer
// payload into the downstream reassembly. It returns the number of downstream bytes
// that became available to Read.
//
// Queries are no longer serialized globally: the only ordering requirement used to be
// the AEAD nonce, and that is now derived from the sequence number carried by the
// query/frame itself.
// buildQuery assembles a tunnel query message for the given data sequence, flag
// and wire payload. The query sequence doubles as the DNS transaction ID. With
// EDNS0 enabled the query announces a 1232-byte buffer so resolvers forward the
// server's larger answers instead of truncating them at 512.
func (t *DNSClientTunnel) buildQuery(dataSeq uint32, flag byte, wirePayload []byte) *dns.Msg {
	seq := atomic.AddUint32(&t.seq, 1)
	name := buildQueryName(t.domain, t.session, seq, atomic.LoadUint32(&t.ack), dataSeq, flag, wirePayload)

	m := new(dns.Msg)
	m.SetQuestion(name, t.qtype)
	m.RecursionDesired = false
	m.Id = uint16(seq)
	if t.edns0 {
		m.SetEdns0(dnsTunnelEDNS0UDPSize, false)
	}
	return m
}

func (t *DNSClientTunnel) sendQuery(pathIdx int, flag byte, wirePayload []byte, dataSeq uint32) (int, error) {
	if t.closed.Load() {
		return 0, net.ErrClosed
	}

	resp, err := t.paths[pathIdx].exchange(t.ctx, t.buildQuery(dataSeq, flag, wirePayload))
	if err != nil {
		return 0, err
	}
	delivered := 0
	if resp != nil {
		for _, ans := range resp.Answer {
			if raw := extractAnswer(ans); len(raw) > 0 {
				delivered += t.deliverDownstream(raw)
			}
		}
	}
	return delivered, nil
}

// nextServer returns the next upstream path in round-robin order, skipping paths that
// are still cooling down after a failure. If every path is cooling down - or the
// process is offline entirely - it falls back to plain round-robin so a chunk is never
// left without a path to try.
func (t *DNSClientTunnel) nextServer() int {
	n := uint32(len(t.paths))
	now := time.Now().UnixNano()
	var fallback uint32
	for i := uint32(0); i < n; i++ {
		idx := atomic.AddUint32(&t.serverCursor, 1) % n
		if i == 0 {
			fallback = idx
		}
		if atomic.LoadInt64(&t.failUntil[idx]) <= now {
			return int(idx)
		}
	}
	return int(fallback)
}

// upstreamWindow is how many upstream chunks may be in flight at once. It starts
// conservatively and is grown by onWindowSample, and its ceiling scales with the
// number of paths: every configured path carries its own share of the load, so more
// paths justify more in-flight queries - but only the measurements can say how many.
func (t *DNSClientTunnel) upstreamWindow() int {
	w := int(atomic.LoadInt32(&t.window))
	max := dnsTunnelMaxUpstreamWindow * len(t.paths)
	if max > dnsTunnelMaxTotalWindow {
		max = dnsTunnelMaxTotalWindow
	}
	if w > max {
		w = max
	}
	if w < dnsTunnelMinUpstreamWindow {
		w = dnsTunnelMinUpstreamWindow
	}
	return w
}

// onWindowSample adapts the in-flight window from a completed upstream query, the same
// way congestion control does: grow while the path still answers at its best RTT, back
// off as soon as it slows down or drops. The right window is a property of the path,
// not of the code - on a loopback link 8 in-flight queries already saturate it and 32
// roughly halves the throughput, while on a 20 ms path 16 nearly doubles it - so it is
// measured rather than configured, and it is what lets several paths add up.
func (t *DNSClientTunnel) onWindowSample(ok bool, rtt time.Duration) {
	if !ok {
		t.halveWindow()
		return
	}
	// A zero round trip is a shutdown or clock artifact, not a measurement. Taking it
	// as the best RTT ever seen would make every later sample look slow and pin the
	// window at its minimum.
	if rtt <= 0 {
		return
	}
	// The first queries include socket setup, DNS server warm-up and GC noise, so
	// their latency says nothing about the path. Adopting one of those as the
	// "best" RTT would make every later sample look fast and pin the window at the
	// maximum, which is the exact opposite of what adaptation is for.
	if atomic.AddInt64(&t.winSamples, 1) <= dnsTunnelWindowWarmup {
		return
	}
	best := atomic.LoadInt64(&t.bestRTT)
	switch {
	case best > 0 && rtt > time.Duration(best)*2:
		// The path is clearly slower than it can be: we are past the useful window.
		// 2x is deliberately tight - on a low-latency link the queueing shows up well
		// before any query actually fails, and sitting at a too-wide window costs more
		// throughput than backing off does.
		t.resizeWindow(func(cur int32) int32 {
			if cur-1 < dnsTunnelMinUpstreamWindow {
				return dnsTunnelMinUpstreamWindow
			}
			return cur - 1
		})
		atomic.StoreInt64(&t.winCredit, 0)
		return
	case best > 0 && rtt > time.Duration(best)+time.Duration(best)/2:
		// Congested but not failing. Holding steady is not enough on its own: on a
		// low-latency path the queueing that a too-wide window causes never grows past
		// the shrink threshold, so the window would sit at the wrong size forever.
		// Decay slowly instead - one step per window's worth of queued samples.
		if atomic.AddInt64(&t.winCredit, 1) >= int64(atomic.LoadInt32(&t.window)) {
			atomic.StoreInt64(&t.winCredit, 0)
			t.resizeWindow(func(cur int32) int32 {
				if cur-1 < dnsTunnelMinUpstreamWindow {
					return dnsTunnelMinUpstreamWindow
				}
				return cur - 1
			})
		}
		return
	}

	if best == 0 || int64(rtt) < best {
		atomic.StoreInt64(&t.bestRTT, int64(rtt))
	}

	// Additive increase, paced to roughly one step per round trip: a window's worth of
	// successful queries is about one RTT at the current concurrency.
	if atomic.AddInt64(&t.winCredit, 1) >= int64(atomic.LoadInt32(&t.window)) {
		atomic.StoreInt64(&t.winCredit, 0)
		t.resizeWindow(func(cur int32) int32 {
			ceil := dnsTunnelMaxUpstreamWindow * len(t.paths)
			if ceil > dnsTunnelMaxTotalWindow {
				ceil = dnsTunnelMaxTotalWindow
			}
			if cur+1 > int32(ceil) {
				return int32(ceil)
			}
			return cur + 1
		})
	}
}

// halveWindow backs the window off after a failed query: a path that is dropping
// queries must not keep a wide window, or every retry floods it further.
func (t *DNSClientTunnel) halveWindow() {
	t.resizeWindow(func(cur int32) int32 {
		next := cur / 2
		if next < dnsTunnelMinUpstreamWindow {
			return dnsTunnelMinUpstreamWindow
		}
		return next
	})
	atomic.StoreInt64(&t.winCredit, 0)
}

// resizeWindow applies a clamp-and-grow step atomically.
func (t *DNSClientTunnel) resizeWindow(step func(int32) int32) {
	for {
		cur := atomic.LoadInt32(&t.window)
		next := step(cur)
		if next == cur || atomic.CompareAndSwapInt32(&t.window, cur, next) {
			return
		}
	}
}

func (t *DNSClientTunnel) markPathHealthy(idx int) {
	if idx >= 0 && idx < len(t.failUntil) {
		atomic.StoreInt64(&t.failUntil[idx], 0)
	}
}

func (t *DNSClientTunnel) markPathFailed(idx int) {
	if idx >= 0 && idx < len(t.failUntil) {
		atomic.StoreInt64(&t.failUntil[idx], time.Now().Add(dnsTunnelPathCooldown).UnixNano())
	}
}

// deliverDownstream reassembles downstream chunks in serverSeq order and updates the
// ACK the client advertises to the server. For TXT it reads the reliable-transport
// frame header, decrypts the payload with the nonce derived from serverSeq, and then
// runs the in-order reassembly. Other record types are best-effort: with Noise they
// carry a 4-byte sequence header in front of the ciphertext for the same reason.
//
// Reassembly bookkeeping happens under recvMu, but inBuf is only ever touched under
// inMu. Any number of pollers can deliver downstream data while the Read goroutine
// drains inBuf, so one lock per buffer is what keeps this race-free.
func (t *DNSClientTunnel) deliverDownstream(raw []byte) int {
	if len(raw) == 0 {
		return 0
	}
	noise := t.noiseSession != nil && t.noiseSession.RecvCipher != nil

	if t.qtype == dns.TypeTXT {
		serverSeq, skipTo, tail, ok := decodeDownstreamFrame(raw)
		if !ok {
			// Not a framed chunk (legacy or truncated answer). Without a sequence
			// number there is no nonce, so an authenticated chunk cannot be opened.
			if noise {
				t.log.Warnf("Short TXT frame (%d bytes) cannot be authenticated, dropped", len(raw))
				return 0
			}
			return t.writeInBuf(raw)
		}

		payload := tail
		if noise {
			dec, err := t.noiseSession.RecvCipher.Decrypt(uint64(serverSeq), tail)
			if err != nil {
				t.log.Warnf("Downstream frame serverSeq=%d failed to decrypt: %v", serverSeq, err)
				return 0
			}
			payload = dec
		}

		t.recvMu.Lock()
		// The server abandoned everything below skipTo: accept the gap rather than
		// block forever on chunks that will never arrive.
		if seqLess(t.recvNext, skipTo) {
			for k := range t.recvOOO {
				if seqLess(k, skipTo) {
					delete(t.recvOOO, k)
				}
			}
			t.recvNext = skipTo
		}
		delivered := 0
		if seqLess(serverSeq, t.recvNext) {
			// duplicate, already delivered in order
		} else if serverSeq == t.recvNext {
			// Keep recvMu held until every newly contiguous chunk has been appended
			// to inBuf. Releasing it first lets a later response win inMu and
			// reverses two otherwise correctly reassembled chunks.
			t.inMu.Lock()
			n, _ := t.inBuf.Write(payload)
			delivered += n
			t.recvNext++
			for {
				chunk, exists := t.recvOOO[t.recvNext]
				if !exists {
					break
				}
				n, _ = t.inBuf.Write(chunk)
				delivered += n
				delete(t.recvOOO, t.recvNext)
				t.recvNext++
			}
			if delivered > 0 && t.inCond != nil {
				t.inCond.Broadcast()
			}
			t.inMu.Unlock()
		} else if _, exists := t.recvOOO[serverSeq]; !exists {
			t.recvOOO[serverSeq] = append([]byte(nil), payload...)
		}
		atomic.StoreUint32(&t.ack, t.recvNext-1)
		t.recvMu.Unlock()

		return delivered
	}

	// Non-TXT: best-effort delivery.
	if noise {
		if len(raw) < nonTxtNoiseHeaderSize {
			return 0
		}
		seq := binary.BigEndian.Uint32(raw[:nonTxtNoiseHeaderSize])
		dec, err := t.noiseSession.RecvCipher.Decrypt(uint64(seq), raw[nonTxtNoiseHeaderSize:])
		if err != nil {
			t.log.Warnf("Downstream chunk seq=%d failed to decrypt: %v", seq, err)
			return 0
		}
		return t.writeInBuf(dec)
	}
	return t.writeInBuf(raw)
}

func (t *DNSClientTunnel) writeInBuf(b []byte) int {
	if len(b) == 0 {
		return 0
	}
	t.inMu.Lock()
	n, _ := t.inBuf.Write(b)
	if t.inCond != nil {
		t.inCond.Broadcast()
	}
	t.inMu.Unlock()
	return n
}

func (t *DNSClientTunnel) pendingDownstream() int {
	t.inMu.Lock()
	defer t.inMu.Unlock()
	return t.inBuf.Len()
}

// pollLoop keeps one upstream path busy: it polls, hands any answer to the reassembly,
// and paces itself. Data-bearing polls pipeline; empty polls back off. It also pauses
// while the reader has not drained what was already fetched, so a slow consumer cannot
// make the tunnel hoard answers.
func (t *DNSClientTunnel) pollLoop(idx int) {
	timer := time.NewTimer(time.Hour)
	if !timer.Stop() {
		<-timer.C
	}
	defer timer.Stop()

	for {
		if t.closed.Load() {
			return
		}
		select {
		case <-t.ctx.Done():
			return
		case <-t.closeCh:
			return
		default:
		}

		// Back off only once a real backlog has piled up. Throttling on ">0" would
		// stall a poller for a whole poll interval every time the reader happens to
		// be a few microseconds behind.
		if t.pendingDownstream() >= dnsTunnelDownstreamBacklog {
			if !t.waitTimer(timer, t.pollInterval) {
				return
			}
			continue
		}

		n, err := t.sendQuery(idx, flagPoll, nil, 0)
		delay := t.pollInterval
		switch {
		case err != nil:
			t.markPathFailed(idx)
		case n > 0:
			t.markPathHealthy(idx)
			delay = dnsTunnelPollBusyInterval
		default:
			t.markPathHealthy(idx)
		}
		if !t.waitTimer(timer, delay) {
			return
		}
	}
}

// waitTimer reuses the poller's timer instead of allocating a time.After timer
// after every response (up to one thousand times per second on a busy path).
func (t *DNSClientTunnel) waitTimer(timer *time.Timer, d time.Duration) bool {
	timer.Reset(d)
	select {
	case <-t.ctx.Done():
	case <-t.closeCh:
	case <-t.pollKick:
		return true
	case <-timer.C:
		return true
	}
	if !timer.Stop() {
		select {
		case <-timer.C:
		default:
		}
	}
	return false
}

// kickPollers wakes one idle poller so freshly written upstream data and its
// downstream answer are fetched within a round trip instead of after up to a
// full poll interval. Non-blocking: tokens coalesce while pollers are busy.
func (t *DNSClientTunnel) kickPollers() {
	select {
	case t.pollKick <- struct{}{}:
	default:
	}
}

func (t *DNSClientTunnel) sleep(d time.Duration) {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-t.ctx.Done():
	case <-t.closeCh:
	case <-timer.C:
	}
}

func (t *DNSClientTunnel) Read(p []byte) (int, error) {
	t.inMu.Lock()
	defer t.inMu.Unlock()

	for t.inBuf.Len() == 0 {
		if t.closed.Load() {
			return 0, io.EOF
		}
		select {
		case <-t.ctx.Done():
			return 0, t.ctx.Err()
		case <-t.closeCh:
			return 0, io.EOF
		default:
		}
		if t.readDeadlineExceeded() {
			return 0, os.ErrDeadlineExceeded
		}

		if t.inCond != nil {
			t.inCond.Wait()
		} else {
			t.inMu.Unlock()
			time.Sleep(10 * time.Millisecond)
			t.inMu.Lock()
		}
	}

	return t.inBuf.Read(p)
}

func (t *DNSClientTunnel) Write(p []byte) (int, error) {
	t.writeMu.Lock()
	defer t.writeMu.Unlock()

	if t.closed.Load() {
		return 0, net.ErrClosed
	}
	total := len(p)
	if total == 0 {
		return 0, nil
	}

	type chunkJob struct {
		idx  int
		seq  uint32
		data []byte
	}
	var jobs []chunkJob
	for len(p) > 0 {
		n := len(p)
		if n > t.chunkSize {
			n = t.chunkSize
		}
		jobs = append(jobs, chunkJob{idx: len(jobs), seq: atomic.AddUint32(&t.dataSeq, 1), data: p[:n]})
		p = p[n:]
	}

	// Upstream chunks fly concurrently. The window scales with the number of paths so
	// each path can keep several queries in flight - that, not the path count alone, is
	// what turns latency into throughput.
	win := t.upstreamWindow()
	if win > len(jobs) {
		win = len(jobs)
	}
	if win <= 0 {
		win = 1
	}

	jobsCh := make(chan chunkJob, len(jobs))
	for _, j := range jobs {
		jobsCh <- j
	}
	close(jobsCh)

	var wg sync.WaitGroup
	var mu sync.Mutex
	var firstErr error
	completed := make([]bool, len(jobs))

	for i := 0; i < win; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for job := range jobsCh {
				if t.closed.Load() {
					mu.Lock()
					if firstErr == nil {
						firstErr = net.ErrClosed
					}
					mu.Unlock()
					return
				}
				if err := t.sendDataChunkWithRetry(job.data, job.seq); err != nil {
					mu.Lock()
					if firstErr == nil {
						firstErr = err
					}
					mu.Unlock()
					return
				}
				mu.Lock()
				completed[job.idx] = true
				mu.Unlock()
			}
		}()
	}
	wg.Wait()

	sentBytes := 0
	for i, ok := range completed {
		if !ok {
			break
		}
		sentBytes += len(jobs[i].data)
	}
	if firstErr != nil {
		// A permanently missing sequence would block every later write in the
		// server's reorder buffer, so the stream cannot be safely reused.
		_ = t.Close()
		return sentBytes, firstErr
	}
	// The server just received fresh data and its backend reply is already on its
	// way downstream; wake an idle poller instead of waiting out the poll interval.
	t.kickPollers()
	return total, nil
}

// sendDataChunkWithRetry sends a data chunk and retransmits it (same dataSeq, hence the
// same ciphertext) on failure. The server dedups by dataSeq, so a retransmit is safe and
// just re-delivers the in-order chunk - this makes the upstream direction loss-tolerant.
func (t *DNSClientTunnel) sendDataChunkWithRetry(chunk []byte, dataSeq uint32) error {
	wire := chunk
	if t.noiseSession != nil && t.noiseSession.SendCipher != nil {
		// Sealed once, outside the retry loop: the nonce is derived from dataSeq, so
		// every attempt is byte-identical and the server can dedup it.
		wire = t.noiseSession.SendCipher.Encrypt(uint64(dataSeq), chunk)
	}
	var lastErr error
	for attempt := 0; attempt < dnsTunnelMaxSendAttempts; attempt++ {
		if t.closed.Load() {
			return net.ErrClosed
		}
		if t.writeDeadlineExceeded() {
			return os.ErrDeadlineExceeded
		}
		idx := t.nextServer()
		start := time.Now()
		_, err := t.sendQuery(idx, flagData, wire, dataSeq)
		t.onWindowSample(err == nil, time.Since(start))
		if err != nil {
			lastErr = err
			t.markPathFailed(idx)
		} else {
			t.markPathHealthy(idx)
			return nil
		}
		t.sleep(time.Duration(attempt+1) * 100 * time.Millisecond)
	}
	return fmt.Errorf("data chunk dataSeq=%d failed after %d attempts: %w", dataSeq, dnsTunnelMaxSendAttempts, lastErr)
}

func (t *DNSClientTunnel) Close() error {
	if t.closed.CompareAndSwap(false, true) {
		close(t.closeCh)
		t.inMu.Lock()
		if t.inCond != nil {
			t.inCond.Broadcast()
		}
		t.inMu.Unlock()
		t.sendCloseSignal()
		t.cancel()
		for _, p := range t.paths {
			p.close()
		}
	}
	return nil
}

// sendCloseSignal tells the server to tear down the session. It runs on a detached
// deadline: cancelling the tunnel context would otherwise also prevent the close
// query from ever leaving the host.
func (t *DNSClientTunnel) sendCloseSignal() {
	ctx, cancel := context.WithTimeout(context.Background(), dnsTunnelCloseTimeout)
	defer cancel()

	seq := atomic.AddUint32(&t.seq, 1)
	name := buildQueryName(t.domain, t.session, seq, atomic.LoadUint32(&t.ack), 0, flagClose, nil)
	m := new(dns.Msg)
	m.SetQuestion(name, t.qtype)
	m.RecursionDesired = false
	m.Id = uint16(seq)

	// Send on the detached context through a throwaway path so it still goes out
	// after the tunnel's own context is cancelled.
	path := newDNSPath(t.servers[t.nextServer()], t.dialer)
	defer path.close()
	_, _ = path.exchange(ctx, m)
}

// declareTarget sends a flag 'T' query declaring the backend this session wants
// ("" = the server default) and returns the transport the server confirmed:
// "tcp" or "udp". The declaration is encrypted with the reserved control
// sequence when Noise is on, and the answer is always plaintext.
func (t *DNSClientTunnel) declareTarget(target string) (string, error) {
	addr, wantUDP := "", false
	if target != "" {
		network, host := "tcp", target
		if strings.HasPrefix(target, "udp://") {
			network, host = "udp", strings.TrimPrefix(target, "udp://")
		} else {
			host = strings.TrimPrefix(target, "tcp://")
		}
		if strings.Contains(host, "://") || host == "" {
			return "", fmt.Errorf("dnstunnel: invalid declared target %q", target)
		}
		addr, wantUDP = host, network == "udp"
	}
	payload := encodeTargetRequest(addr, wantUDP)
	if t.noiseSession != nil && t.noiseSession.SendCipher != nil {
		payload = t.noiseSession.SendCipher.Encrypt(uint64(dnsTunnelControlSeq), payload)
	}

	var lastErr error
	for attempt := 0; attempt < dnsTunnelTargetAttempts; attempt++ {
		if t.closed.Load() {
			return "", net.ErrClosed
		}
		idx := t.nextServer()
		resp, err := t.paths[idx].exchange(t.ctx, t.buildQuery(dnsTunnelControlSeq, flagTarget, payload))
		if err == nil && resp != nil {
			for _, ans := range resp.Answer {
				if raw := extractAnswer(ans); raw != nil {
					status, udp, ok := decodeTargetResponse(raw)
					if !ok {
						continue
					}
					if status == targetStatusDeny {
						return "", fmt.Errorf("dnstunnel: declared target %q denied by the server allow list", target)
					}
					if udp {
						return "udp", nil
					}
					return "tcp", nil
				}
			}
			// A reply without a decodable answer means the server predates target
			// declarations: it echoed an empty or legacy answer. Fall back to the
			// legacy semantics (session marker decides, server default applies).
			t.log.Warnf("Server did not answer the target declaration (old version?); assuming server default target")
			return "", nil
		}
		lastErr = err
		t.markPathFailed(idx)
		t.sleep(dnsTunnelTargetBackoff * time.Duration(attempt+1))
	}
	return "", fmt.Errorf("dnstunnel: target declaration failed after %d attempts: %w", dnsTunnelTargetAttempts, lastErr)
}

// Transport reports the backend transport the server confirmed for this session
// ("tcp" or "udp"). It is set once the target declaration exchange completes;
// sessions without a declared target learn nothing here and follow the server's
// default.
func (t *DNSClientTunnel) Transport() string {
	return t.transport
}

// LocalAddr and RemoteAddr are pseudo addresses identifying this tunnel session;
// the tunnel has no real socket-level endpoints.
func (t *DNSClientTunnel) LocalAddr() net.Addr {
	return tunnelAddr{network: "dnstunnel", addr: "dnstunnel:" + t.session}
}

func (t *DNSClientTunnel) RemoteAddr() net.Addr {
	return tunnelAddr{network: "dnstunnel", addr: "dnstunnel:server"}
}

// SetDeadline sets both the read and the write deadline. A zero time disables the
// deadline. An expired deadline unblocks pending Read/Write calls with
// os.ErrDeadlineExceeded.
func (t *DNSClientTunnel) SetDeadline(deadline time.Time) error {
	if err := t.SetReadDeadline(deadline); err != nil {
		return err
	}
	return t.SetWriteDeadline(deadline)
}

func (t *DNSClientTunnel) SetReadDeadline(deadline time.Time) error {
	t.deadlineMu.Lock()
	t.readDeadline = deadline
	t.deadlineMu.Unlock()
	t.armDeadline(deadline)
	return nil
}

func (t *DNSClientTunnel) SetWriteDeadline(deadline time.Time) error {
	t.deadlineMu.Lock()
	t.writeDeadline = deadline
	t.deadlineMu.Unlock()
	t.armDeadline(deadline)
	return nil
}

// armDeadline wakes the blocking waits once the deadline passes. Read re-checks the
// stored deadline after every wake-up, so a broadcast is all that is needed.
func (t *DNSClientTunnel) armDeadline(deadline time.Time) {
	if deadline.IsZero() {
		return
	}
	if delta := time.Until(deadline); delta > 0 {
		time.AfterFunc(delta, t.wakeWaiters)
	}
}

func (t *DNSClientTunnel) wakeWaiters() {
	t.inMu.Lock()
	if t.inCond != nil {
		t.inCond.Broadcast()
	}
	t.inMu.Unlock()
}

func (t *DNSClientTunnel) readDeadlineExceeded() bool {
	t.deadlineMu.Lock()
	defer t.deadlineMu.Unlock()
	return !t.readDeadline.IsZero() && !time.Now().Before(t.readDeadline)
}

func (t *DNSClientTunnel) writeDeadlineExceeded() bool {
	t.deadlineMu.Lock()
	defer t.deadlineMu.Unlock()
	return !t.writeDeadline.IsZero() && !time.Now().Before(t.writeDeadline)
}

// tunnelAddr is the pseudo address carried by LocalAddr/RemoteAddr on the tunnel
// conn and the packet conn.
type tunnelAddr struct {
	network string
	addr    string
}

func (a tunnelAddr) Network() string { return a.network }
func (a tunnelAddr) String() string  { return a.addr }

// tunnelPacketConn adapts one tunnel session into a net.PacketConn carrying
// length-framed UDP datagrams. Every WriteTo becomes one datagram at the server's
// UDP backend and every datagram the backend sends becomes exactly one ReadFrom.
type tunnelPacketConn struct {
	stream *DNSClientTunnel
}

// packetServerAddr is reported by ReadFrom: the tunnel's backend is a single
// connected UDP peer on the server side.
var packetServerAddr = tunnelAddr{network: "dnstunnel", addr: "dnstunnel:server-backend"}

func (c *tunnelPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	var hdr [udpFrameHeaderSize]byte
	if _, err := io.ReadFull(c.stream, hdr[:]); err != nil {
		return 0, nil, err
	}
	n := int(binary.BigEndian.Uint16(hdr[:]))
	if n > len(p) {
		// Datagrams larger than the caller's buffer are truncated, matching
		// net.UDPConn semantics: read the full frame, keep what fits.
		buf := make([]byte, n)
		if _, err := io.ReadFull(c.stream, buf); err != nil {
			return 0, nil, err
		}
		copy(p, buf[:len(p)])
		return len(p), packetServerAddr, nil
	}
	if _, err := io.ReadFull(c.stream, p[:n]); err != nil {
		return 0, nil, err
	}
	return n, packetServerAddr, nil
}

func (c *tunnelPacketConn) WriteTo(b []byte, _ net.Addr) (int, error) {
	if len(b) > udpFrameMaxDatagram {
		return 0, fmt.Errorf("dnstunnel: datagram of %d bytes exceeds the %d byte frame limit", len(b), udpFrameMaxDatagram)
	}
	frame := encodeUDPFrame(b)
	if _, err := c.stream.Write(frame); err != nil {
		return 0, err
	}
	return len(b), nil
}

func (c *tunnelPacketConn) Close() error                       { return c.stream.Close() }
func (c *tunnelPacketConn) LocalAddr() net.Addr                { return c.stream.LocalAddr() }
func (c *tunnelPacketConn) RemoteAddr() net.Addr               { return packetServerAddr }
func (c *tunnelPacketConn) SetDeadline(t time.Time) error      { return c.stream.SetDeadline(t) }
func (c *tunnelPacketConn) SetReadDeadline(t time.Time) error  { return c.stream.SetReadDeadline(t) }
func (c *tunnelPacketConn) SetWriteDeadline(t time.Time) error { return c.stream.SetWriteDeadline(t) }
