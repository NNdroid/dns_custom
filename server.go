// Server-side of the DNS tunnel: terminates tunnel sessions and forwards their
// byte streams (or framed UDP datagrams) to a configured backend.
package dnstunnel

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
	"go.uber.org/zap"
)

const dnsTunnelServerBufferLimit = 512 * 1024

// ServerConfig configures a Server. Logger may be left nil for a silent server;
// the CLI injects its own zap logger here.
//
// AllowTargets gates client-declared targets (see flagTarget). It is a list of
// patterns like "tcp://127.0.0.1:*" or "udp://10.8.0.*:51820"; scheme, host and
// port may each be "*". An empty list means clients cannot override the target:
// every session uses TargetAddr. The special pattern "*" allows any target.
type ServerConfig struct {
	ListenAddr   string             `json:"listen"`
	TargetAddr   string             `json:"target"`
	Domain       string             `json:"domain"`
	PrivateKey   string             `json:"privkey"`
	AllowTargets []string           `json:"allow_targets,omitempty"`
	MaxSessions  int                `json:"max_sessions,omitempty"` // concurrent session cap; 0 = unlimited
	EDNS0        bool               `json:"edns0,omitempty"`        // announce 1232-byte UDP answers via EDNS0 (both ends must agree)
	Logger       *zap.SugaredLogger `json:"-"`
}

// Server is the library entry point for terminating DNS tunnel sessions and
// forwarding them to a backend. Run binds the authoritative DNS listener and
// blocks until the context is cancelled or the listener fails.
type Server struct {
	cfg     ServerConfig
	handler *DNSServer
	log     *zap.SugaredLogger
}

// NewServer validates the configuration, loads the Noise private key (if any)
// and returns a ready-to-run Server.
func NewServer(cfg ServerConfig) (*Server, error) {
	if strings.TrimSpace(cfg.Domain) == "" {
		return nil, errors.New("dnstunnel: domain is required")
	}
	if cfg.ListenAddr == "" {
		cfg.ListenAddr = ":53"
	}
	if cfg.TargetAddr == "" {
		cfg.TargetAddr = "tcp://127.0.0.1:22"
	}
	log := cfg.Logger
	if log == nil {
		log = nopLogger
	}
	handler, err := NewDNSServer(cfg)
	if err != nil {
		return nil, err
	}
	return &Server{cfg: cfg, handler: handler, log: log}, nil
}

// Run serves tunnel queries on UDP and TCP until ctx is cancelled (returns nil)
// or a listener fails (returns that error).
func (s *Server) Run(ctx context.Context) error {
	netType, target := parseTargetNetworkAndAddr(s.cfg.TargetAddr)
	s.log.Infof("🚀 Starting dns_custom server v%s", Version)
	s.log.Infof("📡 Listening on UDP %s (Authoritative Domain: %s)", s.cfg.ListenAddr, s.cfg.Domain)
	s.log.Infof("🎯 Forwarding Target: [%s] %s", netType, target)

	udpServer := &dns.Server{
		Addr:    s.cfg.ListenAddr,
		Net:     "udp",
		Handler: s.handler,
	}

	tcpServer := &dns.Server{
		Addr:    s.cfg.ListenAddr,
		Net:     "tcp",
		Handler: s.handler,
	}

	go s.handler.cleanupLoop(ctx)

	errCh := make(chan error, 2)
	go func() {
		errCh <- udpServer.ListenAndServe()
	}()
	go func() {
		errCh <- tcpServer.ListenAndServe()
	}()

	var runErr error
	select {
	case err := <-errCh:
		if err != nil {
			runErr = err
		}
	case <-ctx.Done():
	}
	s.log.Info("Shutting down DNS servers...")
	_ = udpServer.Shutdown()
	_ = tcpServer.Shutdown()
	return runErr
}

type DNSServer struct {
	cfg          ServerConfig
	domain       string
	domainLabels int
	edns0        bool
	sessions     map[string]*dnsSession
	mu           sync.RWMutex
	privKey      [32]byte
	hasPrivKey   bool
	log          *zap.SugaredLogger
}

type dnsSession struct {
	sessionID      string
	targetNetwork  string
	targetAddr     string
	wantsDatagram  bool // legacy marker in the session ID (old DialUDP clients)
	declared       bool // a target declaration was applied to this session
	framedUDP      bool // length-framed datagram mode (marker or declared udp:// target)
	backendStarted bool
	tcpConn        net.Conn
	udpConn        net.Conn
	noiseSession   *NoiseSession
	clientBuf      *bytes.Buffer
	serverBuf      *bytes.Buffer
	mu             sync.Mutex
	readCond       *sync.Cond
	serverCond     *sync.Cond // wakes a backend reader when downstream buffer space is freed
	pumpWaiting    bool       // true while the backend pump is blocked in readCond.Wait
	lastActive     int64
	closed         bool
	closeOnce      sync.Once
	log            *zap.SugaredLogger

	// Reliable-ordered transport: dedup plus in-order reassembly in both directions.
	clientNext   uint32                      // next in-order upstream dataSeq expected from client
	clientOOO    map[uint32][]byte           // out-of-order upstream data chunks buffered for later in-order delivery
	serverNext   uint32                      // next downstream serverSeq to assign
	serverOut    map[uint32]*downstreamChunk // un-acked downstream chunks kept for retransmission
	serverSkipTo uint32                      // >0 once chunks were abandoned: client must expect this seq
}

// downstreamChunk is one un-acked downstream chunk. ct is the payload as it goes on
// the wire: plaintext when Noise is off, ciphertext otherwise. It is sealed once when
// the chunk is created, because the AEAD nonce is derived from serverSeq - re-sealing
// on every retransmission would reuse a nonce with a fresh (wrong) counter, and the
// client could never decrypt a retransmitted chunk.
type downstreamChunk struct {
	ct        []byte
	firstSent time.Time
}

func newDnsSession(sessionID, targetNetwork, targetAddr string, wantsDatagram bool, noiseSess *NoiseSession, log *zap.SugaredLogger) *dnsSession {
	sess := &dnsSession{
		sessionID:     sessionID,
		targetNetwork: targetNetwork,
		targetAddr:    targetAddr,
		wantsDatagram: wantsDatagram,
		noiseSession:  noiseSess,
		log:           log,
		clientBuf:     new(bytes.Buffer),
		serverBuf:     new(bytes.Buffer),
		lastActive:    time.Now().Unix(),
		clientNext:    1,
		clientOOO:     make(map[uint32][]byte),
		serverNext:    1,
		serverOut:     make(map[uint32]*downstreamChunk),
	}
	sess.readCond = sync.NewCond(&sess.mu)
	sess.serverCond = sync.NewCond(&sess.mu)
	return sess
}

func (s *dnsSession) updateActive() {
	atomic.StoreInt64(&s.lastActive, time.Now().Unix())
}

func (s *dnsSession) pushClient(seq uint32, data []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || len(data) == 0 {
		return
	}
	// Reject duplicates before paying for AEAD verification. A retried Noise
	// handshake is the common case here: its 32-byte ephemeral key is not an
	// application ciphertext and should simply be ignored once seq was accepted.
	if seqLess(seq, s.clientNext) {
		return
	}
	if seq != s.clientNext {
		if _, exists := s.clientOOO[seq]; exists {
			return
		}
	}
	payload := data
	if s.noiseSession != nil && s.noiseSession.RecvCipher != nil {
		// Nonce is derived from the upstream sequence number, not from arrival
		// order: duplicates decrypt to the same plaintext and out-of-order chunks
		// decrypt independently, which is what makes concurrent paths safe.
		dec, err := s.noiseSession.RecvCipher.Decrypt(uint64(seq), data)
		if err != nil {
			s.log.Warnf("[%s] Noise decryption failed for dataSeq=%d: %v", s.sessionID, seq, err)
			return
		}
		payload = dec
	}

	if seq == s.clientNext {
		s.clientBuf.Write(payload)
		s.clientNext++
		for {
			c, ok := s.clientOOO[s.clientNext]
			if !ok {
				break
			}
			s.clientBuf.Write(c)
			delete(s.clientOOO, s.clientNext)
			s.clientNext++
		}
	} else {
		if _, exists := s.clientOOO[seq]; !exists {
			s.clientOOO[seq] = append([]byte(nil), payload...)
		}
	}
	atomic.StoreInt64(&s.lastActive, time.Now().Unix())
	// Wake the backend pump only when it is actually parked. Broadcasting on every
	// chunk makes each concurrent upstream query pay for a futex wakeup plus the
	// mutex handoff that follows, which is what capped throughput once several
	// paths were in flight at once.
	if s.pumpWaiting {
		s.readCond.Broadcast()
	}
}

// pushServer appends bytes read from the backend while applying bounded
// backpressure. A condition variable avoids the old 10 ms polling loop, reducing
// latency and scheduler wakeups when a slow DNS client catches up.
func (s *dnsSession) pushServer(data []byte) bool {
	if len(data) == 0 {
		return true
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for s.serverBuf.Len()+len(data) > dnsTunnelServerBufferLimit && s.serverBuf.Len() > 0 && !s.closed {
		s.serverCond.Wait()
	}
	if s.closed {
		return false
	}
	_, _ = s.serverBuf.Write(data)
	atomic.StoreInt64(&s.lastActive, time.Now().Unix())
	return true
}

// waitForClientData blocks the backend pump until upstream data arrives or the session
// closes. Caller must hold s.mu.
func (s *dnsSession) waitForClientData() {
	s.pumpWaiting = true
	s.readCond.Wait()
	s.pumpWaiting = false
}

// readNFromClientBuf fills out with exactly len(out) bytes from the upstream byte
// stream, blocking (in steps) until enough data has arrived. Returns false when the
// session closed before the bytes were complete.
func (s *dnsSession) readNFromClientBuf(out []byte) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	got := 0
	for got < len(out) {
		for s.clientBuf.Len() == 0 {
			if s.closed {
				return false
			}
			s.waitForClientData()
		}
		n, _ := s.clientBuf.Read(out[got:])
		got += n
	}
	return true
}

// readFramedFromClient reads one length-prefixed datagram from the upstream byte
// stream. Returns nil,false when the session closed mid-frame.
func (s *dnsSession) readFramedFromClient() ([]byte, bool) {
	var hdr [udpFrameHeaderSize]byte
	if !s.readNFromClientBuf(hdr[:]) {
		return nil, false
	}
	n := int(binary.BigEndian.Uint16(hdr[:]))
	payload := make([]byte, n)
	if n > 0 && !s.readNFromClientBuf(payload) {
		return nil, false
	}
	return payload, true
}

// freeDownstream drops downstream chunks the client has confirmed (ack = highest
// contiguous serverSeq it received). Keeps the retransmit buffer bounded.
func (s *dnsSession) freeDownstream(ack uint32) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for k := range s.serverOut {
		if !seqLess(ack, k) { // k <= ack (wraparound-safe)
			delete(s.serverOut, k)
		}
	}
}

// oldestDownstreamSeq returns the lowest (wraparound-aware) seq in serverOut.
// Caller must hold s.mu.
func oldestDownstreamSeq(m map[uint32]*downstreamChunk) uint32 {
	var minK uint32
	first := true
	for k := range m {
		if first || seqLess(k, minK) {
			minK = k
			first = false
		}
	}
	return minK
}

// sealDownstream encrypts a payload under the nonce derived from seq.
// Caller must hold s.mu.
func (s *dnsSession) sealDownstream(seq uint32, payload []byte) []byte {
	if s.noiseSession != nil && s.noiseSession.SendCipher != nil {
		return s.noiseSession.SendCipher.Encrypt(uint64(seq), payload)
	}
	return payload
}

// serveDownstream returns the next downstream chunk for the client.
// For TXT it implements the reliable-ordered transport as a sliding window: while
// fewer than dnsTunnelDownstreamWindow chunks are outstanding it serves fresh data,
// so concurrent polls across multiple upstream servers each fetch a different chunk
// and their throughput adds up. Once the window is full it falls back to
// retransmitting the oldest un-acked chunk.
//
// Other record types use the legacy best-effort path (popServerNow), which has no
// retransmission and therefore no window, but is now chunked to the capacity of the
// record type instead of a fixed 32 bytes.
//
// A chunk that stays unacked past dnsTunnelDownstreamGiveUp is abandoned: it is
// dropped from serverOut and serverSkipTo tells the client to expect the next seq.
// Accepting a gap is what stops one repeatedly-dropped response from stalling the
// entire stream forever.
func (s *dnsSession) serveDownstream(qtype uint16, qname string, udpBudget int) []byte {
	noise := s.noiseSession != nil && s.noiseSession.SendCipher != nil
	if qtype != dns.TypeTXT {
		// A/AAAA answers hold exactly one address, which cannot carry a framed,
		// authenticated payload. Serve nothing rather than ship a truncated
		// ciphertext the client can only reject.
		if noise && (qtype == dns.TypeA || qtype == dns.TypeAAAA) {
			return nil
		}
		return s.popServerNow(maxDownstreamPayloadBudget(qtype, noise, qname, udpBudget), noise)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	// Abandon chunks the client never acked within the give-up window.
	for len(s.serverOut) > 0 {
		oldest := oldestDownstreamSeq(s.serverOut)
		if time.Since(s.serverOut[oldest].firstSent) <= dnsTunnelDownstreamGiveUp {
			break
		}
		delete(s.serverOut, oldest)
		s.serverSkipTo = oldest + 1
	}

	// Window has room and there is fresh data: hand the poll a new chunk. Each
	// concurrent poll takes a distinct chunk because serverOut grows under s.mu.
	//
	// The chunk is sized against the response budget: a data query echoes the
	// upstream chunk label in the answer, so it can carry less downstream data than
	// a poll can, and overshooting the negotiated UDP size loses the whole datagram.
	maxPayload := maxDownstreamPayloadBudget(dns.TypeTXT, noise, qname, udpBudget)
	if maxPayload > 0 && len(s.serverOut) < dnsTunnelDownstreamWindow && s.serverBuf.Len() > 0 {
		avail := maxPayload
		if s.serverBuf.Len() < avail {
			avail = s.serverBuf.Len()
		}
		out := make([]byte, avail)
		_, _ = s.serverBuf.Read(out)
		s.serverCond.Signal()
		seq := s.serverNext
		s.serverNext++
		s.serverOut[seq] = &downstreamChunk{
			ct:        s.sealDownstream(seq, out),
			firstSent: time.Now(),
		}
		return encodeDownstreamFrame(seq, s.serverSkipTo, s.serverOut[seq].ct)
	}

	if len(s.serverOut) > 0 {
		// Window full (or nothing fresh to send): refill the oldest gap. The frame
		// is rebuilt each time so retransmissions carry the current skipTo.
		oldest := oldestDownstreamSeq(s.serverOut)
		return encodeDownstreamFrame(oldest, s.serverSkipTo, s.serverOut[oldest].ct)
	}
	return nil
}

// popServerNow serves one best-effort chunk for non-TXT record types, chunked to the
// capacity of the record type. With Noise the payload is sealed under the sequence
// number and the 4-byte header in front of it lets the client rebuild the nonce.
func (s *dnsSession) popServerNow(max int, noise bool) []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.serverBuf.Len() == 0 {
		return nil
	}
	avail := s.serverBuf.Len()
	if avail > max {
		avail = max
	}
	out := make([]byte, avail)
	_, _ = s.serverBuf.Read(out)
	s.serverCond.Signal()
	atomic.StoreInt64(&s.lastActive, time.Now().Unix())

	if !noise {
		return out
	}
	seq := s.serverNext
	s.serverNext++
	ct := s.sealDownstream(seq, out)
	frame := make([]byte, nonTxtNoiseHeaderSize+len(ct))
	binary.BigEndian.PutUint32(frame[:nonTxtNoiseHeaderSize], seq)
	copy(frame[nonTxtNoiseHeaderSize:], ct)
	return frame
}

func (s *dnsSession) close() {
	s.closeOnce.Do(func() {
		s.mu.Lock()
		s.closed = true
		if s.tcpConn != nil {
			_ = s.tcpConn.Close()
		}
		if s.udpConn != nil {
			_ = s.udpConn.Close()
		}
		s.readCond.Broadcast()
		s.serverCond.Broadcast()
		s.mu.Unlock()
	})
}

func parseTargetNetworkAndAddr(raw string) (network, addr string) {
	raw = strings.TrimSpace(raw)
	if strings.HasPrefix(raw, "udp://") {
		return "udp", strings.TrimPrefix(raw, "udp://")
	}
	if strings.HasPrefix(raw, "tcp://") {
		return "tcp", strings.TrimPrefix(raw, "tcp://")
	}
	return "tcp", raw
}

// NewDNSServer builds the tunnel DNS handler. Use this when embedding the handler
// in an externally managed dns.Server; most callers want NewServer instead.
func NewDNSServer(cfg ServerConfig) (*DNSServer, error) {
	log := cfg.Logger
	if log == nil {
		log = nopLogger
	}
	srv := &DNSServer{
		cfg:          cfg,
		domain:       dns.Fqdn(cfg.Domain),
		domainLabels: len(dns.SplitDomainName(cfg.Domain)),
		edns0:        cfg.EDNS0,
		sessions:     make(map[string]*dnsSession),
		log:          log,
	}
	if cfg.PrivateKey != "" {
		k, err := ParseNoiseKey(cfg.PrivateKey)
		if err != nil {
			return nil, fmt.Errorf("dnstunnel: failed to parse Noise private key: %w", err)
		}
		srv.privKey = k
		srv.hasPrivKey = true
		srv.log.Infof("🔐 Loaded Noise static private key, Noise_NK encryption enabled")
	}
	return srv, nil
}

func (s *DNSServer) getOrCreateSession(sessionID string, seq uint32, initialData []byte, allowCreate bool) (*dnsSession, bool) {
	s.mu.RLock()
	if sess, ok := s.sessions[sessionID]; ok {
		s.mu.RUnlock()
		sess.updateActive()
		return sess, false
	}
	s.mu.RUnlock()
	if !allowCreate {
		return nil, false
	}

	// Key derivation is intentionally outside the global sessions lock. A new
	// Noise handshake is relatively expensive and must not stall unrelated
	// sessions that only need a map lookup.
	targetNet, targetAddr := parseTargetNetworkAndAddr(s.cfg.TargetAddr)
	// The session ID marker marks a legacy datagram session (old DialUDP clients
	// never declare a target). The effective transport is resolved by a target
	// declaration query; absent one, the configured default target applies. The
	// backend is dialed lazily on the first data chunk, so a declaration that
	// follows the Noise handshake still applies.
	wantsDatagram := strings.HasPrefix(sessionID, udpSessionPrefix)
	var noiseSess *NoiseSession
	var initialPayload []byte
	if s.hasPrivKey {
		if len(initialData) < 32 {
			s.log.Warnf("[%s] First packet missing 32-byte Noise ephemeral public key, rejecting", sessionID)
			return nil, false
		}
		ePub := initialData[:32]
		var err error
		noiseSess, err = NewServerNoiseSession(s.privKey, ePub)
		if err != nil {
			s.log.Warnf("[%s] Noise session handshake failed: %v", sessionID, err)
			return nil, false
		}
		if len(initialData) > 32 {
			initialPayload = initialData[32:]
		}
		s.log.Infof("[%s] 🔐 Established Noise_NK encrypted channel", sessionID)
	}

	sess := newDnsSession(sessionID, targetNet, targetAddr, wantsDatagram, noiseSess, s.log)

	if s.hasPrivKey {
		sess.pushClient(seq, initialPayload)
		// The handshake query used this dataSeq, so the next upstream data chunk is
		// expected at dataSeq+1 regardless of whether the handshake carried a payload.
		sess.mu.Lock()
		sess.clientNext = seq + 1
		sess.mu.Unlock()
	}

	// Two first packets for the same ID may derive candidates concurrently.
	// Publish only one and discard the other before either starts a backend.
	s.mu.Lock()
	if existing, ok := s.sessions[sessionID]; ok {
		s.mu.Unlock()
		existing.updateActive()
		return existing, false
	}
	// Enforce the concurrent-session cap at publish time, so a flood of new
	// session IDs cannot grow the map (and its per-session buffers) unbounded.
	if s.cfg.MaxSessions > 0 && len(s.sessions) >= s.cfg.MaxSessions {
		s.mu.Unlock()
		s.log.Warnf("[%s] Rejected: session limit reached (%d)", sessionID, s.cfg.MaxSessions)
		return nil, false
	}
	s.sessions[sessionID] = sess
	s.mu.Unlock()
	s.log.Infof("[%s] 🆕 Created session -> default Target: [%s] %s", sessionID, targetNet, targetAddr)
	return sess, true
}

// setTarget applies a client-declared target to a session that has not dialed
// its backend yet. A legacy datagram session (UDP marker) may only declare udp
// targets: datagram semantics cannot reach a stream backend. Returns the
// decision plus the target that actually applies.
func (s *dnsSession) setTarget(network, addr string) (byte, string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.backendStarted {
		if s.declared && s.targetNetwork == network && s.targetAddr == addr {
			return targetStatusOK, s.targetNetwork // identical retransmit of the declaration
		}
		return targetStatusDeny, s.targetNetwork
	}
	if s.declared {
		if s.targetNetwork == network && s.targetAddr == addr {
			return targetStatusOK, s.targetNetwork
		}
		return targetStatusDeny, s.targetNetwork
	}
	if s.wantsDatagram && network != "udp" {
		s.log.Warnf("[%s] Declared tcp target on a datagram session is not permitted", s.sessionID)
		return targetStatusDeny, s.targetNetwork
	}
	s.targetNetwork = network
	s.targetAddr = addr
	s.declared = true
	s.framedUDP = s.wantsDatagram || network == "udp"
	return targetStatusOK, network
}

// startBackendOnce flips the lazy-dial latch; the caller spawns the forwarder
// when it returns true.
func (s *dnsSession) startBackendOnce() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.backendStarted {
		return false
	}
	s.backendStarted = true
	return true
}

// startBackendForwarder dials the session's resolved backend and pumps bytes in
// both directions. It runs lazily on the first data chunk, after any target
// declaration has been applied.
func (s *DNSServer) startBackendForwarder(sess *dnsSession) {
	sess.mu.Lock()
	network, addr, framed, wantsDatagram := sess.targetNetwork, sess.targetAddr, sess.framedUDP, sess.wantsDatagram
	sess.mu.Unlock()

	// A legacy datagram session (UDP marker, no declaration) against a tcp://
	// target cannot work: datagram semantics cannot reach a stream backend.
	// Refuse instead of silently sending datagrams at a TCP port.
	if wantsDatagram && network != "udp" {
		sess.log.Warnf("[%s] Refused datagram session: target %q is not udp:// (client transport and server target must match, or declare a target)", sess.sessionID, addr)
		sess.close()
		return
	}

	if network == "udp" {
		conn, err := net.Dial("udp", addr)
		if err != nil {
			sess.log.Errorf("[%s] Failed to connect to UDP target (%s): %v", sess.sessionID, addr, err)
			sess.close()
			return
		}
		sess.mu.Lock()
		sess.udpConn = conn
		sess.mu.Unlock()

		sess.log.Infof("[%s] 🔗 Connected to UDP target (%s)", sess.sessionID, addr)

		if framed {
			s.startUDPFramedForwarder(sess, conn)
		} else {
			s.startUDPLegacyForwarder(sess, conn)
		}
		return
	}

	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		sess.log.Errorf("[%s] Failed to connect to TCP target (%s): %v", sess.sessionID, addr, err)
		sess.close()
		return
	}
	sess.mu.Lock()
	sess.tcpConn = conn
	sess.mu.Unlock()

	sess.log.Infof("[%s] 🔗 Connected to TCP target (%s)", sess.sessionID, addr)

	go func() {
		defer sess.close()
		buf := make([]byte, 4096)
		for {
			sess.mu.Lock()
			for sess.clientBuf.Len() == 0 && !sess.closed {
				sess.waitForClientData()
			}
			if sess.closed {
				sess.mu.Unlock()
				return
			}
			n, _ := sess.clientBuf.Read(buf)
			sess.mu.Unlock()

			if n > 0 {
				if _, err := conn.Write(buf[:n]); err != nil {
					sess.log.Warnf("[%s] Write to target failed: %v", sess.sessionID, err)
					return
				}
			}
		}
	}()

	go func() {
		defer sess.close()
		buf := make([]byte, 4096)
		for {
			n, err := conn.Read(buf)
			if n > 0 {
				if !sess.pushServer(buf[:n]) {
					return
				}
			}
			if err != nil {
				if err != io.EOF && !strings.Contains(err.Error(), "use of closed network connection") {
					sess.log.Warnf("[%s] Target connection disconnected: %v", sess.sessionID, err)
				}
				return
			}
		}
	}()
}

// startUDPLegacyForwarder forwards the session byte stream to a UDP backend without
// datagram framing (pre-UDP-dial behavior, kept for compatibility with older
// clients). Datagram boundaries are not preserved in this mode.
func (s *DNSServer) startUDPLegacyForwarder(sess *dnsSession, conn net.Conn) {
	go func() {
		defer sess.close()
		buf := make([]byte, 4096)
		for {
			sess.mu.Lock()
			for sess.clientBuf.Len() == 0 && !sess.closed {
				sess.waitForClientData()
			}
			if sess.closed {
				sess.mu.Unlock()
				return
			}
			n, _ := sess.clientBuf.Read(buf)
			sess.mu.Unlock()

			if n > 0 {
				if _, err := conn.Write(buf[:n]); err != nil {
					sess.log.Warnf("[%s] Write to UDP target failed: %v", sess.sessionID, err)
					return
				}
			}
		}
	}()

	s.pumpUDPToSession(sess, conn, false)
}

// startUDPFramedForwarder carries length-framed UDP datagrams in both directions:
// each upstream frame becomes exactly one datagram at the backend, and each
// datagram the backend sends becomes one downstream frame.
func (s *DNSServer) startUDPFramedForwarder(sess *dnsSession, conn net.Conn) {
	go func() {
		defer sess.close()
		for {
			dgram, ok := sess.readFramedFromClient()
			if !ok {
				return
			}
			if _, err := conn.Write(dgram); err != nil {
				sess.log.Warnf("[%s] Write to UDP target failed: %v", sess.sessionID, err)
				return
			}
		}
	}()

	s.pumpUDPToSession(sess, conn, true)
}

// pumpUDPToSession reads datagrams from the backend and pushes them into the
// downstream byte stream. Framed sessions wrap each datagram in a length prefix
// so boundaries survive; the legacy stream mode pushes raw bytes, matching
// pre-UDP-dial behavior.
func (s *DNSServer) pumpUDPToSession(sess *dnsSession, conn net.Conn, framed bool) {
	go func() {
		defer sess.close()
		buf := make([]byte, udpFrameMaxDatagram)
		for {
			n, err := conn.Read(buf)
			if n > 0 {
				out := buf[:n]
				if framed {
					out = encodeUDPFrame(out)
				}
				if !sess.pushServer(out) {
					return
				}
			}
			if err != nil {
				if err != io.EOF && !strings.Contains(err.Error(), "use of closed network connection") {
					sess.log.Warnf("[%s] UDP target connection error: %v", sess.sessionID, err)
				}
				return
			}
		}
	}()
}

func (s *DNSServer) ServeDNS(w dns.ResponseWriter, req *dns.Msg) {
	reply := new(dns.Msg)
	if len(req.Question) == 0 {
		reply.SetRcode(req, dns.RcodeServerFailure)
		_ = w.WriteMsg(reply)
		return
	}
	q := req.Question[0]
	sessionID, _, ack, dataSeq, flag, data, err := parseQueryNameForDomain(s.domain, s.domainLabels, q.Name)
	if err != nil {
		s.log.Debugf("Non-tunnel query or parse failed: %s (%v)", q.Name, err)
		reply.SetRcode(req, dns.RcodeNameError)
		_ = w.WriteMsg(reply)
		return
	}

	// A target declaration may be the session's very first packet: without Noise
	// it creates the session shell; with Noise the handshake must come first, so
	// unknown IDs are refused and the client retries after the handshake lands.
	if flag == flagTarget {
		sess, _ := s.getOrCreateSession(sessionID, 0, nil, !s.hasPrivKey)
		if sess == nil {
			reply.SetRcode(req, dns.RcodeNameError)
			_ = w.WriteMsg(reply)
			return
		}
		sess.freeDownstream(ack)
		s.serveTargetDeclaration(w, req, reply, sess, data)
		return
	}

	// Poll and close queries for an unknown ID must not allocate a session or
	// dial the configured backend. Only a data packet can establish state.
	sess, isNew := s.getOrCreateSession(sessionID, dataSeq, data, flag == flagData && len(data) > 0)
	if sess == nil {
		reply.SetRcode(req, dns.RcodeNameError)
		_ = w.WriteMsg(reply)
		return
	}

	if flag == flagData && len(data) > 0 {
		// The first Noise handshake query already delivered its payload inside
		// getOrCreateSession; do not deliver it a second time. The backend dial
		// also waits for real data: a target declaration may still follow the
		// Noise handshake, and it must apply before the connection is made.
		if !(isNew && s.hasPrivKey) {
			sess.pushClient(dataSeq, data)
			if sess.startBackendOnce() {
				go s.startBackendForwarder(sess)
			}
		}
	} else if flag == flagClose {
		s.log.Infof("[%s] Received client close signal", sessionID)
		s.mu.Lock()
		if s.sessions[sessionID] == sess {
			delete(s.sessions, sessionID)
		}
		s.mu.Unlock()
		sess.close()
	}

	// Release downstream chunks the client has confirmed receiving (drives retransmit buffer).
	sess.freeDownstream(ack)

	reply.SetReply(req)
	reply.Authoritative = true
	reply.RecursionAvailable = false

	udpBudget := dnsTunnelMaxUDPResponse
	if s.edns0 {
		// Echo the client's OPT with our advertised size so resolvers forward the
		// larger datagram. The chunk is sized against the negotiated budget, not
		// the client's announcement, so a lying OPT cannot grow our answers.
		if opt := req.IsEdns0(); opt != nil {
			reply.SetEdns0(dnsTunnelEDNS0UDPSize, false)
			udpBudget = dnsTunnelEDNS0UDPSize
		}
	}

	downstreamData := sess.serveDownstream(q.Qtype, q.Name, udpBudget)
	if len(downstreamData) > 0 {
		rr := makeAnswer(q.Name, q.Qtype, downstreamData, s.domain)
		if rr != nil {
			reply.Answer = append(reply.Answer, rr)
		}
	}

	if err := w.WriteMsg(reply); err != nil {
		s.log.Warnf("[%s] Failed to send DNS reply: %v", sessionID, err)
	}
}

// serveTargetDeclaration handles a flag 'T' query: decrypt (when Noise is on),
// validate against the allow list, apply to the session and answer with
// [status][udpMarker]. The answer is always 2 plaintext bytes so it fits every
// record type and leaks nothing but the transport.
func (s *DNSServer) serveTargetDeclaration(w dns.ResponseWriter, req, reply *dns.Msg, sess *dnsSession, data []byte) {
	q := req.Question[0]
	payload := data
	if s.hasPrivKey {
		if sess.noiseSession == nil {
			// The Noise handshake has not landed yet; the client retries after it.
			reply.SetRcode(req, dns.RcodeNameError)
			_ = w.WriteMsg(reply)
			return
		}
		dec, err := sess.noiseSession.RecvCipher.Decrypt(uint64(dnsTunnelControlSeq), data)
		if err != nil {
			s.log.Warnf("[%s] Target declaration decryption failed: %v", sess.sessionID, err)
			reply.SetRcode(req, dns.RcodeNameError)
			_ = w.WriteMsg(reply)
			return
		}
		payload = dec
	}

	addr, wantUDP, ok := decodeTargetRequest(payload)
	if !ok {
		reply.SetRcode(req, dns.RcodeNameError)
		_ = w.WriteMsg(reply)
		return
	}

	// An empty declaration asks "what is the default target?"; a non-empty one
	// must pass the allow list before it may replace the default.
	status := byte(targetStatusOK)
	if addr != "" {
		network := "tcp"
		if wantUDP {
			network = "udp"
		}
		if !targetAllowed(s.cfg.AllowTargets, network, addr) {
			s.log.Warnf("[%s] Target %s://%s denied by allow_targets", sess.sessionID, network, addr)
			status = targetStatusDeny
		} else if st, _ := sess.setTarget(network, addr); st != targetStatusOK {
			status = st
		}
	}

	sess.mu.Lock()
	udp := sess.targetNetwork == "udp"
	effectiveNet, effectiveAddr := sess.targetNetwork, sess.targetAddr
	sess.mu.Unlock()
	if status == targetStatusOK {
		s.log.Infof("[%s] Target resolved: [%s] %s (declared=%v)", sess.sessionID, effectiveNet, effectiveAddr, addr != "")
	}

	reply.SetReply(req)
	reply.Authoritative = true
	if rr := makeAnswer(q.Name, q.Qtype, encodeTargetResponse(status, udp), s.domain); rr != nil {
		reply.Answer = append(reply.Answer, rr)
	}
	_ = w.WriteMsg(reply)
}

func (s *DNSServer) cleanupLoop(ctx context.Context) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			now := time.Now().Unix()
			var stale []*dnsSession
			s.mu.Lock()
			for id, sess := range s.sessions {
				if now-atomic.LoadInt64(&sess.lastActive) > 120 {
					s.log.Infof("[%s] Session inactive for > 120s, cleaning up", id)
					delete(s.sessions, id)
					stale = append(stale, sess)
				}
			}
			s.mu.Unlock()
			for _, sess := range stale {
				sess.close()
			}
		}
	}
}
