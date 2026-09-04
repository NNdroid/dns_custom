package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
)

const dnsTunnelServerBufferLimit = 512 * 1024

type ServerConfig struct {
	ListenAddr string `json:"listen"`
	TargetAddr string `json:"target"`
	Domain     string `json:"domain"`
	PrivateKey string `json:"privkey"`
	LogLevel   string `json:"log_level"`
}

type DNSServer struct {
	cfg          ServerConfig
	domain       string
	domainLabels int
	sessions     map[string]*dnsSession
	mu           sync.RWMutex
	privKey      [32]byte
	hasPrivKey   bool
}

type dnsSession struct {
	sessionID     string
	targetNetwork string
	targetAddr    string
	tcpConn       net.Conn
	udpConn       net.Conn
	noiseSession  *NoiseSession
	clientBuf     *bytes.Buffer
	serverBuf     *bytes.Buffer
	mu            sync.Mutex
	readCond      *sync.Cond
	serverCond    *sync.Cond // wakes a backend reader when downstream buffer space is freed
	pumpWaiting   bool       // true while the backend pump is blocked in readCond.Wait
	lastActive    int64
	closed        bool
	closeOnce     sync.Once

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

func newDnsSession(sessionID, targetNetwork, targetAddr string, noiseSess *NoiseSession) *dnsSession {
	sess := &dnsSession{
		sessionID:     sessionID,
		targetNetwork: targetNetwork,
		targetAddr:    targetAddr,
		noiseSession:  noiseSess,
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
			zlog.Warnf("[%s] Noise decryption failed for dataSeq=%d: %v", s.sessionID, seq, err)
			return
		}
		payload = dec
	}

	// Reliable-ordered reassembly: drop duplicates, buffer out-of-order chunks,
	// and deliver to the backend strictly in dataSeq order.
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
func (s *dnsSession) serveDownstream(qtype uint16, qname string) []byte {
	noise := s.noiseSession != nil && s.noiseSession.SendCipher != nil
	if qtype != dns.TypeTXT {
		// A/AAAA answers hold exactly one address, which cannot carry a framed,
		// authenticated payload. Serve nothing rather than ship a truncated
		// ciphertext the client can only reject.
		if noise && (qtype == dns.TypeA || qtype == dns.TypeAAAA) {
			return nil
		}
		return s.popServerNow(maxDownstreamPayload(qtype, noise, qname), noise)
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
	// a poll can, and overshooting 512 bytes of UDP loses the whole datagram.
	maxPayload := maxDownstreamPayload(dns.TypeTXT, noise, qname)
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

func NewDNSServer(cfg ServerConfig) *DNSServer {
	srv := &DNSServer{
		cfg:          cfg,
		domain:       dns.Fqdn(cfg.Domain),
		domainLabels: len(dns.SplitDomainName(cfg.Domain)),
		sessions:     make(map[string]*dnsSession),
	}
	if cfg.PrivateKey != "" {
		k, err := ParseNoiseKey(cfg.PrivateKey)
		if err == nil {
			srv.privKey = k
			srv.hasPrivKey = true
			zlog.Infof("🔐 Loaded Noise static private key, Noise_NK encryption enabled")
		} else {
			zlog.Fatalf("❌ Failed to parse Noise private key: %v", err)
		}
	}
	return srv
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
	var noiseSess *NoiseSession
	var initialPayload []byte
	if s.hasPrivKey {
		if len(initialData) < 32 {
			zlog.Warnf("[%s] First packet missing 32-byte Noise ephemeral public key, rejecting", sessionID)
			return nil, false
		}
		ePub := initialData[:32]
		var err error
		noiseSess, err = NewServerNoiseSession(s.privKey, ePub)
		if err != nil {
			zlog.Warnf("[%s] Noise session handshake failed: %v", sessionID, err)
			return nil, false
		}
		if len(initialData) > 32 {
			initialPayload = initialData[32:]
		}
		zlog.Infof("[%s] 🔐 Established Noise_NK encrypted channel", sessionID)
	}

	sess := newDnsSession(sessionID, targetNet, targetAddr, noiseSess)

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
	s.sessions[sessionID] = sess
	s.mu.Unlock()
	zlog.Infof("[%s] 🆕 Created session -> Target: [%s] %s", sessionID, targetNet, targetAddr)

	go s.startBackendForwarder(sess)
	return sess, true
}

func (s *DNSServer) startBackendForwarder(sess *dnsSession) {
	if sess.targetNetwork == "udp" {
		conn, err := net.Dial("udp", sess.targetAddr)
		if err != nil {
			zlog.Errorf("[%s] Failed to connect to UDP target (%s): %v", sess.sessionID, sess.targetAddr, err)
			sess.close()
			return
		}
		sess.mu.Lock()
		sess.udpConn = conn
		sess.mu.Unlock()

		zlog.Infof("[%s] 🔗 Connected to UDP target (%s)", sess.sessionID, sess.targetAddr)

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
						zlog.Warnf("[%s] Write to UDP target failed: %v", sess.sessionID, err)
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
					return
				}
			}
		}()
		return
	}

	conn, err := net.DialTimeout("tcp", sess.targetAddr, 5*time.Second)
	if err != nil {
		zlog.Errorf("[%s] Failed to connect to TCP target (%s): %v", sess.sessionID, sess.targetAddr, err)
		sess.close()
		return
	}
	sess.mu.Lock()
	sess.tcpConn = conn
	sess.mu.Unlock()

	zlog.Infof("[%s] 🔗 Connected to TCP target (%s)", sess.sessionID, sess.targetAddr)

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
					zlog.Warnf("[%s] Write to target failed: %v", sess.sessionID, err)
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
					zlog.Warnf("[%s] Target connection disconnected: %v", sess.sessionID, err)
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
		zlog.Debugf("Non-tunnel query or parse failed: %s (%v)", q.Name, err)
		reply.SetRcode(req, dns.RcodeNameError)
		_ = w.WriteMsg(reply)
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
		// getOrCreateSession; do not deliver it a second time.
		if !(isNew && s.hasPrivKey) {
			sess.pushClient(dataSeq, data)
		}
	} else if flag == flagClose {
		zlog.Infof("[%s] Received client close signal", sessionID)
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

	downstreamData := sess.serveDownstream(q.Qtype, q.Name)
	if len(downstreamData) > 0 {
		rr := makeAnswer(q.Name, q.Qtype, downstreamData, s.domain)
		if rr != nil {
			reply.Answer = append(reply.Answer, rr)
		}
	}

	if err := w.WriteMsg(reply); err != nil {
		zlog.Warnf("[%s] Failed to send DNS reply: %v", sessionID, err)
	}
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
					zlog.Infof("[%s] Session inactive for > 120s, cleaning up", id)
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

func runServer(ctx context.Context, cfg ServerConfig) {
	initLogger(cfg.LogLevel)
	defer zlog.Sync()

	netType, target := parseTargetNetworkAndAddr(cfg.TargetAddr)
	zlog.Infof("🚀 Starting dns_custom server v%s", Version)
	zlog.Infof("📡 Listening on UDP %s (Authoritative Domain: %s)", cfg.ListenAddr, cfg.Domain)
	zlog.Infof("🎯 Forwarding Target: [%s] %s", netType, target)

	srv := NewDNSServer(cfg)
	go srv.cleanupLoop(ctx)

	udpServer := &dns.Server{
		Addr:    cfg.ListenAddr,
		Net:     "udp",
		Handler: srv,
	}

	tcpServer := &dns.Server{
		Addr:    cfg.ListenAddr,
		Net:     "tcp",
		Handler: srv,
	}

	go func() {
		if err := udpServer.ListenAndServe(); err != nil {
			zlog.Fatalf("UDP Server exited with error: %v", err)
		}
	}()

	go func() {
		if err := tcpServer.ListenAndServe(); err != nil {
			zlog.Fatalf("TCP Server exited with error: %v", err)
		}
	}()

	<-ctx.Done()
	zlog.Info("Shutting down DNS servers...")
	_ = udpServer.Shutdown()
	_ = tcpServer.Shutdown()
}
