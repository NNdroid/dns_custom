package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	mrand "math/rand"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
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

func newDNSPath(server string) *dnsPath {
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
		p.httpCli = &http.Client{Timeout: 4 * time.Second}
	} else {
		p.dnsCli = &dns.Client{Net: p.network, Timeout: 4 * time.Second}
	}
	return p
}

// acquire returns a warm socket, dialing one if the pool is empty.
func (p *dnsPath) acquire() (*dns.Conn, error) {
	select {
	case co := <-p.pool:
		return co, nil
	default:
	}
	return p.dnsCli.Dial(p.addr)
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
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	reply := new(dns.Msg)
	if err := reply.Unpack(body); err != nil {
		return nil, err
	}
	return reply, nil
}

type ClientConfig struct {
	ListenAddr string   `json:"listen"`
	Domain     string   `json:"domain"`
	Servers    []string `json:"servers"`
	RecordType string   `json:"record_type"`
	PublicKey  string   `json:"pubkey"`
	LogLevel   string   `json:"log_level"`
}

type DNSClientTunnel struct {
	ctx          context.Context
	cancel       context.CancelFunc
	servers      []string
	domain       string
	qtype        uint16
	session      string
	chunkSize    int
	pollInterval time.Duration

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
}

func NewDNSClientTunnel(ctx context.Context, servers []string, domain string, recordType string, pubKeyStr string) (*DNSClientTunnel, error) {
	if domain == "" || len(servers) == 0 {
		return nil, fmt.Errorf("domain and servers are required")
	}
	qtype, err := dnsTypeToQType(recordType)
	if err != nil {
		return nil, err
	}
	paths := make([]*dnsPath, 0, len(servers))
	for _, srv := range servers {
		paths = append(paths, newDNSPath(srv))
	}
	cctx, cancel := context.WithCancel(ctx)
	t := &DNSClientTunnel{
		ctx:          cctx,
		cancel:       cancel,
		servers:      servers,
		domain:       dns.Fqdn(domain),
		qtype:        qtype,
		session:      fmt.Sprintf("%x", mrand.Uint64()),
		chunkSize:    dnsTunnelDefaultChunk,
		pollInterval: dnsTunnelPollInterval,
		inBuf:        new(bytes.Buffer),
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
			return nil, fmt.Errorf("record type %q cannot carry authenticated Noise frames (A/AAAA hold 4/16 bytes); use txt/null/cname/mx/srv/ns", recordType)
		}
		pk, err := ParseNoiseKey(pubKeyStr)
		if err != nil {
			cancel()
			return nil, fmt.Errorf("invalid server public key: %w", err)
		}
		ns, ePub, err := NewClientNoiseSession(pk)
		if err != nil {
			cancel()
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
			return nil, fmt.Errorf("noise handshake exchange failed: %w", hsErr)
		}
		zlog.Infof("🔐 Established Noise_NK encryption session with server")
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

// sendQuery sends one tunnel query to a single upstream server and feeds any answer
// payload into the downstream reassembly. It returns the number of downstream bytes
// that became available to Read.
//
// Queries are no longer serialized globally: the only ordering requirement used to be
// the AEAD nonce, and that is now derived from the sequence number carried by the
// query/frame itself.
func (t *DNSClientTunnel) sendQuery(pathIdx int, flag byte, wirePayload []byte, dataSeq uint32) (int, error) {
	if t.closed.Load() {
		return 0, net.ErrClosed
	}

	seq := atomic.AddUint32(&t.seq, 1)
	name := buildQueryName(t.domain, t.session, seq, atomic.LoadUint32(&t.ack), dataSeq, flag, wirePayload)

	m := new(dns.Msg)
	m.SetQuestion(name, t.qtype)
	m.RecursionDesired = false
	m.Id = uint16(seq)

	resp, err := t.paths[pathIdx].exchange(t.ctx, m)
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
	// "best" RTT would make every later sample look fast and pin the window at its
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

	if t.bestRTT == 0 || int64(rtt) < best {
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
				zlog.Warnf("Short TXT frame (%d bytes) cannot be authenticated, dropped", len(raw))
				return 0
			}
			return t.writeInBuf(raw)
		}

		payload := tail
		if noise {
			dec, err := t.noiseSession.RecvCipher.Decrypt(uint64(serverSeq), tail)
			if err != nil {
				zlog.Warnf("Downstream frame serverSeq=%d failed to decrypt: %v", serverSeq, err)
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
		var out []byte
		if seqLess(serverSeq, t.recvNext) {
			// duplicate, already delivered in order
		} else if serverSeq == t.recvNext {
			out = append(out, payload...)
			t.recvNext++
		} else if _, exists := t.recvOOO[serverSeq]; !exists {
			t.recvOOO[serverSeq] = append([]byte(nil), payload...)
		}
		out = append(out, t.drainRecvOOO()...)
		atomic.StoreUint32(&t.ack, t.recvNext-1)
		t.recvMu.Unlock()

		return t.writeInBuf(out)
	}

	// Non-TXT: best-effort delivery.
	if noise {
		if len(raw) < nonTxtNoiseHeaderSize {
			return 0
		}
		seq := binary.BigEndian.Uint32(raw[:nonTxtNoiseHeaderSize])
		dec, err := t.noiseSession.RecvCipher.Decrypt(uint64(seq), raw[nonTxtNoiseHeaderSize:])
		if err != nil {
			zlog.Warnf("Downstream chunk seq=%d failed to decrypt: %v", seq, err)
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

// drainRecvOOO returns the contiguous run of buffered chunks starting at recvNext.
// Caller must hold t.recvMu.
func (t *DNSClientTunnel) drainRecvOOO() []byte {
	var out []byte
	for {
		c, ok := t.recvOOO[t.recvNext]
		if !ok {
			return out
		}
		out = append(out, c...)
		delete(t.recvOOO, t.recvNext)
		t.recvNext++
	}
}

// pollLoop keeps one upstream path busy: it polls, hands any answer to the reassembly,
// and paces itself. Data-bearing polls pipeline; empty polls back off. It also pauses
// while the reader has not drained what was already fetched, so a slow consumer cannot
// make the tunnel hoard answers.
func (t *DNSClientTunnel) pollLoop(idx int) {
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
			t.sleep(t.pollInterval)
			continue
		}

		n, err := t.sendQuery(idx, flagPoll, nil, 0)
		switch {
		case err != nil:
			t.markPathFailed(idx)
			t.sleep(t.pollInterval)
		case n > 0:
			t.markPathHealthy(idx)
			t.sleep(dnsTunnelPollBusyInterval)
		default:
			t.markPathHealthy(idx)
			t.sleep(t.pollInterval)
		}
	}
}

func (t *DNSClientTunnel) sleep(d time.Duration) {
	select {
	case <-t.ctx.Done():
	case <-t.closeCh:
	case <-time.After(d):
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
	if t.closed.Load() {
		return 0, net.ErrClosed
	}
	total := len(p)

	type chunkJob struct {
		seq  uint32
		data []byte
	}
	var jobs []chunkJob
	for len(p) > 0 {
		n := len(p)
		if n > t.chunkSize {
			n = t.chunkSize
		}
		jobs = append(jobs, chunkJob{seq: atomic.AddUint32(&t.dataSeq, 1), data: p[:n]})
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
	var sentBytes int

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
				sentBytes += len(job.data)
				mu.Unlock()
			}
		}()
	}
	wg.Wait()

	if firstErr != nil {
		return sentBytes, firstErr
	}
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
	_, _ = newDNSPath(t.servers[t.nextServer()]).exchange(ctx, m)
}

func runClient(ctx context.Context, cfg ClientConfig) {
	initLogger(cfg.LogLevel)
	defer zlog.Sync()

	zlog.Infof("🚀 Starting dns_custom client v%s", Version)
	zlog.Infof("🎧 Listening locally on TCP %s", cfg.ListenAddr)
	zlog.Infof("🌐 Upstream DNS Servers: %v (Domain: %s, Type: %s)", cfg.Servers, cfg.Domain, cfg.RecordType)

	ln, err := net.Listen("tcp", cfg.ListenAddr)
	if err != nil {
		zlog.Fatalf("Failed to listen on %s: %v", cfg.ListenAddr, err)
	}
	defer ln.Close()

	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()

	for {
		c, err := ln.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return
			default:
				zlog.Errorf("Accept failed: %v", err)
				continue
			}
		}

		go func(conn net.Conn) {
			defer conn.Close()
			tunnel, err := NewDNSClientTunnel(ctx, cfg.Servers, cfg.Domain, cfg.RecordType, cfg.PublicKey)
			if err != nil {
				zlog.Errorf("Failed to establish DNS tunnel: %v", err)
				return
			}
			defer tunnel.Close()

			go func() {
				_, _ = io.Copy(tunnel, conn)
				_ = tunnel.Close()
			}()
			_, _ = io.Copy(conn, tunnel)
		}(c)
	}
}
