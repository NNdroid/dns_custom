package dnstunnel

import (
	"bytes"
	"context"
	"errors"
	"io"
	mrandv2 "math/rand/v2"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// weakLinkProfile is one degraded network to benchmark the tunnel against.
//
// Every knob is applied on both legs of the path and per packet, independently
// in each direction, so a profile is symmetric the way a real link is.
type weakLinkProfile struct {
	// name labels the sub-benchmark and appears in the CSV and JSON output.
	name string
	// payload is how much stream data one iteration moves. It is tuned per
	// profile, not global: a transfer of N bytes at dnsTunnelDefaultChunk costs
	// about N/chunk round trips divided by the in-flight window, so a 500 ms RTT
	// profile needs a smaller payload than a clean one to stay inside a sane
	// wall-clock budget.
	payload int
	// oneWay is the fixed delay injected on each leg, so a round trip costs 2*oneWay.
	oneWay time.Duration
	// jitter is extra delay drawn uniformly over [0, jitter] for every packet.
	jitter time.Duration
	// loss is the independent per-packet drop probability, per leg. Because the
	// knobs apply to both directions, a datagram that must cross the link twice
	// survives with probability (1-loss)^2, so 10%% loss costs about 19%% of
	// round trips and 50%% loss leaves only a quarter of them.
	loss float64
	// duplicate is the probability a packet is delivered a second time. Real
	// networks do this after a lost ACK or a middlebox retry.
	duplicate float64
	// reorder is the probability a packet is held back for an extra round trip
	// and arrives after packets sent after it.
	reorder float64
	// bitsPerSecond caps both directions with a shared token bucket; 0 is uncapped.
	bitsPerSecond int
}

// decide reports the delivery plan for one packet: one delay per copy that
// should be forwarded, or nothing at all when the packet is dropped.
func (p weakLinkProfile) decide(r *mrandv2.Rand) []time.Duration {
	base := p.oneWay
	if p.jitter > 0 {
		base += time.Duration(r.Uint64() % uint64(p.jitter+1))
	}
	out := []time.Duration{base}
	if p.duplicate > 0 && r.Float64() < p.duplicate {
		out = append(out, base)
	}
	if p.reorder > 0 && r.Float64() < p.reorder {
		out = append(out, base+p.oneWay*2)
	}
	if p.loss > 0 && r.Float64() < p.loss {
		return nil
	}
	return out
}

// tokenBucket is a leaky bucket shared by every flow in one direction, so the
// cap models the link's capacity rather than a per-connection quota.
type tokenBucket struct {
	mu      sync.Mutex
	rate    float64 // bytes per second; 0 = uncapped
	burst   float64 // bytes admitted before pacing kicks in; 0 = one second's worth
	tokens  float64
	last    time.Time
}

// capacity is the most credit the bucket ever holds, so a burst of datagrams can
// go out before the rate is enforced at all.
func (b *tokenBucket) capacity() float64 {
	if b.burst > 0 {
		return b.burst
	}
	return b.rate
}

// pace blocks until n bytes have been admitted. It sleeps at most once per
// call: re-sleeping inside a loop until the bucket refills turns timer
// resolution into an indefinite stall, and a relay that silently stops
// delivering looks exactly like a link with no throughput at all.
func (b *tokenBucket) pace(n int, closed <-chan struct{}) {
	if b.rate <= 0 || n <= 0 {
		return
	}
	need := float64(n)
	b.mu.Lock()
	now := time.Now()
	capacity := b.capacity()
	if b.last.IsZero() {
		b.last = now
		b.tokens = capacity
	}
	b.tokens += now.Sub(b.last).Seconds() * b.rate
	if b.tokens > capacity {
		b.tokens = capacity
	}
	b.last = now

	var wait time.Duration
	if need <= b.tokens {
		b.tokens -= need
		b.mu.Unlock()
		return
	}
	// Not enough credit: the missing bytes are produced at b.rate, so wait
	// exactly that long. The consumed credit is charged against the bucket and
	// the clock is parked at the wake time, so the next call recharges from
	// the right point instead of double-counting the wait.
	shortfall := need - b.tokens
	b.tokens = 0
	wait = time.Duration(shortfall/b.rate*float64(time.Second))
	b.last = now.Add(wait)
	b.mu.Unlock()

	if wait <= 0 {
		return
	}
	t := time.NewTimer(wait)
	defer t.Stop()
	select {
	case <-t.C:
	case <-closed:
	}
}

// weakLink stands between a tunnel client and a DNS server and degrades the
// path in both directions.
//
// It is a real UDP relay rather than a net.Conn wrapper: the client under test
// dials, pools and retransmits exactly as it would against a live resolver, so
// the numbers come from the tunnel's own loss handling instead of from a stub
// that pre-empted it. Each distinct client socket gets its own socket toward
// the backend, so replies come back on the socket they were sent from and the
// relay never has to guess which pooled connection owns which answer.
//
// Reading and pacing are deliberately separate goroutines. Pacing inline with
// the read loop stalls the drain, the kernel receive buffer overflows and the
// OS drops datagrams of its own - loss the profile never asked for, which would
// be read as tunnel behaviour in the results.
type weakLink struct {
	profile   weakLinkProfile
	front     net.PacketConn
	backendIP *net.UDPAddr
	up        tokenBucket // front -> backend
	down      tokenBucket // backend -> front
	upQueue   chan linkDelivery
	downQueue chan linkDelivery

	rngMu sync.Mutex
	rng   *mrandv2.Rand

	mu    sync.Mutex
	flows map[string]*weakFlow

	closed       chan struct{}
	frontStopped chan struct{}
	wg           sync.WaitGroup
	closeOnce    sync.Once
}

// linkDelivery is one datagram awaiting its paced, delayed forwarding.
type linkDelivery struct {
	to  net.PacketConn
	dst *net.UDPAddr
	pkt []byte
	dly []time.Duration
}

// weakFlow is one client socket relayed through the link.
type weakFlow struct {
	from net.Addr
	back net.PacketConn
}

// weakLinkSockBuf is the kernel buffer asked of every relay socket.
const weakLinkSockBuf = 1 << 20

// weakLinkBurstBytes is the credit a rate-limited link admits before it starts
// pacing. One datagram is all a real link bursts, so the sustained rate is what
// the benchmark measures; a one-second allowance would let half of a modest
// transfer cross free and the cap would read as twice as fast as it is.
const weakLinkBurstBytes = 512

// widenPacketBuffer raises the kernel receive and transmit buffers of a UDP
// socket when the platform exposes them. A bursty sender otherwise overruns the
// socket's receive window and the kernel drops datagrams outright - loss that
// no profile declared, which would otherwise be mistaken for tunnel behaviour.
// The no-op fallback is deliberate: the knobs are a best effort.
func widenPacketBuffer(pc net.PacketConn, bytes int) {
	type bufferSetter interface {
		SetReadBuffer(int) error
		SetWriteBuffer(int) error
	}
	b, ok := pc.(bufferSetter)
	if !ok {
		return
	}
	_ = b.SetReadBuffer(bytes)
	_ = b.SetWriteBuffer(bytes)
}

// startWeakLink puts a degraded hop in front of the backend address and
// returns the link; link.Addr is what the tunnel should point at.
func startWeakLink(b testing.TB, profile weakLinkProfile, backend string) *weakLink {
	b.Helper()
	front, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		b.Fatalf("weak link listen failed: %v", err)
	}
	widenPacketBuffer(front, weakLinkSockBuf)
	backendIP, err := net.ResolveUDPAddr("udp", backend)
	if err != nil {
		b.Fatalf("weak link backend address %q: %v", backend, err)
	}
	bps := float64(profile.bitsPerSecond) / 8
	l := &weakLink{
		profile:      profile,
		front:        front,
		backendIP:    backendIP,
		upQueue:      make(chan linkDelivery, 1024),
		downQueue:    make(chan linkDelivery, 1024),
		flows:        make(map[string]*weakFlow),
		rng:          mrandv2.New(mrandv2.NewPCG(1, 0x5EED)),
		closed:       make(chan struct{}),
		frontStopped: make(chan struct{}),
	}
	l.up.rate, l.up.burst = bps, weakLinkBurstBytes
	l.down.rate, l.down.burst = bps, weakLinkBurstBytes
	b.Cleanup(l.close)
	l.wg.Add(3)
	go l.serveFront()
	go l.writeQueued(l.upQueue, &l.up)
	go l.writeQueued(l.downQueue, &l.down)
	return l
}

// Addr is the address a tunnel client should use as its upstream.
func (l *weakLink) Addr() string { return l.front.LocalAddr().String() }

func (l *weakLink) decide() []time.Duration {
	l.rngMu.Lock()
	defer l.rngMu.Unlock()
	return l.profile.decide(l.rng)
}

// sleep is cancellation-aware so teardown never waits out a pending injection.
func (l *weakLink) sleep(d time.Duration) {
	if d <= 0 {
		return
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
	case <-l.closed:
	}
}

func (l *weakLink) serveFront() {
	defer func() {
		close(l.frontStopped)
		l.wg.Done()
	}()
	buf := make([]byte, 65536)
	for {
		n, from, err := l.front.ReadFrom(buf)
		if err != nil {
			return
		}
		pkt := make([]byte, n)
		copy(pkt, buf[:n])
		f := l.flowFor(from)
		select {
		case l.upQueue <- linkDelivery{to: f.back, dst: l.backendIP, pkt: pkt, dly: l.decide()}:
		case <-l.closed:
			return
		}
	}
}

func (l *weakLink) flowFor(from net.Addr) *weakFlow {
	l.mu.Lock()
	defer l.mu.Unlock()
	if f, ok := l.flows[from.String()]; ok {
		return f
	}
	back, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		// Loopback with an ephemeral port: unreachable in a test.
		panic("weak link back socket: " + err.Error())
	}
	widenPacketBuffer(back, weakLinkSockBuf)
	f := &weakFlow{from: from, back: back}
	l.flows[from.String()] = f
	l.wg.Add(1)
	go l.collectFromBackend(f)
	return f
}

// collectFromBackend reads the DNS server's answers off the flow's socket
// without ever waiting on the pacing, so the kernel buffer drains continuously.
func (l *weakLink) collectFromBackend(f *weakFlow) {
	defer l.wg.Done()
	buf := make([]byte, 65536)
	for {
		select {
		case <-l.closed:
			return
		default:
		}
		n, _, err := f.back.ReadFrom(buf)
		if err != nil {
			return
		}
		pkt := make([]byte, n)
		copy(pkt, buf[:n])
		select {
		case l.downQueue <- linkDelivery{to: l.front, dst: f.from.(*net.UDPAddr), pkt: pkt, dly: l.decide()}:
		case <-l.closed:
			return
		}
	}
}

// writeQueued paces one direction: every datagram waits its share of the
// shared bucket and its own injection delay before it is handed to the wire.
func (l *weakLink) writeQueued(q <-chan linkDelivery, bucket *tokenBucket) {
	defer l.wg.Done()
	for {
		select {
		case d := <-q:
			for _, dly := range d.dly {
				bucket.pace(len(d.pkt), l.closed)
				l.sleep(dly)
				if !writeUDP(l.closed, d.to, d.dst, d.pkt) {
					return
				}
			}
		case <-l.closed:
			return
		}
	}
}

// writeUDP retries a transient UDP write and reports whether the datagram got
// out. Windows surfaces a datagram that is still draining from a previous write
// as an error rather than blocking, so a relay or echo that dies on the first
// failure silently drops every later datagram.
func writeUDP(shutdown <-chan struct{}, to net.PacketConn, dst net.Addr, pkt []byte) bool {
	for i := 0; i < 400; i++ {
		select {
		case <-shutdown:
			return false
		default:
		}
		if _, err := to.WriteTo(pkt, dst); err == nil {
			return true
		} else if errors.Is(err, net.ErrClosed) {
			return false
		}
		time.Sleep(time.Millisecond)
	}
	return false
}

func (l *weakLink) close() {
	l.closeOnce.Do(func() {
		close(l.closed)
		_ = l.front.Close()
		<-l.frontStopped
		l.mu.Lock()
		for _, f := range l.flows {
			_ = f.back.Close()
		}
		l.mu.Unlock()
		l.wg.Wait()
	})
}

// weakLinkProfiles orders the sweeps from cheapest to most degraded so a
// failure names the first profile that breaks.
//
// Payload size is tuned per profile, not shared: the client retransmits a lost
// chunk only after its DNS query times out, and that timeout is a fixed 4 s
// regardless of the path's latency. So a lost chunk costs 4 s of wall clock and
// the number of chunks a degraded profile can afford is bounded by
//
//	payload / 32 * loss^2 * 4s / window ≲ iteration budget
//
// which is why the high-loss profiles carry small payloads. Payloads are still
// multi-chunk, so the window, reorder buffer and retransmit path are exercised
// rather than a single round trip.
var weakLinkProfiles = []weakLinkProfile{
	{name: "clean", payload: 32 << 10},
	{name: "3g", payload: 2 << 10, oneWay: 75 * time.Millisecond, loss: 0.02},
	{name: "4g", payload: 2 << 10, oneWay: 40 * time.Millisecond, loss: 0.01},
	{name: "badWifi", payload: 1 << 10, oneWay: 15 * time.Millisecond, jitter: 40 * time.Millisecond, loss: 0.05},
	{name: "congested", payload: 512, oneWay: 250 * time.Millisecond, loss: 0.10},
	{name: "lossy", payload: 2 << 10, loss: 0.10},
	{name: "reordered", payload: 2 << 10, oneWay: 15 * time.Millisecond, reorder: 0.25},
	{name: "duplicated", payload: 2 << 10, duplicate: 0.30},
	{name: "2mbit", payload: 4 << 10, bitsPerSecond: 2 * 1000 * 1000},
	{name: "512kbit", payload: 4 << 10, bitsPerSecond: 512 * 1000},
}

// weakLinkIterationTimeout bounds one iteration so a profile that the tunnel
// cannot survive fails fast with a message instead of hanging the CI job.
const weakLinkIterationTimeout = 60 * time.Second

// benchmarkWeakLink transfers one payload through a degraded DNS hop, checks
// it came back intact and reports how fast the tunnel actually got there. The
// session is opened inside the timed region, like the latency sweep, so the
// figure includes the handshake and target declaration a real client pays.
func benchmarkWeakLink(b *testing.B, p weakLinkProfile) {
	echoLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		b.Fatalf("echo listen failed: %v", err)
	}
	b.Cleanup(func() { _ = echoLn.Close() })
	go func() {
		for {
			conn, err := echoLn.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_, _ = io.Copy(c, c)
			}(conn)
		}
	}()

	domain := "weaklink.bench.local"
	srv, err := NewDNSServer(ServerConfig{Domain: domain, TargetAddr: echoLn.Addr().String()})
	if err != nil {
		b.Fatal(err)
	}
	link := startWeakLink(b, p, startTestDNSServer(b, srv))

	payload := make([]byte, p.payload)
	for i := range payload {
		payload[i] = byte(i)
	}
	recv := make([]byte, p.payload)

	var retries atomic.Int64
	var firstWindow int

	// The session context must outlive the handshake: cancelling it the moment
	// the tunnel is constructed makes the tunnel tear itself down, so the first
	// Write fails with a closed connection. The write and read deadlines below
	// are what bound a stuck iteration.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	b.SetBytes(int64(p.payload))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ev := newEventDispatcher[ClientEvent](func(c ClientEvent) {
			if c.Kind == ClientReconnecting {
				retries.Add(1)
			}
		})
		tunnel, err := newDNSClientTunnel(ctx, []string{link.Addr()}, domain, "txt", "", "", "", "", false, nopLogger, nil, nil, ev, nil)
		if err != nil {
			ev.close()
			b.Fatalf("session setup over %s failed: %v", p.name, err)
		}
		deadline := time.Now().Add(weakLinkIterationTimeout)
		if err := tunnel.SetWriteDeadline(deadline); err != nil {
			ev.close()
			_ = tunnel.Close()
			b.Fatal(err)
		}
		if err := tunnel.SetReadDeadline(deadline); err != nil {
			ev.close()
			_ = tunnel.Close()
			b.Fatal(err)
		}
		if _, err := tunnel.Write(payload); err != nil {
			ev.close()
			_ = tunnel.Close()
			b.Fatalf("write over %s failed: %v", p.name, err)
		}
		if _, err := io.ReadFull(tunnel, recv); err != nil {
			ev.close()
			_ = tunnel.Close()
			b.Fatalf("read over %s failed: %v", p.name, err)
		}
		if !bytes.Equal(recv, payload) {
			ev.close()
			_ = tunnel.Close()
			b.Fatalf("payload corrupted over %s", p.name)
		}
		if i == 0 {
			firstWindow = tunnel.upstreamWindow()
		}
		ev.close()
		_ = tunnel.Close()
	}
	b.StopTimer()

	if b.N > 0 {
		b.ReportMetric(float64(retries.Load())/float64(b.N), "retries")
		b.ReportMetric(float64(firstWindow), "window")
	}
}

// BenchmarkWeakLink sweeps the tunnel over a spread of degraded DNS paths.
// Throughput in ops/sec with SetBytes gives effective goodput; "retries" is the
// number of retransmitted upstream chunks per iteration and "window" is the
// adaptive in-flight window the sweep settled at.
func BenchmarkWeakLink(b *testing.B) {
	for _, p := range weakLinkProfiles {
		p := p
		b.Run(p.name, func(bb *testing.B) { benchmarkWeakLink(bb, p) })
	}
}

// weakLinkEchoBackend is a bare UDP echo for the simulator's own unit test.
func weakLinkEchoBackend(b testing.TB) string {
	b.Helper()
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		b.Fatalf("udp echo listen failed: %v", err)
	}
	done := make(chan struct{})
	b.Cleanup(func() {
		close(done)
		_ = conn.Close()
	})
	go func() {
		buf := make([]byte, 65536)
		for {
			select {
			case <-done:
				return
			default:
			}
			n, raddr, err := conn.ReadFrom(buf)
			if err != nil {
				return
			}
			if !writeUDP(done, conn, raddr, buf[:n]) {
				return
			}
		}
	}()
	return conn.LocalAddr().String()
}

// weakLinkRoundTrip drives the relay with a bare UDP echo backend and counts
// the datagrams that come back, so a degradation knob is observed on the wire
// instead of trusted by convention. It returns as soon as minCollect
// datagrams are in, so the deterministic cases do not wait out the deadline;
// only a profile that drops everything pays it.
func weakLinkRoundTrip(t *testing.T, p weakLinkProfile, packets int, minCollect int, deadline time.Duration) int {
	t.Helper()
	link := startWeakLink(t, p, weakLinkEchoBackend(t))
	defer link.close()
	src, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer src.Close()
	dst, err := net.ResolveUDPAddr("udp", link.Addr())
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < packets; i++ {
		if _, err := src.WriteTo([]byte{byte(i)}, dst); err != nil {
			t.Fatal(err)
		}
	}
	buf := make([]byte, 65536)
	src.SetReadDeadline(time.Now().Add(deadline))
	got := 0
	for {
		n, _, err := src.ReadFrom(buf)
		if err != nil {
			break
		}
		if n > 0 {
			got++
			if minCollect > 0 && got >= minCollect {
				return got
			}
		}
	}
	return got
}

// TestWeakLinkAppliesEveryDegradationMode pins down the simulator itself. The
// weak-link benchmarks are only as trustworthy as this relay, so each knob is
// checked against the wire instead of being trusted by convention.
func TestWeakLinkAppliesEveryDegradationMode(t *testing.T) {
	if got := weakLinkRoundTrip(t, weakLinkProfile{loss: 1}, 50, 1, 300*time.Millisecond); got != 0 {
		t.Errorf("100%% loss: %d datagrams delivered, want 0", got)
	}
	if got := weakLinkRoundTrip(t, weakLinkProfile{duplicate: 1}, 50, 100, 5*time.Second); got != 100 {
		t.Errorf("100%% duplicate: %d datagrams delivered, want 100", got)
	}
	if got := weakLinkRoundTrip(t, weakLinkProfile{}, 50, 50, 5*time.Second); got != 50 {
		t.Errorf("clean link: %d datagrams delivered, want 50", got)
	}
	// A probabilistic knob gets a band, not an equality. 50%% loss is applied
	// per leg, so only a quarter of a two-hop round trip survives: 200 datagrams
	// give 50 with a standard deviation of 6, and 20..80 is roughly five sigma.
	if got := weakLinkRoundTrip(t, weakLinkProfile{loss: 0.5}, 200, 0, 3*time.Second); got < 20 || got > 80 {
		t.Errorf("50%% loss per leg: %d of 200 round trips survived, want roughly 50", got)
	}
}

// TestWeakLinkInjectsDelayAndReorder checks the timing knobs, which a datagram
// counter alone cannot see.
func TestWeakLinkInjectsDelayAndReorder(t *testing.T) {
	t.Run("delay", func(t *testing.T) {
		link := startWeakLink(t, weakLinkProfile{oneWay: 60 * time.Millisecond}, weakLinkEchoBackend(t))
		defer link.close()
		src, err := net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		widenPacketBuffer(src, weakLinkSockBuf)
		defer src.Close()
		dst, err := net.ResolveUDPAddr("udp", link.Addr())
		if err != nil {
			t.Fatal(err)
		}
		start := time.Now()
		if _, err := src.WriteTo([]byte("ping"), dst); err != nil {
			t.Fatal(err)
		}
		buf := make([]byte, 64)
		src.SetReadDeadline(time.Now().Add(10 * time.Second))
		if _, _, err := src.ReadFrom(buf); err != nil {
			t.Fatalf("no reply: %v", err)
		}
		if rt := time.Since(start); rt < 120*time.Millisecond {
			t.Errorf("round trip %v shorter than the 120 ms injected", rt)
		}
	})

	t.Run("reorder", func(t *testing.T) {
		// A 100% reorder rate delivers every datagram twice: once on time and
		// once a round trip late. Sending 20 packets at 5 ms spacing into a
		// 20 ms path means the second copy of an early packet always lands
		// after several later ones, so a repeat payload is proof of reordering.
		link := startWeakLink(t, weakLinkProfile{oneWay: 20 * time.Millisecond, reorder: 1}, weakLinkEchoBackend(t))
		defer link.close()
		src, err := net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer src.Close()
		dst, err := net.ResolveUDPAddr("udp", link.Addr())
		if err != nil {
			t.Fatal(err)
		}
		for i := 0; i < 20; i++ {
			pkt := make([]byte, 8)
			pkt[0] = byte(i)
			if _, err := src.WriteTo(pkt, dst); err != nil {
				t.Fatal(err)
			}
			time.Sleep(5 * time.Millisecond)
		}
		buf := make([]byte, 64)
		seen := make([]bool, 256)
		got := 0
		repeats := 0
		src.SetReadDeadline(time.Now().Add(10 * time.Second))
		for {
			n, _, err := src.ReadFrom(buf)
			if err != nil {
				break
			}
			if n == 0 {
				continue
			}
			got++
			v := int(buf[0])
			if seen[v] {
				repeats++
			}
			seen[v] = true
			if repeats > 0 {
				break
			}
		}
		if repeats == 0 {
			t.Errorf("reorder rate of 1 delivered %d datagrams in order, want an out-of-order arrival", got)
		}
	})
}

// TestWeakLinkRateLimits measures the token bucket, the one knob that cannot
// be checked by counting datagrams. UDP writes are non-blocking, so the cap
// shows up in the transfer's wall-clock time rather than in the sender's loop.
func TestWeakLinkRateLimits(t *testing.T) {
	const (
		bps     = 512 * 1000
		size    = 512
		packets = 256 // 128 KiB total
	)
	link := startWeakLink(t, weakLinkProfile{bitsPerSecond: bps}, weakLinkEchoBackend(t))
	defer link.close()
	src, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	defer func() {
		close(done)
		_ = src.Close()
	}()
	dst, err := net.ResolveUDPAddr("udp", link.Addr())
	if err != nil {
		t.Fatal(err)
	}

	pkt := make([]byte, size)
	buf := make([]byte, 65536)
	src.SetReadDeadline(time.Now().Add(20 * time.Second))

	// Send in small windows, the way the tunnel keeps its in-flight window
	// bounded. A raw 128 KiB burst would overrun the local send buffer and the
	// kernel would drop datagrams of its own, which is not what a bandwidth cap
	// means and would be mistaken for one.
	const window = 8
	start := time.Now()
	got := 0
	for i := 0; i < packets; i += window {
		end := min(i+window, packets)
		for j := i; j < end; j++ {
			if !writeUDP(done, src, dst, pkt) {
				t.Fatalf("could not send datagram %d of %d", j+1, packets)
			}
		}
		for got < end {
			n, _, err := src.ReadFrom(buf)
			if err != nil {
				t.Fatalf("no reply after %d of %d datagrams: %v", got, packets, err)
			}
			if n > 0 {
				got++
			}
		}
	}
	elapsed := time.Since(start)
	if got != packets {
		t.Fatalf("got %d of %d echoed datagrams back", got, packets)
	}
	// 128 KiB each way at 64 KiB/s is about 2 s of pacing no matter how the
	// windows overlap, so anything well under that means the cap is not being
	// applied at all, and anything much over it means the relay stalled.
	least := 1500 * time.Millisecond
	if elapsed < least {
		t.Errorf("128 KiB crossed the %d kbit/s link in %v, want at least about %v of pacing",
			bps/1000, elapsed, least)
	}
	if elapsed > 10*time.Second {
		t.Errorf("128 KiB crossed the %d kbit/s link in %v, the relay stalled", bps/1000, elapsed)
	}
	t.Logf("128 KiB over a %d kbit/s link in %v (effective %.0f kbit/s per direction)",
		bps/1000, elapsed, float64(size)*8*float64(packets)/elapsed.Seconds()/1000)
}

// TestTokenBucketPaces pins the bucket in isolation. It is the guard against the
// failure that silently killed the rate-limited profiles: a pacing loop that
// re-sleeps until the bucket refills never returns at all, and a relay that
// stops forwarding looks identical to a link with zero throughput.
func TestTokenBucketPaces(t *testing.T) {
	b := tokenBucket{rate: 64000, burst: 512}
	closed := make(chan struct{})
	const (
		size    = 512
		packets = 256 // 128 KiB
	)
	t0 := time.Now()
	for i := 0; i < packets; i++ {
		b.pace(size, closed)
	}
	elapsed := time.Since(t0)
	want := time.Duration(float64(size*packets-512)/64000*float64(time.Second))
	t.Logf("128 KiB through a 64 KiB/s bucket in %v, want about %v",
		elapsed.Round(time.Millisecond), want.Round(time.Millisecond))
	if elapsed < want-200*time.Millisecond {
		t.Errorf("128 KiB crossed a 64 KiB/s bucket in %v, want about %v", elapsed, want)
	}
	if elapsed > want+2*time.Second {
		t.Errorf("128 KiB crossed a 64 KiB/s bucket in %v, want about %v", elapsed, want)
	}
}
