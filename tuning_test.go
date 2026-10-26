package dnstunnel

import (
	"context"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// countingHandler wraps a dns.Handler and counts every query it serves, so a
// poll cadence can be asserted by counting instead of timing.
type countingHandler struct {
	inner dns.Handler
	n     *atomic.Int64
}

func (h *countingHandler) ServeDNS(w dns.ResponseWriter, req *dns.Msg) {
	h.n.Add(1)
	h.inner.ServeDNS(w, req)
}

func TestExchangeTimeoutPropagates(t *testing.T) {
	for _, tc := range []struct {
		label  string
		server string
	}{
		{"udp", "udp://127.0.0.1:53"},
		{"tcp", "tcp://127.0.0.1:53"},
		{"dot", "dot://127.0.0.1:853"},
		{"doh", "https://resolver.example/dns-query"},
	} {
		t.Run(tc.label, func(t *testing.T) {
			want := 750 * time.Millisecond
			p := newDNSPath(tc.server, nil, nil, want)
			defer p.close()
			if tc.label == "doh" {
				if p.httpCli == nil {
					t.Fatal("DoH path has no http.Client")
				}
				if p.httpCli.Timeout != want {
					t.Fatalf("DoH timeout = %v, want %v", p.httpCli.Timeout, want)
				}
				return
			}
			if p.dnsCli == nil {
				t.Fatal("non-DoH path has no dns.Client")
			}
			if p.dnsCli.Timeout != want {
				t.Fatalf("%s timeout = %v, want %v", tc.label, p.dnsCli.Timeout, want)
			}
		})
	}
}

func TestClientConfigTiming(t *testing.T) {
	base := ClientConfig{Domain: "tune.local", Servers: []string{"127.0.0.1:53"}, RecordType: "txt"}

	zero, err := NewClient(base)
	if err != nil {
		t.Fatal(err)
	}
	if zero.exchangeTimeout != dnsTunnelExchangeTimeout || zero.pollInterval != dnsTunnelPollInterval {
		t.Fatalf("defaults = (exchange %v, poll %v), want (%v, %v)",
			zero.exchangeTimeout, zero.pollInterval, dnsTunnelExchangeTimeout, dnsTunnelPollInterval)
	}

	explicit := base
	explicit.ExchangeTimeout = 900 * time.Millisecond
	explicit.PollInterval = 25 * time.Millisecond
	set, err := NewClient(explicit)
	if err != nil {
		t.Fatal(err)
	}
	if set.exchangeTimeout != 900*time.Millisecond || set.pollInterval != 25*time.Millisecond {
		t.Fatalf("explicit = (exchange %v, poll %v), want (900ms, 25ms)", set.exchangeTimeout, set.pollInterval)
	}

	negExchange := base
	negExchange.ExchangeTimeout = -time.Second
	if _, err := NewClient(negExchange); err == nil {
		t.Fatal("negative exchange_timeout was accepted")
	}
	negPoll := base
	negPoll.PollInterval = -time.Second
	if _, err := NewClient(negPoll); err == nil {
		t.Fatal("negative poll_interval was accepted")
	}
}

func TestAdaptiveExchangeTimeout(t *testing.T) {
	tests := []struct {
		name    string
		limit   time.Duration
		bestRTT time.Duration
		want    time.Duration
	}{
		{"no sample yet waits the floor, not the ceiling", 4 * time.Second, 0, dnsTunnelExchangeMinTimeout},
		{"a lowered ceiling still wins while unmeasured", 300 * time.Millisecond, 0, 300 * time.Millisecond},
		{"the first measurement already clamps", 4 * time.Second, 75 * time.Millisecond, 75 * time.Millisecond * dnsTunnelExchangeRTTFactor},
		{"floor beats an implausibly fast path", 4 * time.Second, time.Millisecond, dnsTunnelExchangeMinTimeout},
		{"clamped to the measured round trip", 4 * time.Second, 200 * time.Millisecond, 200 * time.Millisecond * dnsTunnelExchangeRTTFactor},
		{"the configured ceiling still wins", 4 * time.Second, time.Second, 4 * time.Second},
		{"a lowered ceiling is respected", 1 * time.Second, 200 * time.Millisecond, 1 * time.Second},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tun := &DNSClientTunnel{exchangeTimeout: tc.limit}
			if tc.bestRTT > 0 {
				tun.bestRTT.Store(int64(tc.bestRTT))
			}
			if got := tun.adaptiveExchangeTimeout(); got != tc.want {
				t.Fatalf("adaptiveExchangeTimeout() = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestObserveRTT holds bestRTT to a running minimum of successful round trips.
// adaptiveExchangeTimeout is only as good as bestRTT: a spurious sub-microsecond
// minimum would pin the exchange wait at the floor and turn every queued query
// into a retry.
func TestObserveRTT(t *testing.T) {
	tun := &DNSClientTunnel{}

	tun.observeRTT(900 * time.Millisecond)
	if got := tun.bestRTT.Load(); got != int64(900*time.Millisecond) {
		t.Fatalf("bestRTT = %v, want the first successful sample", got)
	}

	tun.observeRTT(time.Second) // slower than the current best: ignored
	if got := tun.bestRTT.Load(); got != int64(900*time.Millisecond) {
		t.Fatalf("bestRTT = %v after a slower sample, want the minimum kept", got)
	}

	tun.observeRTT(400 * time.Millisecond)
	if got := tun.bestRTT.Load(); got != int64(400*time.Millisecond) {
		t.Fatalf("bestRTT = %v after a faster sample, want the lower value", got)
	}

	// Once a real minimum exists, a degenerate reading must not be allowed to pin
	// it down further.
	for _, junk := range []time.Duration{0, -time.Millisecond} {
		tun.observeRTT(junk)
	}
	if got := tun.bestRTT.Load(); got != int64(400*time.Millisecond) {
		t.Fatalf("bestRTT = %v after zero and negative samples, want the minimum kept", got)
	}
}

// TestFreshSessionClampsFromFirstExchange covers the case that made the adaptive
// timeout appear to have no effect under load. bestRTT starts empty, and observeRTT
// drops the zero round trips that show up when a reply is already sitting in the
// socket buffer - observed in under one monotonic clock tick. On a heavily loaded
// machine the session's first successful exchange is often exactly such a sample, so
// bestRTT could stay empty for the whole session. With an unmeasured session waiting
// the ceiling that meant every loss cost four seconds; it now waits the floor.
func TestFreshSessionClampsFromFirstExchange(t *testing.T) {
	tun := &DNSClientTunnel{exchangeTimeout: dnsTunnelExchangeTimeout}

	if got := tun.adaptiveExchangeTimeout(); got != dnsTunnelExchangeMinTimeout {
		t.Fatalf("adaptiveExchangeTimeout() = %v before any sample, want the floor %v", got, dnsTunnelExchangeMinTimeout)
	}

	// A reply already in the receive buffer reads as a zero round trip. It must not
	// be recorded as a new best, and it must not push the wait back to the ceiling.
	tun.observeRTT(0)
	if got := time.Duration(tun.bestRTT.Load()); got != 0 {
		t.Fatalf("bestRTT = %v after a zero sample, want no measurement recorded", got)
	}
	if got := tun.adaptiveExchangeTimeout(); got != dnsTunnelExchangeMinTimeout {
		t.Fatalf("adaptiveExchangeTimeout() = %v after a zero sample, want the floor %v", got, dnsTunnelExchangeMinTimeout)
	}

	// A real measurement of the path's latency clamps the wait to the path itself.
	tun.observeRTT(200 * time.Millisecond)
	if got := tun.adaptiveExchangeTimeout(); got != 200*time.Millisecond*dnsTunnelExchangeRTTFactor {
		t.Fatalf("adaptiveExchangeTimeout() = %v after a 200ms sample, want %v", got, 200*time.Millisecond*dnsTunnelExchangeRTTFactor)
	}
}

func TestRetryDelay(t *testing.T) {
	tests := []struct {
		attempt int
		want    time.Duration
	}{
		{0, 0}, // the exchange already waited a full timeout; do not wait again
		{1, 400 * time.Millisecond},
		{2, 800 * time.Millisecond},
		{3, 1600 * time.Millisecond},
		{4, dnsTunnelMaxRetryBackoff},
		{5, dnsTunnelMaxRetryBackoff}, // capped, and never grows past the cap
	}
	for _, tc := range tests {
		if got := retryDelay(tc.attempt); got != tc.want {
			t.Errorf("retryDelay(%d) = %v, want %v", tc.attempt, got, tc.want)
		}
	}
}

func TestEdns0EffectiveNeedsAuthentication(t *testing.T) {
	tests := []struct {
		name  string
		edns0 bool
		psk   []byte
		noise bool
		want  bool
	}{
		{"edns0 off", false, []byte("secret"), true, false},
		{"edns0 on, anonymous", true, nil, false, false},
		{"edns0 on, psk", true, []byte("secret"), false, true},
		{"edns0 on, noise", true, nil, true, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tun := &DNSClientTunnel{edns0: tc.edns0, pskKey: tc.psk}
			if tc.noise {
				tun.noiseSession = &NoiseSession{}
			}
			if got := tun.edns0Effective(); got != tc.want {
				t.Fatalf("edns0Effective() = %v, want %v", got, tc.want)
			}
		})
	}
}

// newTuningTunnel opens one session against a fresh tunnel server and returns it
// plus a counter over every DNS query the server receives.
func newTuningTunnel(t *testing.T, opts ...tunnelOption) (*DNSClientTunnel, *atomic.Int64) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_, _ = io.Copy(c, c)
			}(c)
		}
	}()

	srv, err := NewDNSServer(ServerConfig{Domain: "tune.local", TargetAddr: ln.Addr().String()})
	if err != nil {
		t.Fatal(err)
	}
	n := new(atomic.Int64)
	addr := startTestDNSServer(t, &countingHandler{inner: srv, n: n})

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	tun, err := newDNSClientTunnel(ctx, []string{addr}, "tune.local", "txt", "", "", "", "", false, nopLogger, nil, nil, nil, nil, opts...)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = tun.Close() })
	return tun, n
}

// TestExchangeWaitClampedBeforeFirstByte is the regression guard for the adaptive
// exchange timeout. A session's very first data query can be the one the link drops,
// and the handshake and target probe that precede it do not always measure a usable
// round trip: a reply already sitting in the receive buffer can be observed in under
// one monotonic clock tick, and such a reading is dropped rather than recorded. A
// session whose setup never produced a sample must therefore still come out of setup
// with the wait clamped below the ceiling, or every early loss costs four seconds.
func TestExchangeWaitClampedBeforeFirstByte(t *testing.T) {
	tun, _ := newTuningTunnel(t)

	if got := tun.adaptiveExchangeTimeout(); got >= tun.exchangeTimeout {
		t.Fatalf("adaptiveExchangeTimeout() = %v, ceiling = %v, bestRTT = %v; the wait must already be clamped before the first byte",
			got, tun.exchangeTimeout, time.Duration(tun.bestRTT.Load()))
	}
	// With nothing measured the wait is the floor exactly - not the ceiling.
	if got, want := tun.bestRTT.Load(), tun.adaptiveExchangeTimeout(); got <= 0 {
		if time.Duration(want) != dnsTunnelExchangeMinTimeout {
			t.Fatalf("adaptiveExchangeTimeout() = %v with no measurement, want the floor %v", want, dnsTunnelExchangeMinTimeout)
		}
	}
}

func TestPollIntervalDrivesPollRate(t *testing.T) {
	const window = 900 * time.Millisecond

	fast, fastN := newTuningTunnel(t, withPollInterval(20*time.Millisecond))
	slow, slowN := newTuningTunnel(t, withPollInterval(400*time.Millisecond))
	if fast.pollInterval != 20*time.Millisecond || slow.pollInterval != 400*time.Millisecond {
		t.Fatalf("pollInterval not applied: fast=%v slow=%v", fast.pollInterval, slow.pollInterval)
	}

	time.Sleep(window)

	fastQ, slowQ := fastN.Load(), slowN.Load()
	// 400ms per poll against 20ms is a 20x gap, so no scheduler can invert this.
	if fastQ <= slowQ {
		t.Fatalf("fast session sent %d queries, slow session sent %d; poll_interval had no effect", fastQ, slowQ)
	}
}
