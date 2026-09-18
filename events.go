package dnstunnel

import (
	"crypto/hmac"
	"crypto/sha256"
	"strings"
	"sync"
)

// Client events. Handlers are dispatched on a dedicated goroutine with a panic
// guard per event: they may drive business logic, but they can never block the
// tunnel's send/receive loops — publishing an event never waits on a handler
// and never touches the data path.
type ClientEventKind int

const (
	// ClientTunnelEstablished fires once per session, after the Noise
	// handshake, target declaration and pollers are all in place.
	ClientTunnelEstablished ClientEventKind = iota
	// ClientTunnelDied fires when the session dies (or is closed). The Reason
	// field explains which; Err carries the underlying error, if any.
	ClientTunnelDied
	// ClientReconnecting fires on every retry of an upstream chunk after its
	// first attempt failed. Attempt is the 1-based retry number. The session
	// usually survives; a permanent failure is followed by TunnelDied.
	ClientReconnecting
	// ClientTargetDenied fires when the server's allow list refused the
	// declared target; the Dial call returns the same condition as an error.
	ClientTargetDenied
)

func (k ClientEventKind) String() string {
	switch k {
	case ClientTunnelEstablished:
		return "TunnelEstablished"
	case ClientTunnelDied:
		return "TunnelDied"
	case ClientReconnecting:
		return "Reconnecting"
	case ClientTargetDenied:
		return "TargetDenied"
	default:
		return "unknown"
	}
}

// Common TunnelDied reasons carried in ClientEvent.Reason.
const (
	ReasonCallerClosed      = "closed by caller"
	ReasonWriteFailed       = "write failed"
	ReasonWriteTimeout      = "write deadline exceeded"
	ReasonCtxCancelled      = "context cancelled"
	ReasonServerSessionGone = "server session no longer exists"
	// ReasonMaxRetries is retained for source compatibility. Current clients
	// retry transient transport failures until a deadline or cancellation.
	ReasonMaxRetries = "write failed after max retries"
)

// ClientEvent describes one lifecycle occurrence on a client tunnel session.
type ClientEvent struct {
	Kind      ClientEventKind
	Session   string // tunnel session ID
	Target    string // declared backend, "" = server default
	Transport string // confirmed backend transport ("tcp"/"udp"), "" = unknown
	Reason    string // TunnelDied: why the session died
	Attempt   int    // Reconnecting: the 1-based retry number
	Err       error  // underlying error, when applicable
}

// ClientEventHandler receives client tunnel events. Called from the event
// dispatcher goroutine — never from the data path.
type ClientEventHandler func(ClientEvent)

// Server events. Valuable for SIEM pipelines: the security kinds
// (AuthRejected, ReplayDropped, TargetDenied) surface attack and misuse
// signals that plain logs make easy to miss.
type ServerEventKind int

const (
	// ServerSessionCreated fires when a tunnel session is registered.
	ServerSessionCreated ServerEventKind = iota
	// ServerSessionClosed fires when a tunnel session is torn down for any
	// reason (client close signal, idle expiry, backend failure).
	ServerSessionClosed
	// ServerAuthRejected fires when a client fails the Noise handshake (bad
	// or missing ephemeral key).
	ServerAuthRejected
	// ServerReplayDropped fires when a duplicate or replayed upstream chunk is
	// dropped by the deduplication window.
	ServerReplayDropped
	// ServerTargetDenied fires when a declared target is refused by the
	// allow_targets list.
	ServerTargetDenied
)

func (k ServerEventKind) String() string {
	switch k {
	case ServerSessionCreated:
		return "SessionCreated"
	case ServerSessionClosed:
		return "SessionClosed"
	case ServerAuthRejected:
		return "AuthRejected"
	case ServerReplayDropped:
		return "ReplayDropped"
	case ServerTargetDenied:
		return "TargetDenied"
	default:
		return "unknown"
	}
}

// ServerEvent describes one lifecycle or security occurrence on the server.
type ServerEvent struct {
	Kind      ServerEventKind
	SessionID string
	Remote    string // resolver address the query arrived from, when known
	Target    string // declared backend, for TargetDenied
	Detail    string // human-readable detail, kind-specific
}

// ServerEventHandler receives server session events. Called from the event
// dispatcher goroutine — never from the DNS query path.
type ServerEventHandler func(ServerEvent)

const eventQueueSize = 64

// eventDispatcher decouples event producers (data-path goroutines) from the
// embedder's handler. Publishing is always non-blocking: events queue into a
// bounded channel and the OLDEST event is evicted (best effort) when the queue
// is full, so terminal events are not lost to a burst of advisory ones. A slow
// handler must never stall the tunnel. Every invocation of the handler is
// wrapped in a panic guard so a buggy handler cannot kill the dispatcher (or
// anything else).
type eventDispatcher[E any] struct {
	mu      sync.Mutex
	handler func(E)
	ch      chan E
	stop    chan struct{}
	stopOne sync.Once
}

func newEventDispatcher[E any](handler func(E)) *eventDispatcher[E] {
	d := &eventDispatcher[E]{
		handler: handler,
		ch:      make(chan E, eventQueueSize),
		stop:    make(chan struct{}),
	}
	go d.loop()
	return d
}

// setHandler swaps the handler; nil disables delivery. Safe to call while
// events are being published.
func (d *eventDispatcher[E]) setHandler(h func(E)) {
	if d == nil {
		return
	}
	d.mu.Lock()
	d.handler = h
	d.mu.Unlock()
}

// publish enqueues an event without ever blocking. Safe on a nil dispatcher.
// When the queue is full the OLDEST queued event is evicted (best effort) to
// make room, so a burst of advisory events cannot starve terminal ones such
// as TunnelDied / SessionClosed; only if a concurrent publisher re-fills the
// queue inside the retry window is the new event dropped.
func (d *eventDispatcher[E]) publish(ev E) {
	if d == nil {
		return
	}
	select {
	case d.ch <- ev:
		return
	default:
	}
	select {
	case <-d.ch:
	default:
	}
	select {
	case d.ch <- ev:
	default:
		// Queue full: the handler is overwhelmed. Dropping an advisory event
		// is strictly better than stalling the data path.
	}
}

// close stops the dispatcher after draining everything already queued.
func (d *eventDispatcher[E]) close() {
	if d == nil {
		return
	}
	d.stopOne.Do(func() { close(d.stop) })
}

func (d *eventDispatcher[E]) loop() {
	for {
		select {
		case ev := <-d.ch:
			d.safeHandle(ev)
		case <-d.stop:
			// Drain whatever was queued before the stop signal so terminal
			// events (TunnelDied, SessionClosed) are never lost.
			for {
				select {
				case ev := <-d.ch:
					d.safeHandle(ev)
				default:
					return
				}
			}
		}
	}
}

func (d *eventDispatcher[E]) safeHandle(ev E) {
	d.mu.Lock()
	handler := d.handler
	d.mu.Unlock()
	if handler == nil {
		return
	}
	defer func() {
		_ = recover() // a panicking handler must not kill the dispatcher
	}()
	handler(ev)
}

// newEventDispatcherOrNil returns nil (a no-op dispatcher) when no handler is
// configured, so hot paths can publish unconditionally.
func newEventDispatcherOrNil[E any](handler func(E)) *eventDispatcher[E] {
	if handler == nil {
		return nil
	}
	return newEventDispatcher[E](handler)
}

// pskKeyFromSecret derives the HMAC key from a PSK string (SHA-256 of the raw
// secret). Empty secrets yield nil — no client authentication.
func pskKeyFromSecret(secret string) []byte {
	secret = strings.TrimSpace(secret)
	if secret == "" {
		return nil
	}
	key := sha256.Sum256([]byte(secret))
	return key[:]
}

// pskProof computes the per-session authentication proof a client sends in its
// capability probe: HMAC-SHA256(psk, sessionID) truncated to 16 bytes.
func pskProof(key []byte, sessionID string) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(sessionID))
	return mac.Sum(nil)[:pskProofLen]
}
