package dnstunnel

import (
	"sync"
	"sync/atomic"
	"time"

	"go.uber.org/zap"
)

// dnsTunnelLogWindow is the emission window shared by the data-path warn
// throttlers: short enough to keep a genuine incident diagnosable, long enough
// that a query-rate flood cannot out-write the disk.
const dnsTunnelLogWindow = 10 * time.Second

// warnThrottle caps one recurring warning to a single emission per window, so
// an attacker who can trigger the condition at query rate (a session-cap flood,
// garbage ciphertext into a known session) cannot turn the data path into a
// log-flood disk DoS. Suppressed emissions are counted and reported in the next
// admitted line, so the aggregate signal survives the throttling.
type warnThrottle struct {
	mu         sync.Mutex
	next       time.Time // next time an emission is admitted
	suppressed atomic.Int64
}

// warnf emits the warning at most once per window. Call it exactly where the
// un-throttled Warnf used to sit; the format string and arguments are evaluated
// lazily as before, so a suppressed call costs a mutex acquire and a counter.
func (w *warnThrottle) warnf(log *zap.SugaredLogger, window time.Duration, format string, args ...any) {
	w.mu.Lock()
	now := time.Now()
	admit := !now.Before(w.next)
	if admit {
		w.next = now.Add(window)
	}
	w.mu.Unlock()
	if !admit {
		w.suppressed.Add(1)
		return
	}
	if n := w.suppressed.Swap(0); n > 0 {
		args = append(args, n)
		format += " (suppressed %d more in the last %v)"
		args = append(args, window)
	}
	log.Warnf(format, args...)
}
