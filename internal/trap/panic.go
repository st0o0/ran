package trap

import (
	"log/slog"
	"net/http"
	"runtime/debug"
	"sync"
	"time"

	"github.com/st0o0/ran/internal/metrics"
)

const (
	// panicStackLimit is how many panics per protocol are logged with a full
	// stack trace; later ones are sampled.
	panicStackLimit = 5
	// panicLogInterval is the minimum gap between sampled panic logs per protocol.
	panicLogInterval = time.Second
)

// panicLimiter rate limits panic logs per protocol so a crafted input that
// panics on every packet cannot amplify into a log flood. Counting is never limited.
type panicLimiter struct {
	mu      sync.Mutex
	nowFunc func() time.Time
	state   map[string]*panicState
}

type panicState struct {
	count      int
	last       time.Time
	suppressed int
}

func newPanicLimiter(nowFunc func() time.Time) *panicLimiter {
	return &panicLimiter{nowFunc: nowFunc, state: make(map[string]*panicState)}
}

var panicLog = newPanicLimiter(time.Now)

// allow reports whether this panic should be logged, whether the log carries a
// stack trace, and how many panics were suppressed since the previous log.
func (p *panicLimiter) allow(protocol string) (logIt, withStack bool, suppressed int) {
	now := p.nowFunc()
	p.mu.Lock()
	defer p.mu.Unlock()

	st, ok := p.state[protocol]
	if !ok {
		st = &panicState{}
		p.state[protocol] = st
	}
	st.count++
	if st.count <= panicStackLimit {
		st.last = now
		return true, true, 0
	}
	if now.Sub(st.last) < panicLogInterval {
		st.suppressed++
		return false, false, 0
	}
	suppressed = st.suppressed
	st.suppressed = 0
	st.last = now
	return true, false, suppressed
}

// reportPanic counts a recovered panic and logs it subject to rate limiting.
// It must be called from the deferred function that recovered r so the stack
// still shows the panic site. logger and m may be nil.
func reportPanic(logger *slog.Logger, m *metrics.Metrics, protocol string, r any) {
	if m != nil {
		m.PanicsRecovered.WithLabelValues(protocol).Inc()
	}
	logIt, withStack, suppressed := panicLog.allow(protocol)
	if !logIt {
		return
	}
	if logger == nil {
		logger = slog.Default()
	}
	args := []any{
		"action", "error",
		"protocol", protocol,
		"error_type", "panic",
		"panic", r,
	}
	if withStack {
		args = append(args, "stack", string(debug.Stack()))
	} else {
		args = append(args, "suppressed", suppressed)
	}
	logger.Error("panic recovered", args...)
}

// safely runs fn and recovers from any panic so one bad connection or packet
// cannot take down the whole process. Deferred cleanups inside fn (limiter
// release, session end) still run while the panic unwinds. logger and m may be nil.
func safely(logger *slog.Logger, m *metrics.Metrics, protocol string, fn func()) {
	defer func() {
		if r := recover(); r != nil {
			reportPanic(logger, m, protocol, r)
		}
	}()
	fn()
}

// recoverHandler counts and logs panics in HTTP handlers once, then aborts the
// connection. net/http would otherwise recover them itself without our metric.
func recoverHandler(logger *slog.Logger, m *metrics.Metrics, protocol string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			rec := recover()
			if rec == nil {
				return
			}
			if rec != http.ErrAbortHandler {
				reportPanic(logger, m, protocol, rec)
			}
			panic(http.ErrAbortHandler)
		}()
		next.ServeHTTP(w, r)
	})
}
