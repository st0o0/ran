package trap

import (
	"sync"
	"time"

	"github.com/st0o0/ran/internal/config"
)

// maxRateSources caps the per-source state of the UDP rate limiter. Sources
// beyond the cap are only subject to the global bucket.
const maxRateSources = 100000

type bucket struct {
	tokens float64
	last   time.Time
}

// take adds tokens for the elapsed time, capped at burst, and takes one if available.
func (b *bucket) take(now time.Time, rate, burst float64) bool {
	if elapsed := now.Sub(b.last).Seconds(); elapsed > 0 {
		b.tokens += elapsed * rate
		if b.tokens > burst {
			b.tokens = burst
		}
	}
	b.last = now
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// udpRateLimiter applies a per-source and a global token bucket to inbound
// UDP packets before any session or goroutine is created.
type udpRateLimiter struct {
	perSource  float64
	burst      float64
	global     float64
	maxSources int

	mu        sync.Mutex
	sources   map[string]*bucket
	globalB   bucket
	lastSweep time.Time
	nowFunc   func() time.Time
}

func newUDPRateLimiter(cfg *config.Config) *udpRateLimiter {
	// Configs built without Load (tests) fall back to the documented defaults.
	perSource, burst, global := orDefault(cfg.UDPRatePerSource, 20), orDefault(cfg.UDPRateBurst, 40), orDefault(cfg.UDPRateGlobal, 2000)
	now := time.Now()
	return &udpRateLimiter{
		perSource:  float64(perSource),
		burst:      float64(burst),
		global:     float64(global),
		maxSources: maxRateSources,
		sources:    make(map[string]*bucket),
		globalB:    bucket{tokens: float64(global), last: now},
		lastSweep:  now,
		nowFunc:    time.Now,
	}
}

func orDefault(v, def int) int {
	if v <= 0 {
		return def
	}
	return v
}

// Allow reports whether a packet from source may be handled.
func (l *udpRateLimiter) Allow(source string) bool {
	now := l.nowFunc()
	l.mu.Lock()
	defer l.mu.Unlock()

	b, ok := l.sources[source]
	if !ok && l.makeRoom(now) {
		b = &bucket{tokens: l.burst, last: now}
		l.sources[source] = b
		ok = true
	}
	if ok && !b.take(now, l.perSource, l.burst) {
		return false
	}
	return l.globalB.take(now, l.global, l.global)
}

// makeRoom returns true if a new source can be tracked. At the cap it sweeps
// idle sources (fully refilled buckets), at most once per second.
func (l *udpRateLimiter) makeRoom(now time.Time) bool {
	if len(l.sources) < l.maxSources {
		return true
	}
	if now.Sub(l.lastSweep) < time.Second {
		return false
	}
	l.lastSweep = now
	idle := time.Duration(l.burst / l.perSource * float64(time.Second))
	for k, b := range l.sources {
		if now.Sub(b.last) >= idle {
			delete(l.sources, k)
		}
	}
	return len(l.sources) < l.maxSources
}
