package alert

import (
	"sync"
	"time"
)

type dedupFilter struct {
	mu      sync.Mutex
	seen    map[string]time.Time
	window  time.Duration
	nowFunc func() time.Time
}

func newDedupFilter(window time.Duration) *dedupFilter {
	return &dedupFilter{
		seen:    make(map[string]time.Time),
		window:  window,
		nowFunc: time.Now,
	}
}

func (d *dedupFilter) Allow(key string) bool {
	if d.window == 0 {
		return true
	}
	now := d.nowFunc()
	d.mu.Lock()
	defer d.mu.Unlock()
	if last, ok := d.seen[key]; ok && now.Sub(last) < d.window {
		return false
	}
	d.seen[key] = now
	return true
}

func (d *dedupFilter) cleanup() {
	if d.window == 0 {
		return
	}
	cutoff := d.nowFunc().Add(-2 * d.window)
	d.mu.Lock()
	defer d.mu.Unlock()
	for k, t := range d.seen {
		if t.Before(cutoff) {
			delete(d.seen, k)
		}
	}
}
