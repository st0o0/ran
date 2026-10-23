package alert

import (
	"container/list"
	"sync"
	"time"
)

const (
	// scanProtocols is the number of distinct TCP trap protocols from one IP
	// within scanWindow that makes the IP a scanner.
	scanProtocols = 3
	scanWindow    = 10 * time.Minute
)

type scanEntry struct {
	ip      string
	last    time.Time
	touched map[string]time.Time // protocol -> last touch
}

// scanTracker detects sources that touch several distinct TCP trap protocols in
// a short time. Entries live in a FIFO list ordered by last touch, so sweeps and
// eviction of the oldest entry only look at the front. The map is capped; under
// a flood of unique sources the oldest tracking state is dropped, which only
// delays a scan classification (accepted for a sensor).
type scanTracker struct {
	stats      *trackStats
	mu         sync.Mutex
	entries    map[string]*list.Element
	order      *list.List
	window     time.Duration
	threshold  int
	maxEntries int
	nowFunc    func() time.Time
}

func newScanTracker(window time.Duration, threshold, maxEntries int) *scanTracker {
	return &scanTracker{
		entries:    make(map[string]*list.Element),
		order:      list.New(),
		window:     window,
		threshold:  threshold,
		maxEntries: maxEntries,
		nowFunc:    time.Now,
	}
}

// Touch records that ip used protocol and reports whether ip is currently a
// scanner. Callers must only pass TCP protocols from validated source IPs.
func (s *scanTracker) Touch(ip, protocol string) bool {
	now := s.nowFunc()
	s.mu.Lock()
	defer s.mu.Unlock()

	el, ok := s.entries[ip]
	if !ok {
		if len(s.entries) >= s.maxEntries {
			s.sweepFront(now)
			if len(s.entries) >= s.maxEntries {
				if front := s.order.Front(); front != nil {
					s.stats.evicted()
					s.remove(front)
				}
			}
		}
		el = s.order.PushBack(&scanEntry{ip: ip, touched: make(map[string]time.Time, scanProtocols)})
		s.entries[ip] = el
		s.stats.size(len(s.entries))
	}
	e := el.Value.(*scanEntry)
	e.touched[protocol] = now
	e.last = now
	s.order.MoveToBack(el)

	live := 0
	for p, at := range e.touched {
		if now.Sub(at) >= s.window {
			delete(e.touched, p)
			continue
		}
		live++
	}
	return live >= s.threshold
}

func (s *scanTracker) remove(el *list.Element) {
	delete(s.entries, el.Value.(*scanEntry).ip)
	s.order.Remove(el)
	s.stats.size(len(s.entries))
}

func (s *scanTracker) sweepFront(now time.Time) {
	for el := s.order.Front(); el != nil; el = s.order.Front() {
		if now.Sub(el.Value.(*scanEntry).last) < s.window {
			return
		}
		s.remove(el)
	}
}

func (s *scanTracker) cleanup() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sweepFront(s.nowFunc())
}

func (s *scanTracker) len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.entries)
}
