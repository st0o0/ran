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
	// scanPorts is the number of distinct destination ports from one IP within
	// scanWindow that makes the IP a scanner, even on a single protocol.
	scanPorts = 5
	// maxScanPorts bounds the per-entry port set. It is larger than scanPorts:
	// once that many live ports are held the verdict is already scan.
	maxScanPorts = 16
)

type scanEntry struct {
	ip      string
	last    time.Time
	touched map[string]time.Time // protocol -> last touch
	ports   map[int]time.Time    // destination port -> last touch, at most maxScanPorts
}

// scanTracker detects sources that touch several distinct TCP trap protocols or
// destination ports in a short time. Entries live in a FIFO list ordered by last
// touch, so sweeps and eviction of the oldest entry only look at the front. The
// map is capped; under a flood of unique sources the oldest tracking state is
// dropped, which only delays a scan classification (accepted for a sensor).
type scanTracker struct {
	stats      *trackStats
	mu         sync.Mutex
	entries    map[string]*list.Element
	order      *list.List
	window     time.Duration
	threshold  int
	portLimit  int
	maxEntries int
	nowFunc    func() time.Time
}

func newScanTracker(window time.Duration, threshold, maxEntries int) *scanTracker {
	return &scanTracker{
		entries:    make(map[string]*list.Element),
		order:      list.New(),
		window:     window,
		threshold:  threshold,
		portLimit:  scanPorts,
		maxEntries: maxEntries,
		nowFunc:    time.Now,
	}
}

// Touch records that ip used protocol and reports whether ip is currently a
// scanner. Callers must only pass TCP protocols from validated source IPs.
func (s *scanTracker) Touch(ip, protocol string) bool {
	return s.TouchPort(ip, protocol, 0)
}

// TouchPort is Touch with the destination port. ip is a scanner when it used at
// least threshold distinct protocols or portLimit distinct ports within the
// window. A port <= 0 (unknown) is not counted.
func (s *scanTracker) TouchPort(ip, protocol string, port int) bool {
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
		el = s.order.PushBack(&scanEntry{
			ip:      ip,
			touched: make(map[string]time.Time, scanProtocols),
			ports:   make(map[int]time.Time, scanPorts),
		})
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

	// Expire ports first so the set only holds live ones, then add the new port
	// if there is room. A full set of live ports already exceeds portLimit, so
	// skipping a further port cannot hide a scan.
	for p, at := range e.ports {
		if now.Sub(at) >= s.window {
			delete(e.ports, p)
		}
	}
	if _, known := e.ports[port]; port > 0 && (known || len(e.ports) < maxScanPorts) {
		e.ports[port] = now
	}
	return live >= s.threshold || len(e.ports) >= s.portLimit
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
