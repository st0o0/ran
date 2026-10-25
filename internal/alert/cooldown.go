package alert

import (
	"container/list"
	"sync"
	"time"
)

type cooldownEntry struct {
	key  string
	at   time.Time
	win  time.Duration
	slot uint64
}

// cooldownFilter allows at most one alert per IP and class within a window, so
// CrowdSec's GetDecisionsCount counts episodes instead of packets. A class that
// ranks higher than one still in cooldown for the same IP (probe to attack,
// attack to scan) is allowed once; a lower class is suppressed while a higher
// one is in cooldown.
//
// Entries live in a FIFO list ordered by the time their slot was taken, so
// expiry sweeps and oldest-entry eviction only touch the front (O(1) amortized).
// Eviction trade-off: a flood of unique sources can evict an entry that is still
// inside its window, so a repeat alert for it may pass. This is accepted: the
// LAPI stays authoritative.
type cooldownFilter struct {
	stats      *trackStats
	mu         sync.Mutex
	seen       map[string]*list.Element
	order      *list.List
	nextSlot   uint64
	window     time.Duration
	maxEntries int
	nowFunc    func() time.Time
	// offenders, when set, supplies the repeat cooldown that replaces window
	// after RAN_REPEAT_AFTER alerts. Each entry remembers the window it was
	// created with, so entries are not ordered by expiry any more: the sweep
	// stops at the first live entry and later expired ones wait for it or for
	// eviction (the map stays bounded).
	offenders *Offenders
}

func newCooldownFilter(window time.Duration, maxEntries int) *cooldownFilter {
	return &cooldownFilter{
		seen:       make(map[string]*list.Element),
		order:      list.New(),
		window:     window,
		maxEntries: maxEntries,
		nowFunc:    time.Now,
	}
}

func cooldownKey(ip string, c Class) string { return ip + "|" + string(c) }

// Allow records the slot for ip and class and reports whether the alert may
// proceed. Callers that fail to enqueue must pass the returned key and slot to
// Release so the alert can be retried.
func (d *cooldownFilter) Allow(ip string, class Class) (key string, slot uint64, ok bool) {
	key, slot, _, ok = d.allow(ip, class)
	return key, slot, ok
}

// allow is Allow that also returns the window applied to the new alert.
func (d *cooldownFilter) allow(ip string, class Class) (key string, slot uint64, win time.Duration, ok bool) {
	if d.window == 0 {
		return "", 0, 0, true
	}
	now := d.nowFunc()
	d.mu.Lock()
	defer d.mu.Unlock()

	// The same class or any higher class still in cooldown suppresses the alert.
	for _, c := range Classes {
		if c.rank() < class.rank() {
			continue
		}
		if el, found := d.seen[cooldownKey(ip, c)]; found && now.Sub(el.Value.(*cooldownEntry).at) < el.Value.(*cooldownEntry).win {
			return "", 0, 0, false
		}
	}

	win = d.offenders.WindowFor(ip, class, d.window)
	key = cooldownKey(ip, class)
	d.nextSlot++
	if el, found := d.seen[key]; found {
		e := el.Value.(*cooldownEntry)
		e.at, e.win, e.slot = now, win, d.nextSlot
		d.order.MoveToBack(el)
		return key, e.slot, win, true
	}
	if len(d.seen) >= d.maxEntries {
		d.makeRoom(now)
	}
	d.seen[key] = d.order.PushBack(&cooldownEntry{key: key, at: now, win: win, slot: d.nextSlot})
	d.stats.size(len(d.seen))
	return key, d.nextSlot, win, true
}

// Release frees the slot taken by Allow after a failed enqueue. It does nothing
// if the key has since been re-armed by another alert (different slot).
func (d *cooldownFilter) Release(key string, slot uint64) {
	if key == "" {
		return
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if el, ok := d.seen[key]; ok && el.Value.(*cooldownEntry).slot == slot {
		d.remove(el)
	}
}

func (d *cooldownFilter) remove(el *list.Element) {
	delete(d.seen, el.Value.(*cooldownEntry).key)
	d.order.Remove(el)
	d.stats.size(len(d.seen))
}

func (d *cooldownFilter) makeRoom(now time.Time) {
	d.sweepFront(now)
	if len(d.seen) >= d.maxEntries {
		if el := d.order.Front(); el != nil {
			d.stats.evicted()
			d.remove(el)
		}
	}
}

// sweepFront removes expired entries; the list is ordered by age, so it stops
// at the first live one.
func (d *cooldownFilter) sweepFront(now time.Time) {
	for el := d.order.Front(); el != nil; el = d.order.Front() {
		if now.Sub(el.Value.(*cooldownEntry).at) < el.Value.(*cooldownEntry).win {
			return
		}
		d.remove(el)
	}
}

func (d *cooldownFilter) cleanup() {
	if d.window == 0 {
		return
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	d.sweepFront(d.nowFunc())
}
