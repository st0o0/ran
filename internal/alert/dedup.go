package alert

import (
	"container/list"
	"sync"
	"time"
)

type dedupEntry struct {
	key  string
	at   time.Time
	slot uint64
}

// dedupFilter suppresses repeated alerts per key within a window. Entries live
// in a FIFO list ordered by the time their slot was taken, so expiry sweeps and
// oldest-entry eviction only touch the front and cost O(1) amortized.
//
// Eviction trade-off: a flood of unique sources can evict an entry that is still
// inside its window, so a repeat alert for it may pass the filter. This is
// accepted: the LAPI stays authoritative and deduplicates on its side.
type dedupFilter struct {
	mu         sync.Mutex
	seen       map[string]*list.Element
	order      *list.List
	nextSlot   uint64
	window     time.Duration
	maxEntries int
	nowFunc    func() time.Time
}

func newDedupFilter(window time.Duration, maxEntries int) *dedupFilter {
	return &dedupFilter{
		seen:       make(map[string]*list.Element),
		order:      list.New(),
		window:     window,
		maxEntries: maxEntries,
		nowFunc:    time.Now,
	}
}

// Allow records the slot for key and reports whether the alert may proceed.
// Callers that fail to enqueue must pass the returned slot to Release so the
// alert can be retried.
func (d *dedupFilter) Allow(key string) (slot uint64, ok bool) {
	if d.window == 0 {
		return 0, true
	}
	now := d.nowFunc()
	d.mu.Lock()
	defer d.mu.Unlock()

	d.nextSlot++
	if el, found := d.seen[key]; found {
		e := el.Value.(*dedupEntry)
		if now.Sub(e.at) < d.window {
			return 0, false
		}
		e.at, e.slot = now, d.nextSlot
		d.order.MoveToBack(el)
		return e.slot, true
	}
	if len(d.seen) >= d.maxEntries {
		d.makeRoom(now)
	}
	d.seen[key] = d.order.PushBack(&dedupEntry{key: key, at: now, slot: d.nextSlot})
	return d.nextSlot, true
}

// Release frees the slot taken by Allow after a failed enqueue. It does nothing
// if the key has since been re-armed by another alert (different slot).
func (d *dedupFilter) Release(key string, slot uint64) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if el, ok := d.seen[key]; ok && el.Value.(*dedupEntry).slot == slot {
		d.remove(el)
	}
}

func (d *dedupFilter) remove(el *list.Element) {
	delete(d.seen, el.Value.(*dedupEntry).key)
	d.order.Remove(el)
}

// makeRoom drops expired entries from the front and, if still full, evicts the
// oldest one.
func (d *dedupFilter) makeRoom(now time.Time) {
	d.sweepFront(now)
	if len(d.seen) >= d.maxEntries {
		if el := d.order.Front(); el != nil {
			d.remove(el)
		}
	}
}

// sweepFront removes expired entries; the list is ordered by age, so it stops
// at the first live one.
func (d *dedupFilter) sweepFront(now time.Time) {
	for el := d.order.Front(); el != nil; el = d.order.Front() {
		if now.Sub(el.Value.(*dedupEntry).at) < d.window {
			return
		}
		d.remove(el)
	}
}

func (d *dedupFilter) cleanup() {
	if d.window == 0 {
		return
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	d.sweepFront(d.nowFunc())
}
