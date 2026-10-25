package alert

import (
	"container/list"
	"log/slog"
	"math"
	"net/netip"
	"sort"
	"sync"
	"time"

	"github.com/st0o0/ran/internal/metrics"
)

// Offender table defaults.
const (
	// defaultOffenderReset is the silence after which a source is forgotten and
	// its alert counters start again.
	defaultOffenderReset = 7 * 24 * time.Hour
	// maxShunProtocols bounds the protocol list of one shun summary line.
	maxShunProtocols = 8
	// mapOffender is the "map" label of the offender table in the tracking gauges.
	mapOffender = "offender"
)

// offenderConfig configures the offender table. The CrowdSec sink owns the table
// and builds this from its own config.
type offenderConfig struct {
	// Shun turns on the shun deadline: after an accepted alert the source is
	// refused at accept time for the window that was applied to that alert.
	Shun bool
	// RepeatAfter is the number of accepted alerts for a source and class after
	// which the repeat cooldown applies; values below 1 mean 5.
	RepeatAfter int
	// RepeatCooldown replaces the base cooldown once RepeatAfter is reached; 0
	// keeps the base cooldown (no change in behavior).
	RepeatCooldown time.Duration
	// MaxEntries bounds the table (FIFO eviction); 0 uses the default of the
	// other tracking maps.
	MaxEntries int
	// Reset is the silence after which an entry expires; 0 uses
	// defaultOffenderReset (raised to twice RepeatCooldown if that is longer).
	Reset time.Duration
	// Now is the clock; nil uses time.Now.
	Now func() time.Time
	// Metrics receives the table gauges and the shun counters; nil disables them.
	Metrics *metrics.Metrics
}

type offender struct {
	ip     string
	counts [3]int // accepted alerts per class (probe, attack, scan)
	last   time.Time

	// shunUntil is the end of the current shun window; the zero value means no
	// window. An entry in the active set has a window that has not been closed
	// (summary written) yet.
	shunStart time.Time
	shunUntil time.Time
	// winID identifies the current window (and its last extension) so revert closes
	// only the window the reverted alert opened.
	winID      uint64
	suppressed int
	protos     map[string]struct{}

	el     *list.Element
	active bool
}

// offenderTable is the bounded table behind the repeat cooldown and the shun
// window. It is keyed by source IP and holds, per class, the number of accepted
// alerts, the time of the last alert and the shun deadline. It is FIFO ordered
// by the last alert, expires entries after a period of silence and is safe for
// concurrent use. A nil *offenderTable is valid and does nothing.
//
// Eviction trade-off: a flood of unique sources can evict an entry, which loses
// a shun or a repeat counter. That is a missed suppression, never a wrong ban:
// ran stays a sensor.
type offenderTable struct {
	mu          sync.Mutex
	entries     map[string]*offender
	order       *list.List // oldest last alert first
	active      map[*offender]struct{}
	nextWin     uint64
	shun        bool
	repeatAfter int
	repeat      time.Duration
	max         int
	reset       time.Duration
	now         func() time.Time
	logger      *slog.Logger
	stats       *trackStats
	rejectedCtr interface{ Inc() }
	activeGauge interface{ Set(float64) }
}

// newOffenderTable creates the table. The logger receives the "shun summary" lines.
func newOffenderTable(cfg offenderConfig, logger *slog.Logger) *offenderTable {
	o := &offenderTable{
		entries:     make(map[string]*offender),
		order:       list.New(),
		active:      make(map[*offender]struct{}),
		shun:        cfg.Shun,
		repeatAfter: cfg.RepeatAfter,
		repeat:      cfg.RepeatCooldown,
		max:         cfg.MaxEntries,
		reset:       cfg.Reset,
		now:         cfg.Now,
		logger:      logger.With("component", "sensor"),
	}
	if o.repeatAfter < 1 {
		o.repeatAfter = 5
	}
	if o.max <= 0 {
		o.max = defaultMaxTracked
	}
	if o.reset <= 0 {
		o.reset = defaultOffenderReset
		// Twice the repeat cooldown, without overflowing a Duration.
		if o.repeat > o.reset/2 {
			if o.repeat > math.MaxInt64/2 {
				o.reset = math.MaxInt64
			} else {
				o.reset = 2 * o.repeat
			}
		}
	}
	if o.now == nil {
		o.now = time.Now
	}
	o.stats = newTrackStats(cfg.Metrics, mapOffender)
	if cfg.Metrics != nil {
		o.rejectedCtr = cfg.Metrics.ConnectionsRejected.WithLabelValues("shun")
		o.activeGauge = cfg.Metrics.ShunActive
	}
	return o
}

// shunEnabled reports whether accepted alerts open shun windows.
func (o *offenderTable) shunEnabled() bool { return o != nil && o.shun }

func classIndex(c Class) int {
	if r := c.rank(); r > 0 {
		return r - 1
	}
	return -1
}

// normalizeIP returns the table key of ip, or false for an unparsable address.
func normalizeIP(ip string) (string, bool) {
	addr, err := netip.ParseAddr(ip)
	if err != nil || addr.Zone() != "" {
		return "", false
	}
	return addr.Unmap().String(), true
}

// windowFor returns the cooldown that applies to the next accepted alert for
// ip and class: base until RepeatAfter alerts were accepted (counting that one),
// RepeatCooldown from then on. A zero base disables cooldowns altogether and
// stays zero.
func (o *offenderTable) windowFor(ip string, class Class, base time.Duration) time.Duration {
	if o == nil || base <= 0 || o.repeat <= 0 {
		return base
	}
	key, ok := normalizeIP(ip)
	if !ok {
		return base
	}
	idx := classIndex(class)
	if idx < 0 {
		return base
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	count := 0
	if e := o.entries[key]; e != nil && !o.expired(e, o.now()) {
		count = e.counts[idx]
	}
	if count+1 >= o.repeatAfter {
		return o.repeat
	}
	return base
}

// expired reports whether e was silent for the reset period and has no shun
// window left.
func (o *offenderTable) expired(e *offender, now time.Time) bool {
	return now.Sub(e.last) >= o.reset && !now.Before(e.shunUntil)
}

// acceptMark identifies what one accepted alert recorded, so a failed push can
// undo exactly that. The zero value reverts nothing.
type acceptMark struct {
	key string
	idx int
	// win is the id of the shun window this alert opened; 0 when it opened none
	// (probe, no shun, or it only extended a running window).
	win uint64
	ok  bool
}

// accepted records an alert that passed the cooldown, with the window that was
// applied to it. With shun on, a class other than probe opens (or extends) the
// shun window of the source. The returned mark undoes the record through revert.
func (o *offenderTable) accepted(ip string, class Class, window time.Duration) acceptMark {
	if o == nil {
		return acceptMark{}
	}
	key, ok := normalizeIP(ip)
	idx := classIndex(class)
	if !ok || idx < 0 {
		return acceptMark{}
	}
	now := o.now()
	var sums []shunSummary
	o.mu.Lock()
	win := o.acceptLocked(key, idx, class, window, now, &sums)
	o.mu.Unlock()
	o.logSummaries(sums)
	return acceptMark{key: key, idx: idx, win: win, ok: true}
}

// revert undoes accepted for an alert whose push failed (the cooldown slot is
// released at the same time, so the source is reported again). It decrements the
// class counter and, if the alert opened the window that is still running
// unchanged, closes it; a summary is written only if connections were
// suppressed. A window that was extended by another alert, already ended or
// belongs to an evicted entry is left alone.
func (o *offenderTable) revert(m acceptMark) {
	if o == nil || !m.ok {
		return
	}
	now := o.now()
	var sums []shunSummary
	o.mu.Lock()
	if e := o.entries[m.key]; e != nil {
		if e.counts[m.idx] > 0 {
			e.counts[m.idx]--
		}
		if m.win != 0 && e.active && e.winID == m.win {
			o.endWindow(e, now, &sums)
		}
		if !e.active && e.counts == [3]int{} {
			o.remove(e, now, &sums)
		}
	}
	o.mu.Unlock()
	o.logSummaries(sums)
}

// acceptLocked is the body of accepted. Callers hold mu; summaries of closed windows
// are appended to sums and must be logged after mu is released. It returns the id
// of the window the alert opened, or 0.
func (o *offenderTable) acceptLocked(key string, idx int, class Class, window time.Duration, now time.Time, sums *[]shunSummary) uint64 {
	e := o.entries[key]
	if e != nil && o.expired(e, now) {
		o.remove(e, now, sums)
		e = nil
	}
	if e == nil {
		if len(o.entries) >= o.max {
			o.makeRoom(now, sums)
		}
		e = &offender{ip: key}
		e.el = o.order.PushBack(e)
		o.entries[key] = e
		o.stats.size(len(o.entries))
	} else {
		o.order.MoveToBack(e.el)
	}
	e.counts[idx]++
	e.last = now

	if !o.shun || class == ClassProbe || window <= 0 {
		return 0
	}
	until := now.Add(window)
	if e.active && now.Before(e.shunUntil) {
		// A higher class alert inside a running window: extend, keep counting. An
		// extension gets a new id, so reverting the alert that opened the window no
		// longer closes it.
		if until.After(e.shunUntil) {
			e.shunUntil = until
			o.nextWin++
			e.winID = o.nextWin
		}
		return 0
	}
	if e.active {
		o.endWindow(e, now, sums)
	}
	o.nextWin++
	e.winID = o.nextWin
	e.shunStart, e.shunUntil = now, until
	e.active = true
	o.active[e] = struct{}{}
	o.setGauge()
	return e.winID
}

// shunned reports whether new connections from ip are refused right now. A
// window that has ended is closed here (lazily) and its summary is written.
func (o *offenderTable) shunned(ip string) bool {
	if o == nil || !o.shun {
		return false
	}
	o.mu.Lock()
	if len(o.active) == 0 {
		o.mu.Unlock()
		return false
	}
	o.mu.Unlock()
	key, ok := normalizeIP(ip)
	if !ok {
		return false
	}
	now := o.now()
	var sums []shunSummary
	o.mu.Lock()
	e := o.entries[key]
	if e == nil || !e.active {
		o.mu.Unlock()
		return false
	}
	if now.Before(e.shunUntil) {
		o.mu.Unlock()
		return true
	}
	o.endWindow(e, now, &sums)
	o.mu.Unlock()
	o.logSummaries(sums)
	return false
}

// rejected counts one refused connection for ip on protocol. The protocol list
// of the summary is bounded; the counter has no client labels.
func (o *offenderTable) rejected(ip, protocol string) {
	if o == nil {
		return
	}
	if o.rejectedCtr != nil {
		o.rejectedCtr.Inc()
	}
	key, ok := normalizeIP(ip)
	if !ok {
		return
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	e := o.entries[key]
	if e == nil || !e.active {
		return
	}
	e.suppressed++
	if e.protos == nil {
		e.protos = make(map[string]struct{}, 2)
	}
	if _, seen := e.protos[protocol]; !seen && len(e.protos) < maxShunProtocols {
		e.protos[protocol] = struct{}{}
	}
}

// shunSummary is one pending "shun summary" log line. It is collected under mu
// and written after mu is released, so a slow log handler never blocks the
// accept path (Shunned).
type shunSummary struct {
	ip      string
	count   int
	protos  []string
	seconds int
}

// logSummaries writes the collected summaries. Callers must not hold mu.
func (o *offenderTable) logSummaries(sums []shunSummary) {
	for _, s := range sums {
		o.logger.Info("shun summary",
			"action", "shun_summary",
			"source_ip", s.ip,
			"count", s.count,
			"protocols", s.protos,
			"window_seconds", s.seconds,
		)
	}
}

// endWindow closes the shun window of e and, if connections were suppressed,
// appends the summary to sums. Callers hold mu and log sums after releasing it.
func (o *offenderTable) endWindow(e *offender, now time.Time, sums *[]shunSummary) {
	if e.suppressed > 0 {
		end := e.shunUntil
		if now.Before(end) {
			end = now
		}
		protos := make([]string, 0, len(e.protos))
		for p := range e.protos {
			protos = append(protos, p)
		}
		sort.Strings(protos)
		*sums = append(*sums, shunSummary{
			ip:      e.ip,
			count:   e.suppressed,
			protos:  protos,
			seconds: int(end.Sub(e.shunStart).Seconds()),
		})
	}
	e.suppressed, e.protos = 0, nil
	e.shunStart, e.shunUntil = time.Time{}, time.Time{}
	e.active = false
	delete(o.active, e)
	o.setGauge()
}

func (o *offenderTable) setGauge() {
	if o.activeGauge != nil {
		o.activeGauge.Set(float64(len(o.active)))
	}
}

// remove drops e from the table, writing a pending summary first. Callers hold mu.
func (o *offenderTable) remove(e *offender, now time.Time, sums *[]shunSummary) {
	if e.active {
		o.endWindow(e, now, sums)
	}
	delete(o.entries, e.ip)
	o.order.Remove(e.el)
	o.stats.size(len(o.entries))
}

// evictScan bounds how many of the oldest entries makeRoom inspects for one
// without an active shun window. The scan is O(evictScan) per eviction, which
// only happens when the table is full.
const evictScan = 64

// makeRoom frees one slot: first silent entries, then the oldest entry without
// an active shun window among the first evictScan entries. An entry with an
// active shun is evicted (oldest first) only when every entry is active, or when
// the first evictScan entries are all active (the bound; a missed suppression
// then, never a wrong ban).
func (o *offenderTable) makeRoom(now time.Time, sums *[]shunSummary) {
	o.sweepFront(now, sums)
	if len(o.entries) < o.max {
		return
	}
	victim := o.order.Front()
	if victim == nil {
		return
	}
	if len(o.active) < len(o.entries) {
		n := 0
		for el := victim; el != nil && n < evictScan; el, n = el.Next(), n+1 {
			if !el.Value.(*offender).active {
				victim = el
				break
			}
		}
	}
	o.stats.evicted()
	o.remove(victim.Value.(*offender), now, sums)
}

// sweepFront removes silent entries; the list is ordered by last alert, so it
// stops at the first live one.
func (o *offenderTable) sweepFront(now time.Time, sums *[]shunSummary) {
	for el := o.order.Front(); el != nil; el = o.order.Front() {
		e := el.Value.(*offender)
		if !o.expired(e, now) {
			return
		}
		o.remove(e, now, sums)
	}
}

// sweep closes ended shun windows (writing their summaries) and removes silent
// entries. It is called periodically by the sensor through the ShunGate.
func (o *offenderTable) sweep() {
	if o == nil {
		return
	}
	now := o.now()
	var sums []shunSummary
	o.mu.Lock()
	for e := range o.active {
		if !now.Before(e.shunUntil) {
			o.endWindow(e, now, &sums)
		}
	}
	o.sweepFront(now, &sums)
	o.mu.Unlock()
	o.logSummaries(sums)
}

// flush writes the summary of every open window (shutdown). The windows stay
// open, so a connection that is still being accepted keeps being refused.
func (o *offenderTable) flush() {
	if o == nil {
		return
	}
	now := o.now()
	var sums []shunSummary
	o.mu.Lock()
	for e := range o.active {
		if e.suppressed > 0 {
			o.endWindowKeep(e, now, &sums)
		}
	}
	o.mu.Unlock()
	o.logSummaries(sums)
}

// endWindowKeep writes the summary and resets the counters but keeps the window.
func (o *offenderTable) endWindowKeep(e *offender, now time.Time, sums *[]shunSummary) {
	until := e.shunUntil
	o.endWindow(e, now, sums)
	e.shunStart, e.shunUntil = now, until
	e.active = true
	o.active[e] = struct{}{}
	o.setGauge()
}

// length returns the number of tracked sources (tests and diagnostics).
func (o *offenderTable) length() int {
	if o == nil {
		return 0
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	return len(o.entries)
}
