package alert

import (
	"container/list"
	"log/slog"
	"net/netip"
	"sort"
	"sync"
	"time"

	"github.com/st0o0/ran/internal/metrics"
)

// Offender table defaults.
const (
	// DefaultOffenderReset is the silence after which a source is forgotten and
	// its alert counters start again.
	DefaultOffenderReset = 7 * 24 * time.Hour
	// maxShunProtocols bounds the protocol list of one shun summary line.
	maxShunProtocols = 8
	// mapOffender is the "map" label of the offender table in the tracking gauges.
	mapOffender = "offender"
)

// OffenderConfig configures the offender table.
type OffenderConfig struct {
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
	// DefaultOffenderReset (raised to twice RepeatCooldown if that is longer).
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
	shunStart  time.Time
	shunUntil  time.Time
	suppressed int
	protos     map[string]struct{}

	el     *list.Element
	active bool
}

// Offenders is the bounded table behind the repeat cooldown and the shun
// window. It is keyed by source IP and holds, per class, the number of accepted
// alerts, the time of the last alert and the shun deadline. It is FIFO ordered
// by the last alert, expires entries after a period of silence and is safe for
// concurrent use. A nil *Offenders is valid and does nothing.
//
// Eviction trade-off: a flood of unique sources can evict an entry, which loses
// a shun or a repeat counter. That is a missed suppression, never a wrong ban:
// ran stays a sensor.
type Offenders struct {
	mu          sync.Mutex
	entries     map[string]*offender
	order       *list.List // oldest last alert first
	active      map[*offender]struct{}
	shun        bool
	repeatAfter int
	repeat      time.Duration
	max         int
	reset       time.Duration
	now         func() time.Time
	logger      *slog.Logger
	stats       *trackStats
	rejected    interface{ Inc() }
	activeGauge interface{ Set(float64) }
}

// NewOffenders creates the table. The logger receives the "shun summary" lines.
func NewOffenders(cfg OffenderConfig, logger *slog.Logger) *Offenders {
	o := &Offenders{
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
		o.reset = DefaultOffenderReset
		if 2*o.repeat > o.reset {
			o.reset = 2 * o.repeat
		}
	}
	if o.now == nil {
		o.now = time.Now
	}
	o.stats = newTrackStats(cfg.Metrics, mapOffender)
	if cfg.Metrics != nil {
		o.rejected = cfg.Metrics.ConnectionsRejected.WithLabelValues("shun")
		o.activeGauge = cfg.Metrics.ShunActive
	}
	return o
}

// ShunEnabled reports whether accepted alerts open shun windows.
func (o *Offenders) ShunEnabled() bool { return o != nil && o.shun }

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

// WindowFor returns the cooldown that applies to the next accepted alert for
// ip and class: base until RepeatAfter alerts were accepted (counting that one),
// RepeatCooldown from then on. A zero base disables cooldowns altogether and
// stays zero.
func (o *Offenders) WindowFor(ip string, class Class, base time.Duration) time.Duration {
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
func (o *Offenders) expired(e *offender, now time.Time) bool {
	return now.Sub(e.last) >= o.reset && !now.Before(e.shunUntil)
}

// Accepted records an alert that passed the cooldown and was queued, with the
// window that was applied to it. With shun on, a class other than probe opens
// (or extends) the shun window of the source.
func (o *Offenders) Accepted(ip string, class Class, window time.Duration) {
	if o == nil {
		return
	}
	key, ok := normalizeIP(ip)
	idx := classIndex(class)
	if !ok || idx < 0 {
		return
	}
	now := o.now()
	o.mu.Lock()
	defer o.mu.Unlock()

	e := o.entries[key]
	if e != nil && o.expired(e, now) {
		o.remove(e, now)
		e = nil
	}
	if e == nil {
		if len(o.entries) >= o.max {
			o.makeRoom(now)
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
		return
	}
	until := now.Add(window)
	if e.active && now.Before(e.shunUntil) {
		// A higher class alert inside a running window: extend, keep counting.
		if until.After(e.shunUntil) {
			e.shunUntil = until
		}
		return
	}
	if e.active {
		o.endWindow(e, now)
	}
	e.shunStart, e.shunUntil = now, until
	e.active = true
	o.active[e] = struct{}{}
	o.setGauge()
}

// Shunned reports whether new connections from ip are refused right now. A
// window that has ended is closed here (lazily) and its summary is written.
func (o *Offenders) Shunned(ip string) bool {
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
	o.mu.Lock()
	defer o.mu.Unlock()
	e := o.entries[key]
	if e == nil || !e.active {
		return false
	}
	if now.Before(e.shunUntil) {
		return true
	}
	o.endWindow(e, now)
	return false
}

// Rejected counts one refused connection for ip on protocol. The protocol list
// of the summary is bounded; the counter has no client labels.
func (o *Offenders) Rejected(ip, protocol string) {
	if o == nil {
		return
	}
	if o.rejected != nil {
		o.rejected.Inc()
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

// endWindow closes the shun window of e and writes the summary if connections
// were suppressed. Callers hold mu.
func (o *Offenders) endWindow(e *offender, now time.Time) {
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
		o.logger.Info("shun summary",
			"action", "shun_summary",
			"source_ip", e.ip,
			"count", e.suppressed,
			"protocols", protos,
			"window_seconds", int(end.Sub(e.shunStart).Seconds()),
		)
	}
	e.suppressed, e.protos = 0, nil
	e.shunStart, e.shunUntil = time.Time{}, time.Time{}
	e.active = false
	delete(o.active, e)
	o.setGauge()
}

func (o *Offenders) setGauge() {
	if o.activeGauge != nil {
		o.activeGauge.Set(float64(len(o.active)))
	}
}

// remove drops e from the table, writing a pending summary first. Callers hold mu.
func (o *Offenders) remove(e *offender, now time.Time) {
	if e.active {
		o.endWindow(e, now)
	}
	delete(o.entries, e.ip)
	o.order.Remove(e.el)
	o.stats.size(len(o.entries))
}

func (o *Offenders) makeRoom(now time.Time) {
	o.sweepFront(now)
	if len(o.entries) >= o.max {
		if el := o.order.Front(); el != nil {
			o.stats.evicted()
			o.remove(el.Value.(*offender), now)
		}
	}
}

// sweepFront removes silent entries; the list is ordered by last alert, so it
// stops at the first live one.
func (o *Offenders) sweepFront(now time.Time) {
	for el := o.order.Front(); el != nil; el = o.order.Front() {
		e := el.Value.(*offender)
		if !o.expired(e, now) {
			return
		}
		o.remove(e, now)
	}
}

// Sweep closes ended shun windows (writing their summaries) and removes silent
// entries. It is called periodically by the sensor.
func (o *Offenders) Sweep() {
	if o == nil {
		return
	}
	now := o.now()
	o.mu.Lock()
	defer o.mu.Unlock()
	for e := range o.active {
		if !now.Before(e.shunUntil) {
			o.endWindow(e, now)
		}
	}
	o.sweepFront(now)
}

// Flush writes the summary of every open window (shutdown). The windows stay
// open, so a connection that is still being accepted keeps being refused.
func (o *Offenders) Flush() {
	if o == nil {
		return
	}
	now := o.now()
	o.mu.Lock()
	defer o.mu.Unlock()
	for e := range o.active {
		if e.suppressed > 0 {
			o.endWindowKeep(e, now)
		}
	}
}

// endWindowKeep writes the summary and resets the counters but keeps the window.
func (o *Offenders) endWindowKeep(e *offender, now time.Time) {
	until := e.shunUntil
	o.endWindow(e, now)
	e.shunStart, e.shunUntil = now, until
	e.active = true
	o.active[e] = struct{}{}
	o.setGauge()
}

// Len returns the number of tracked sources (tests and diagnostics).
func (o *Offenders) Len() int {
	if o == nil {
		return 0
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	return len(o.entries)
}
