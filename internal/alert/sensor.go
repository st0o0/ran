package alert

import (
	"container/list"
	"context"
	"log/slog"
	"net/netip"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/st0o0/ran/internal/config"
	"github.com/st0o0/ran/internal/metrics"
)

// DefaultSummaryWindow is the default probe summary window.
const DefaultSummaryWindow = 60 * time.Second

// SensorConfig configures the Sensor.
type SensorConfig struct {
	// MaxTracked caps the scan tracker and the probe log maps.
	MaxTracked int
	// SummaryWindow is the probe log aggregation window. Zero or negative
	// disables aggregation (probe sessions keep their per-session log lines).
	SummaryWindow time.Duration
	// Metrics receives the tracking map gauges and counters; nil disables them.
	Metrics *metrics.Metrics
	// IgnoreIPs lists sources that never alert, never enter the scan tracker and
	// never enter the probe summary (RAN_IGNORE_IPS).
	IgnoreIPs []netip.Prefix
	// Offenders is the repeat and shun table (RAN_SHUN); nil disables shunning.
	// The same table must be given to the CrowdSec sink, which feeds it.
	Offenders *Offenders
}

// Sensor classifies sessions (probe, attack, scan), detects scans, aggregates
// probe log output and forwards classified events to a Sink. The Sink may be
// nil (no CrowdSec): classification and log aggregation still run.
type Sensor struct {
	sink      Sink
	logger    *slog.Logger
	scan      *scanTracker
	probes    *probeLog
	ignore    []netip.Prefix
	offenders *Offenders

	// interval overrides the maintenance interval (tests only).
	interval time.Duration

	stop      chan struct{}
	wg        sync.WaitGroup
	closeOnce sync.Once
}

// NewSensor creates a Sensor and starts the probe summary flusher.
func NewSensor(cfg SensorConfig, sink Sink, logger *slog.Logger) *Sensor {
	s := newSensor(cfg, sink, logger)
	s.start()
	return s
}

func newSensor(cfg SensorConfig, sink Sink, logger *slog.Logger) *Sensor {
	maxTracked := cfg.MaxTracked
	if maxTracked <= 0 {
		maxTracked = defaultMaxTracked
	}
	lg := logger.With("component", "sensor")
	s := &Sensor{
		sink:      sink,
		logger:    lg,
		scan:      newScanTracker(scanWindow, scanProtocols, maxTracked),
		probes:    newProbeLog(cfg.SummaryWindow, maxTracked, lg),
		ignore:    cfg.IgnoreIPs,
		offenders: cfg.Offenders,
		stop:      make(chan struct{}),
	}
	s.scan.stats = newTrackStats(cfg.Metrics, mapScan)
	s.probes.stats = newTrackStats(cfg.Metrics, mapProbe)
	if cfg.Metrics != nil {
		s.probes.suppressed = cfg.Metrics.ProbeSuppressed
	}
	return s
}

// maintenanceInterval returns how often the flusher runs. The scan tracker
// cleanup must run even when probe aggregation is disabled.
func (s *Sensor) maintenanceInterval() time.Duration {
	if s.interval > 0 {
		return s.interval
	}
	if s.probes.window <= 0 {
		return time.Minute
	}
	if interval := s.probes.window / 2; interval >= time.Second {
		return interval
	}
	return time.Second
}

func (s *Sensor) start() {
	interval := s.maintenanceInterval()
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		t := time.NewTicker(interval)
		defer t.Stop()
		for {
			select {
			case <-t.C:
				if s.probes.window > 0 {
					s.probes.flushDue()
				}
				s.scan.cleanup()
				s.offenders.Sweep()
			case <-s.stop:
				return
			}
		}
	}()
}

// touchScan records a TCP trap protocol use and reports whether the source is a
// scanner. UDP and non-bannable sources never count: UDP is spoofable and the
// other addresses are never real scanners.
func (s *Sensor) touchScan(info SessionInfo) bool {
	if info.Transport != TransportTCP || s.Ignored(info.SourceIP) {
		return false
	}
	addr, ok := parseBannableIP(info.SourceIP)
	if !ok {
		return false
	}
	return s.scan.TouchPort(addr.String(), info.Protocol, info.DestPort)
}

// Ignored reports whether ip is in the ignore list. IPv4-mapped IPv6 addresses
// are unmapped before matching.
func (s *Sensor) Ignored(ip string) bool {
	return config.MatchesPrefixes(s.ignore, ip)
}

// Shunned reports whether new connections from ip must be refused at accept
// time (RAN_SHUN). Every accept path calls it, so the ignore list applies in one
// place: an ignored source is never shunned.
func (s *Sensor) Shunned(ip string) bool {
	if !s.offenders.ShunEnabled() || s.Ignored(ip) {
		return false
	}
	return s.offenders.Shunned(ip)
}

// ShunRejected records one connection refused because Shunned was true. It
// counts it in the shun summary of the source and in the rejection metric.
func (s *Sensor) ShunRejected(ip, protocol string) {
	s.offenders.Rejected(ip, protocol)
}

func (s *Sensor) classify(info SessionInfo) Class {
	if s.touchScan(info) {
		return ClassScan
	}
	return Classify(info)
}

func (s *Sensor) submit(ctx context.Context, ev Event) {
	if s.sink != nil {
		s.sink.Submit(ctx, ev)
	}
}

// Alert implements Alerter.
func (s *Sensor) Alert(ctx context.Context, info SessionInfo, meta map[string]string) Class {
	// Defense in depth: UDP sources are spoofable and must never alert, even if a
	// UDP trap is ever wired to the sensor.
	if info.Transport != TransportTCP {
		return ""
	}
	// An ignored source is served and logged but never classified, tracked or
	// reported.
	if s.Ignored(info.SourceIP) {
		return ""
	}
	class := s.classify(info)
	s.submit(ctx, Event{Class: class, Info: info, Meta: meta})
	return class
}

// SessionEnd implements Alerter. It reports an escalation that happened after
// the last Alert call (including pure probes and scans whose triggering session
// sent nothing) and aggregates the log output of probe sessions.
func (s *Sensor) SessionEnd(info SessionInfo) bool {
	// Ignored sources are never summarized: their sessions log per session.
	if info.Transport != TransportTCP || s.Ignored(info.SourceIP) {
		return false
	}
	class := s.classify(info)
	if class.rank() > info.AlertedClass.rank() {
		s.submit(context.Background(), Event{Class: class, Info: info})
	}
	if Classify(info) == ClassProbe && s.probes.window > 0 {
		// Record returns false after Close: the caller then logs the session itself.
		return s.probes.Record(info.SourceIP, info.Protocol)
	}
	return false
}

// Close stops the flusher, writes pending probe summaries and closes the sink.
func (s *Sensor) Close() {
	s.CloseContext(context.Background())
}

// contextCloser is implemented by sinks that can honor a shutdown deadline.
type contextCloser interface{ CloseContext(ctx context.Context) }

// CloseContext is Close with a shutdown budget: a sink that supports it gets the
// remaining time of ctx for its final drain.
func (s *Sensor) CloseContext(ctx context.Context) {
	s.closeOnce.Do(func() {
		close(s.stop)
		s.wg.Wait()
		s.probes.closeAndFlush()
		s.offenders.Flush()
		switch sink := s.sink.(type) {
		case nil:
		case contextCloser:
			sink.CloseContext(ctx)
		default:
			sink.Close()
		}
	})
}

type probeEntry struct {
	ip       string
	start    time.Time
	sessions int
	protos   map[string]int
}

// probeLog aggregates probe sessions per source IP and window into one summary
// log line. Entries are inserted once and never re-ordered, so the FIFO list is
// ordered by window start and flushing only inspects the front. When the map is
// full the oldest entry is written out immediately, so no data is lost.
type probeLog struct {
	stats      *trackStats
	suppressed prometheus.Counter
	mu         sync.Mutex
	entries    map[string]*list.Element
	order      *list.List
	window     time.Duration
	maxEntries int
	logger     *slog.Logger
	nowFunc    func() time.Time
	closed     bool
}

func newProbeLog(window time.Duration, maxEntries int, logger *slog.Logger) *probeLog {
	return &probeLog{
		entries:    make(map[string]*list.Element),
		order:      list.New(),
		window:     window,
		maxEntries: maxEntries,
		logger:     logger,
		nowFunc:    time.Now,
	}
}

// Record adds one probe session for ip and protocol. It returns false when the
// log is closed; the caller must then log the session itself.
// The key is normalized, so mapped and plain IPv4 forms share one summary line.
func (p *probeLog) Record(rawIP, protocol string) bool {
	ip := rawIP
	if addr, err := netip.ParseAddr(rawIP); err == nil {
		ip = addr.Unmap().String()
	}
	now := p.nowFunc()
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return false
	}

	el, ok := p.entries[ip]
	if ok && now.Sub(el.Value.(*probeEntry).start) >= p.window {
		p.emit(el, now)
		ok = false
	}
	if !ok {
		if len(p.entries) >= p.maxEntries {
			if front := p.order.Front(); front != nil {
				p.stats.evicted()
				p.emit(front, now)
			}
		}
		el = p.order.PushBack(&probeEntry{ip: ip, start: now, protos: make(map[string]int, 2)})
		p.entries[ip] = el
		p.stats.size(len(p.entries))
	}
	e := el.Value.(*probeEntry)
	e.sessions++
	e.protos[protocol]++
	if p.suppressed != nil {
		p.suppressed.Inc()
	}
	return true
}

// emit writes the summary line for el and removes it. Callers hold mu.
func (p *probeLog) emit(el *list.Element, now time.Time) {
	e := el.Value.(*probeEntry)
	delete(p.entries, e.ip)
	p.order.Remove(el)
	p.stats.size(len(p.entries))
	elapsed := now.Sub(e.start)
	if elapsed > p.window {
		elapsed = p.window
	}
	p.logger.Info("probe summary",
		"action", "probe_summary",
		"class", string(ClassProbe),
		"source_ip", e.ip,
		"window_seconds", int(elapsed.Seconds()),
		"sessions", e.sessions,
		"protocols", e.protos,
	)
}

// flushDue writes summaries for every entry whose window has elapsed.
func (p *probeLog) flushDue() {
	now := p.nowFunc()
	p.mu.Lock()
	defer p.mu.Unlock()
	for el := p.order.Front(); el != nil; el = p.order.Front() {
		if now.Sub(el.Value.(*probeEntry).start) < p.window {
			return
		}
		p.emit(el, now)
	}
}

// closeAndFlush rejects further records and writes every pending summary, so a
// straggler session cannot create an entry that is never logged.
func (p *probeLog) closeAndFlush() {
	p.mu.Lock()
	p.closed = true
	p.mu.Unlock()
	p.flushAll()
}

// flushAll writes summaries for every pending entry.
func (p *probeLog) flushAll() {
	now := p.nowFunc()
	p.mu.Lock()
	defer p.mu.Unlock()
	for el := p.order.Front(); el != nil; el = p.order.Front() {
		p.emit(el, now)
	}
}
