package alert

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"

	"github.com/st0o0/ran/internal/metrics"
)

func testOffenders(t *testing.T, cfg offenderConfig) (*offenderTable, *fakeClock, *lockedBuffer) {
	t.Helper()
	buf := &lockedBuffer{}
	clk := newFakeClock()
	cfg.Now = clk.Now
	return newOffenderTable(cfg, slog.New(slog.NewJSONHandler(buf, nil))), clk, buf
}

func counterValue(t *testing.T, c prometheus.Collector) float64 {
	t.Helper()
	ch := make(chan prometheus.Metric, 8)
	c.Collect(ch)
	close(ch)
	var sum float64
	for m := range ch {
		var d dto.Metric
		if err := m.Write(&d); err != nil {
			t.Fatal(err)
		}
		switch {
		case d.Counter != nil:
			sum += d.Counter.GetValue()
		case d.Gauge != nil:
			sum += d.Gauge.GetValue()
		}
	}
	return sum
}

func TestShunWindowOpensAndEnds(t *testing.T) {
	t.Parallel()
	o, clk, _ := testOffenders(t, offenderConfig{Shun: true})
	ip := "8.8.8.8"
	if o.shunned(ip) {
		t.Fatal("shunned before any alert")
	}
	o.accepted(ip, ClassAttack, time.Hour)
	if !o.shunned(ip) {
		t.Fatal("not shunned right after an accepted alert")
	}
	if o.shunned("1.1.1.1") {
		t.Error("another source is shunned")
	}
	clk.Advance(59 * time.Minute)
	if !o.shunned(ip) {
		t.Error("window ended early")
	}
	clk.Advance(2 * time.Minute)
	if o.shunned(ip) {
		t.Error("still shunned after the window")
	}
}

func TestShunAppliesToAllClassesOfTheSource(t *testing.T) {
	t.Parallel()
	o, _, _ := testOffenders(t, offenderConfig{Shun: true})
	o.accepted("8.8.8.8", ClassScan, time.Hour)
	// The IPv4-mapped form is the same source.
	if !o.shunned("::ffff:8.8.8.8") {
		t.Error("mapped address is not shunned")
	}
}

func TestShunOffByDefaultAndProbeNeverShuns(t *testing.T) {
	t.Parallel()
	off, _, _ := testOffenders(t, offenderConfig{})
	off.accepted("8.8.8.8", ClassAttack, time.Hour)
	if off.shunned("8.8.8.8") {
		t.Error("shunned with shun off")
	}
	on, _, _ := testOffenders(t, offenderConfig{Shun: true})
	on.accepted("8.8.8.8", ClassProbe, time.Hour)
	if on.shunned("8.8.8.8") {
		t.Error("probe alert started a shun")
	}
	on.accepted("8.8.4.4", ClassAttack, 0)
	if on.shunned("8.8.4.4") {
		t.Error("zero window started a shun")
	}
}

func TestNilOffenderTableIsInert(t *testing.T) {
	t.Parallel()
	var o *offenderTable
	o.accepted("8.8.8.8", ClassAttack, time.Hour)
	o.rejected("8.8.8.8", "ssh")
	o.sweep()
	o.flush()
	if o.shunned("8.8.8.8") || o.shunEnabled() || o.length() != 0 {
		t.Error("nil table reported state")
	}
	if got := o.windowFor("8.8.8.8", ClassAttack, time.Hour); got != time.Hour {
		t.Errorf("windowFor = %v, want the base window", got)
	}
}

func TestWindowForRepeatThreshold(t *testing.T) {
	t.Parallel()
	o, clk, _ := testOffenders(t, offenderConfig{RepeatAfter: 3, RepeatCooldown: 12 * time.Hour})
	ip := "8.8.8.8"
	base := time.Hour
	for i := 1; i <= 5; i++ {
		got := o.windowFor(ip, ClassAttack, base)
		want := base
		if i >= 3 {
			want = 12 * time.Hour
		}
		if got != want {
			t.Errorf("alert %d: window %v, want %v", i, got, want)
		}
		o.accepted(ip, ClassAttack, got)
		clk.Advance(time.Minute)
	}
	// Another class counts separately.
	if got := o.windowFor(ip, ClassScan, base); got != base {
		t.Errorf("scan window = %v, want base", got)
	}
	// A disabled cooldown stays disabled.
	if got := o.windowFor(ip, ClassAttack, 0); got != 0 {
		t.Errorf("window with base 0 = %v, want 0", got)
	}
}

func TestWindowForUnsetRepeatKeepsBase(t *testing.T) {
	t.Parallel()
	o, _, _ := testOffenders(t, offenderConfig{RepeatAfter: 1})
	o.accepted("8.8.8.8", ClassAttack, time.Hour)
	if got := o.windowFor("8.8.8.8", ClassAttack, time.Hour); got != time.Hour {
		t.Errorf("window = %v, want base without a repeat cooldown", got)
	}
}

func TestRepeatCountsResetAfterSilence(t *testing.T) {
	t.Parallel()
	o, clk, _ := testOffenders(t, offenderConfig{RepeatAfter: 2, RepeatCooldown: 12 * time.Hour})
	ip := "8.8.8.8"
	o.accepted(ip, ClassAttack, time.Hour)
	if got := o.windowFor(ip, ClassAttack, time.Hour); got != 12*time.Hour {
		t.Fatalf("window = %v, want the repeat cooldown", got)
	}
	clk.Advance(defaultOffenderReset + time.Second)
	if got := o.windowFor(ip, ClassAttack, time.Hour); got != time.Hour {
		t.Errorf("window after silence = %v, want base", got)
	}
	o.accepted(ip, ClassAttack, time.Hour)
	if n := o.length(); n != 1 {
		t.Errorf("table holds %d entries, want 1 after expiry and re-insert", n)
	}
}

func TestSummaryAtWindowEndLazily(t *testing.T) {
	t.Parallel()
	o, clk, buf := testOffenders(t, offenderConfig{Shun: true})
	ip := "8.8.8.8"
	o.accepted(ip, ClassAttack, time.Hour)
	for i := 0; i < 5; i++ {
		o.rejected(ip, "ssh")
		o.rejected(ip, "telnet")
		clk.Advance(time.Minute)
	}
	if strings.Contains(buf.String(), "shun summary") {
		t.Fatal("summary written while the window is open")
	}
	clk.Advance(time.Hour)
	if o.shunned(ip) {
		t.Fatal("still shunned")
	}
	out := buf.String()
	if n := strings.Count(out, "shun summary"); n != 1 {
		t.Fatalf("got %d summary lines, want 1:\n%s", n, out)
	}
	for _, want := range []string{`"source_ip":"8.8.8.8"`, `"count":10`, `"protocols":["ssh","telnet"]`, `"window_seconds":3600`} {
		if !strings.Contains(out, want) {
			t.Errorf("summary misses %s:\n%s", want, out)
		}
	}
	// No second line for the same window.
	o.sweep()
	o.flush()
	if n := strings.Count(buf.String(), "shun summary"); n != 1 {
		t.Errorf("got %d summary lines after sweep and flush, want 1", n)
	}
}

func TestSummaryBySweepOnlyWhenSuppressed(t *testing.T) {
	t.Parallel()
	o, clk, buf := testOffenders(t, offenderConfig{Shun: true})
	o.accepted("8.8.8.8", ClassAttack, time.Hour)
	o.accepted("1.1.1.1", ClassAttack, time.Hour)
	o.rejected("8.8.8.8", "rdp")
	clk.Advance(2 * time.Hour)
	o.sweep()
	out := buf.String()
	if strings.Count(out, "shun summary") != 1 || !strings.Contains(out, `"source_ip":"8.8.8.8"`) {
		t.Errorf("want exactly one summary for 8.8.8.8:\n%s", out)
	}
}

func TestSummaryFlushAtShutdown(t *testing.T) {
	t.Parallel()
	o, _, buf := testOffenders(t, offenderConfig{Shun: true})
	o.accepted("8.8.8.8", ClassAttack, time.Hour)
	o.rejected("8.8.8.8", "smb")
	o.rejected("8.8.8.8", "smb")
	o.flush()
	out := buf.String()
	if strings.Count(out, "shun summary") != 1 || !strings.Contains(out, `"count":2`) {
		t.Errorf("flush output:\n%s", out)
	}
	if !o.shunned("8.8.8.8") {
		t.Error("flush closed the window")
	}
	// Counting restarts after the flush; no empty second summary.
	o.flush()
	if strings.Count(buf.String(), "shun summary") != 1 {
		t.Error("second flush wrote an empty summary")
	}
}

func TestSummaryProtocolListIsBounded(t *testing.T) {
	t.Parallel()
	o, _, buf := testOffenders(t, offenderConfig{Shun: true})
	o.accepted("8.8.8.8", ClassAttack, time.Hour)
	for i := 0; i < 50; i++ {
		o.rejected("8.8.8.8", fmt.Sprintf("p%02d", i))
	}
	o.flush()
	line := buf.String()
	if n := strings.Count(line, `"p0`) + strings.Count(line, `"p1`) + strings.Count(line, `"p2`) + strings.Count(line, `"p3`) + strings.Count(line, `"p4`); n != maxShunProtocols {
		t.Errorf("summary lists %d protocols, want %d:\n%s", n, maxShunProtocols, line)
	}
	if !strings.Contains(line, `"count":50`) {
		t.Errorf("count is not exact:\n%s", line)
	}
}

func TestEvictionWritesSummaryAndStaysBounded(t *testing.T) {
	t.Parallel()
	o, _, buf := testOffenders(t, offenderConfig{Shun: true, MaxEntries: 3})
	for i := 1; i <= 3; i++ {
		o.accepted(fmt.Sprintf("8.8.8.%d", i), ClassAttack, time.Hour)
	}
	o.rejected("8.8.8.1", "ssh")
	o.accepted("8.8.8.4", ClassAttack, time.Hour)
	if n := o.length(); n != 3 {
		t.Fatalf("table holds %d entries, want 3", n)
	}
	if o.shunned("8.8.8.1") {
		t.Error("evicted entry is still shunned")
	}
	if !o.shunned("8.8.8.4") || !o.shunned("8.8.8.2") {
		t.Error("live entries lost")
	}
	if !strings.Contains(buf.String(), `"source_ip":"8.8.8.1"`) {
		t.Errorf("eviction wrote no summary:\n%s", buf.String())
	}
}

func TestOffenderTableSoak(t *testing.T) {
	t.Parallel()
	const capEntries = 500
	o, clk, _ := testOffenders(t, offenderConfig{Shun: true, MaxEntries: capEntries})
	for i := 0; i < 200000; i++ {
		ip := netip.AddrFrom4([4]byte{byte(11 + i>>16), byte(i >> 8), byte(i), 7}).String()
		o.accepted(ip, ClassAttack, time.Hour)
		if i%7 == 0 {
			o.rejected(ip, "ssh")
		}
		if i%1000 == 0 {
			clk.Advance(time.Second)
			o.sweep()
		}
		if n := o.length(); n > capEntries {
			t.Fatalf("table grew to %d entries, cap %d", n, capEntries)
		}
		o.mu.Lock()
		a := len(o.active)
		o.mu.Unlock()
		if a > capEntries {
			t.Fatalf("active set grew to %d, cap %d", a, capEntries)
		}
	}
}

func TestSweepRemovesSilentEntries(t *testing.T) {
	t.Parallel()
	o, clk, _ := testOffenders(t, offenderConfig{Shun: true})
	o.accepted("8.8.8.8", ClassAttack, time.Hour)
	clk.Advance(defaultOffenderReset + time.Minute)
	o.sweep()
	if n := o.length(); n != 0 {
		t.Errorf("table holds %d entries after the silence, want 0", n)
	}
}

func TestMetricsRejectedAndActive(t *testing.T) {
	t.Parallel()
	m := metrics.New(prometheus.NewRegistry(), "test")
	o, clk, _ := testOffenders(t, offenderConfig{Shun: true, Metrics: m})
	o.accepted("8.8.8.8", ClassAttack, time.Hour)
	o.rejected("8.8.8.8", "ssh")
	o.rejected("8.8.8.8", "ssh")
	if v := counterValue(t, m.ConnectionsRejected); v != 2 {
		t.Errorf("rejected counter = %v, want 2", v)
	}
	if v := counterValue(t, m.ShunActive); v != 1 {
		t.Errorf("active gauge = %v, want 1", v)
	}
	clk.Advance(2 * time.Hour)
	o.sweep()
	if v := counterValue(t, m.ShunActive); v != 0 {
		t.Errorf("active gauge after the window = %v, want 0", v)
	}
}

func TestSensorShunnedAppliesIgnoreList(t *testing.T) {
	t.Parallel()
	a, _ := newOffenderCrowdSec(t, time.Hour, func(c *CrowdSecConfig) { c.Shun = true })
	buf := &lockedBuffer{}
	logger := slog.New(slog.NewJSONHandler(buf, nil))
	s := newSensor(SensorConfig{IgnoreIPs: []netip.Prefix{netip.MustParsePrefix("8.8.8.0/24")}}, a, logger)
	if !s.ShunActive() {
		t.Fatal("sensor did not discover the shun gate of its sink")
	}
	// An ignored source can only get into the table through a bug; the sensor
	// check must still refuse to shun it.
	a.offenders.accepted("8.8.8.8", ClassAttack, time.Hour)
	a.offenders.accepted("1.1.1.1", ClassAttack, time.Hour)
	if s.Shunned("8.8.8.8") {
		t.Error("ignored source is shunned")
	}
	if !s.Shunned("1.1.1.1") {
		t.Error("non-ignored source is not shunned")
	}
	bare := newSensor(SensorConfig{}, nil, logger)
	if bare.Shunned("1.1.1.1") || bare.ShunActive() {
		t.Error("sensor without a sink shuns")
	}
	bare.ShunRejected("1.1.1.1", "ssh")
	// A sink with the table but shun off: the gate is found, shunning stays off.
	off, _ := newOffenderCrowdSec(t, time.Hour, nil)
	offSensor := newSensor(SensorConfig{}, off, logger)
	off.offenders.accepted("1.1.1.1", ClassAttack, time.Hour)
	if offSensor.ShunActive() || offSensor.Shunned("1.1.1.1") {
		t.Error("sensor shuns with RAN_SHUN off")
	}
}

// newOffenderCrowdSec builds a CrowdSec sink on a fake LAPI. The sink owns the
// offender table and uses the fake clock for the table and the cooldown.
func newOffenderCrowdSec(t *testing.T, cooldown time.Duration, mutate func(*CrowdSecConfig)) (*CrowdSecAlerter, *fakeClock) {
	t.Helper()
	srv := testServer(t, "ran", "secret", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) })
	t.Cleanup(srv.Close)
	clk := newFakeClock()
	cfg := testConfig(srv.URL)
	cfg.Cooldown = cooldown
	cfg.Now = clk.Now
	if mutate != nil {
		mutate(&cfg)
	}
	a, err := NewCrowdSec(context.Background(), cfg, slog.Default(), testMetrics(t))
	if err != nil {
		t.Fatal(err)
	}
	a.cooldown.nowFunc = clk.Now
	t.Cleanup(a.Close)
	return a, clk
}

func TestRepeatCooldownThroughCrowdSec(t *testing.T) {
	t.Parallel()
	a, clk := newOffenderCrowdSec(t, time.Hour, func(c *CrowdSecConfig) {
		c.Shun, c.RepeatAfter, c.RepeatCooldown = true, 2, 12*time.Hour
	})
	ip := "8.8.8.8"
	ctx := context.Background()

	a.Submit(ctx, ev(ip, "ssh")) // alert 1, window 1h
	if !a.Shunned(ip) {
		t.Fatal("no shun after the first accepted alert")
	}
	clk.Advance(30 * time.Minute)
	a.Submit(ctx, ev(ip, "ssh")) // within the cooldown: filtered
	clk.Advance(31 * time.Minute)
	if a.Shunned(ip) {
		t.Fatal("shun window is longer than the cooldown")
	}
	a.Submit(ctx, ev(ip, "ssh")) // alert 2, window 12h
	clk.Advance(2 * time.Hour)
	if !a.Shunned(ip) {
		t.Error("shun window did not become the repeat cooldown")
	}
	a.Submit(ctx, ev(ip, "ssh")) // still inside 12h: filtered
	clk.Advance(9 * time.Hour)
	if !a.Shunned(ip) {
		t.Error("shun ended before 12h")
	}
	clk.Advance(2 * time.Hour)
	if a.Shunned(ip) {
		t.Error("shun lasted beyond 12h")
	}
	a.Submit(ctx, ev(ip, "ssh")) // alert 3, allowed after 12h
	if !a.Shunned(ip) {
		t.Error("third alert after the repeat cooldown was not accepted")
	}
}

func TestFilteredAlertsDoNotShun(t *testing.T) {
	t.Parallel()
	a, _ := newOffenderCrowdSec(t, time.Hour, func(c *CrowdSecConfig) { c.Shun = true })
	// Probe is not in the default BanOn: filtered, never accepted.
	a.Submit(context.Background(), evClass("8.8.8.8", "ssh", ClassProbe))
	if a.Shunned("8.8.8.8") || a.offenders.length() != 0 {
		t.Error("filtered probe alert reached the offender table")
	}
	// Invalid (private) source: rejected before the cooldown.
	a.Submit(context.Background(), ev("10.0.0.1", "ssh"))
	if a.offenders.length() != 0 {
		t.Error("invalid source reached the offender table")
	}
}

// blockingHandler signals entered and then blocks in Handle until release is closed.
type blockingHandler struct {
	entered chan struct{}
	release chan struct{}
	once    sync.Once
}

func (h *blockingHandler) Enabled(context.Context, slog.Level) bool { return true }
func (h *blockingHandler) Handle(context.Context, slog.Record) error {
	h.once.Do(func() { close(h.entered) })
	<-h.release
	return nil
}
func (h *blockingHandler) WithAttrs([]slog.Attr) slog.Handler { return h }
func (h *blockingHandler) WithGroup(string) slog.Handler      { return h }

func TestSlowLogHandlerDoesNotHoldTableLock(t *testing.T) {
	t.Parallel()
	h := &blockingHandler{entered: make(chan struct{}), release: make(chan struct{})}
	clk := newFakeClock()
	o := newOffenderTable(offenderConfig{Shun: true, Now: clk.Now}, slog.New(h))
	const a, b = "8.8.8.8", "1.1.1.1"
	o.accepted(a, ClassAttack, time.Minute)
	o.rejected(a, "ssh")
	o.accepted(b, ClassAttack, 24*time.Hour)
	clk.Advance(2 * time.Minute) // a's window has ended, b's is open

	first := make(chan struct{})
	go func() {
		defer close(first)
		o.shunned(a) // closes the window and logs the summary; the handler blocks
	}()
	<-h.entered

	second := make(chan bool)
	go func() { second <- o.shunned(b) }()
	if got := <-second; !got {
		t.Error("b should still be shunned")
	}
	close(h.release)
	<-first
}
