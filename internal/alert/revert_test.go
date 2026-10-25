package alert

import (
	"context"
	"log/slog"
	"math"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// failingCrowdSec builds a sink whose fake LAPI answers 503 while fail is set.
func failingCrowdSec(t *testing.T, fail *atomic.Bool, mutate func(*CrowdSecConfig)) (*CrowdSecAlerter, *fakeClock) {
	t.Helper()
	setPacing(t, time.Millisecond, time.Hour)
	srv := testServer(t, "ran", "secret", func(w http.ResponseWriter, r *http.Request) {
		if fail.Load() {
			w.WriteHeader(503)
			return
		}
		w.WriteHeader(200)
	})
	t.Cleanup(srv.Close)
	clk := newFakeClock()
	cfg := testConfig(srv.URL)
	cfg.Cooldown = time.Hour
	cfg.Shun = true
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

func offenderCounts(a *CrowdSecAlerter, ip string) ([3]int, bool) {
	a.offenders.mu.Lock()
	defer a.offenders.mu.Unlock()
	e := a.offenders.entries[ip]
	if e == nil {
		return [3]int{}, false
	}
	return e.counts, true
}

func TestFailedPushRevertsShunAndCounters(t *testing.T) {
	var fail atomic.Bool
	a, clk := failingCrowdSec(t, &fail, func(c *CrowdSecConfig) { c.RepeatAfter = 3 })
	ctx := context.Background()
	const ip = "8.8.8.8"

	// One alert that reached the LAPI.
	a.Submit(ctx, ev(ip, "ssh"))
	waitFor(t, "first alert sent", func() bool { return pipelineCount(t, a.metrics, "ssh", "sent") == 1 })
	clk.Advance(2 * time.Hour)
	if a.Shunned(ip) {
		t.Fatal("first window did not end")
	}
	before, _ := offenderCounts(a, ip)
	if before[1] != 1 {
		t.Fatalf("attack count = %d, want 1", before[1])
	}

	// The next alert fails to push.
	fail.Store(true)
	a.Submit(ctx, ev(ip, "ssh"))
	if !a.Shunned(ip) {
		t.Fatal("not shunned right after the accepted alert")
	}
	waitFor(t, "failed push released", func() bool { return pipelineCount(t, a.metrics, "ssh", "released") == 1 })
	if a.Shunned(ip) {
		t.Error("source stays shunned after the push failed")
	}
	if after, _ := offenderCounts(a, ip); after != before {
		t.Errorf("counts after failed push = %v, want %v", after, before)
	}

	// The retry alert is accepted and shuns again.
	fail.Store(false)
	a.Submit(ctx, ev(ip, "ssh"))
	waitFor(t, "retry sent", func() bool { return pipelineCount(t, a.metrics, "ssh", "sent") == 2 })
	if !a.Shunned(ip) {
		t.Error("retry alert did not shun the source")
	}
	if got, _ := offenderCounts(a, ip); got[1] != 2 {
		t.Errorf("attack count after retry = %d, want 2", got[1])
	}
}

func TestFailedFirstPushForgetsTheSource(t *testing.T) {
	var fail atomic.Bool
	fail.Store(true)
	a, _ := failingCrowdSec(t, &fail, nil)
	a.Submit(context.Background(), ev("8.8.8.8", "ssh"))
	waitFor(t, "failed push released", func() bool { return pipelineCount(t, a.metrics, "ssh", "released") == 1 })
	if a.Shunned("8.8.8.8") || a.offenders.length() != 0 {
		t.Errorf("source still tracked after a failed first push (entries %d)", a.offenders.length())
	}
}

func TestRevertWritesSummaryForSuppressedConnections(t *testing.T) {
	t.Parallel()
	o, _, buf := testOffenders(t, offenderConfig{Shun: true})
	m := o.accepted("8.8.8.8", ClassAttack, time.Hour)
	o.rejected("8.8.8.8", "ssh")
	o.rejected("8.8.8.8", "ssh")
	o.revert(m)
	if o.shunned("8.8.8.8") {
		t.Error("window still open after revert")
	}
	if out := buf.String(); !strings.Contains(out, `"count":2`) {
		t.Errorf("no summary for the suppressed connections:\n%s", out)
	}
	o2, _, buf2 := testOffenders(t, offenderConfig{Shun: true})
	o2.revert(o2.accepted("8.8.8.8", ClassAttack, time.Hour))
	if buf2.String() != "" {
		t.Errorf("summary written without suppressed connections:\n%s", buf2.String())
	}
}

func TestRevertKeepsExtendedWindow(t *testing.T) {
	t.Parallel()
	o, clk, _ := testOffenders(t, offenderConfig{Shun: true})
	opener := o.accepted("8.8.8.8", ClassAttack, time.Hour)
	clk.Advance(time.Minute)
	extender := o.accepted("8.8.8.8", ClassScan, time.Hour)
	o.revert(opener)
	if !o.shunned("8.8.8.8") {
		t.Fatal("reverting the opener closed a window another alert extended")
	}
	o.revert(extender)
	if !o.shunned("8.8.8.8") {
		t.Error("an extending alert closed the window it did not open")
	}
	// Counters are restored per class.
	o.mu.Lock()
	c := o.entries["8.8.8.8"].counts
	o.mu.Unlock()
	if c != [3]int{} {
		t.Errorf("counts = %v, want all zero", c)
	}
}

func TestRevertIsHarmlessAfterEviction(t *testing.T) {
	t.Parallel()
	o, _, _ := testOffenders(t, offenderConfig{Shun: true, MaxEntries: 1})
	m := o.accepted("8.8.8.8", ClassAttack, time.Hour)
	o.accepted("1.1.1.1", ClassAttack, time.Hour)
	o.revert(m)
	o.revert(acceptMark{})
	var nilTable *offenderTable
	nilTable.revert(m)
	if !o.shunned("1.1.1.1") || o.length() != 1 {
		t.Error("revert of an evicted entry disturbed the table")
	}
}

func TestEvictionPrefersEntriesWithoutActiveShun(t *testing.T) {
	t.Parallel()
	o, _, _ := testOffenders(t, offenderConfig{Shun: true, MaxEntries: 3})
	o.accepted("8.8.8.1", ClassAttack, time.Hour) // active, oldest
	o.accepted("8.8.8.2", ClassProbe, time.Hour)  // no window
	o.accepted("8.8.8.3", ClassAttack, time.Hour) // active
	o.accepted("8.8.8.4", ClassAttack, time.Hour) // needs room
	if !o.shunned("8.8.8.1") || !o.shunned("8.8.8.3") || !o.shunned("8.8.8.4") {
		t.Error("an active shun was evicted while an entry without one existed")
	}
	o.mu.Lock()
	_, kept := o.entries["8.8.8.2"]
	o.mu.Unlock()
	if kept {
		t.Error("the entry without a shun window was not the victim")
	}
	// Every entry active: plain FIFO again.
	o.accepted("8.8.8.5", ClassAttack, time.Hour)
	if o.shunned("8.8.8.1") || !o.shunned("8.8.8.5") || o.length() != 3 {
		t.Error("with only active entries the oldest must be evicted")
	}
}

func TestEvictionScanIsBounded(t *testing.T) {
	t.Parallel()
	n := evictScan + 8
	o, _, _ := testOffenders(t, offenderConfig{Shun: true, MaxEntries: n})
	for i := 0; i < n-1; i++ {
		o.accepted(wideIP(i), ClassAttack, time.Hour)
	}
	o.accepted(wideIP(n), ClassProbe, time.Hour) // inactive, beyond the scan window
	o.accepted(wideIP(n+1), ClassAttack, time.Hour)
	if o.length() != n {
		t.Fatalf("table holds %d entries, want %d", o.length(), n)
	}
	if o.shunned(wideIP(0)) {
		t.Error("beyond the scan bound the oldest entry is evicted")
	}
}

func TestOffenderResetDoesNotOverflow(t *testing.T) {
	t.Parallel()
	for _, rc := range []time.Duration{time.Hour, 24 * 365 * time.Hour, math.MaxInt64/2 + 1, math.MaxInt64} {
		o, clk, _ := testOffenders(t, offenderConfig{Shun: true, RepeatCooldown: rc})
		if o.reset <= 0 || o.reset < rc && rc <= math.MaxInt64/2 {
			t.Errorf("repeat %s: reset %s", rc, o.reset)
		}
		o.accepted("8.8.8.8", ClassAttack, time.Hour)
		clk.Advance(time.Minute)
		o.sweep()
	}
}
