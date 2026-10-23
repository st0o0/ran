package alert

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

type recordingSink struct {
	mu     sync.Mutex
	events []Event
	closed bool
}

func (r *recordingSink) Submit(_ context.Context, ev Event) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.events = append(r.events, ev)
}

func (r *recordingSink) Close() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.closed = true
}

func (r *recordingSink) snapshot() []Event {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]Event(nil), r.events...)
}

type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func newFakeClock() *fakeClock { return &fakeClock{now: time.Unix(1_700_000_000, 0)} }

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

// testSensor builds a Sensor without background goroutines and with a fake clock.
func testSensor(t *testing.T, window time.Duration, maxTracked int) (*Sensor, *recordingSink, *fakeClock, *lockedBuffer) {
	t.Helper()
	buf := &lockedBuffer{}
	logger := slog.New(slog.NewJSONHandler(buf, nil))
	sink := &recordingSink{}
	s := newSensor(SensorConfig{MaxTracked: maxTracked, SummaryWindow: window}, sink, logger)
	clk := newFakeClock()
	s.scan.nowFunc = clk.Now
	s.probes.nowFunc = clk.Now
	return s, sink, clk, buf
}

func tcpInfo(ip, proto string) SessionInfo {
	return SessionInfo{SourceIP: ip, Protocol: proto, Transport: "tcp", DestPort: 1}
}

func TestClassify(t *testing.T) {
	cases := []struct {
		name string
		info SessionInfo
		want Class
	}{
		{"connect only", SessionInfo{}, ClassProbe},
		{"auth attempt", SessionInfo{AuthAttempts: 1}, ClassAttack},
		{"command", SessionInfo{Commands: 1}, ClassAttack},
		{"payload bytes", SessionInfo{PayloadBytes: 1}, ClassAttack},
	}
	for _, c := range cases {
		if got := Classify(c.info); got != c.want {
			t.Errorf("%s: class = %s, want %s", c.name, got, c.want)
		}
	}
}

func TestScanThreeProtocolsWithinWindow(t *testing.T) {
	s, sink, clk, _ := testSensor(t, 0, 100)
	ctx := context.Background()
	ip := "8.8.8.8"
	for i, proto := range []string{"ssh", "redis", "vnc"} {
		info := tcpInfo(ip, proto)
		info.AuthAttempts = 1
		got := s.Alert(ctx, info, nil)
		want := ClassAttack
		if i == 2 {
			want = ClassScan
		}
		if got != want {
			t.Errorf("session %d (%s): class = %s, want %s", i, proto, got, want)
		}
		clk.Advance(time.Minute)
	}
	if n := len(sink.snapshot()); n != 3 {
		t.Errorf("sink got %d events, want 3", n)
	}
}

func TestScanIgnoresUDP(t *testing.T) {
	s, _, _, _ := testSensor(t, 0, 100)
	for _, proto := range []string{"dns", "snmp", "ntp", "sip"} {
		info := SessionInfo{SourceIP: "8.8.8.8", Protocol: proto, Transport: "udp", AuthAttempts: 1}
		if got := s.Alert(context.Background(), info, nil); got == ClassScan {
			t.Errorf("udp %s produced scan", proto)
		}
	}
	if s.scan.len() != 0 {
		t.Errorf("scan tracker has %d entries, want 0 (UDP never tracked)", s.scan.len())
	}
}

func TestScanWindowExpiry(t *testing.T) {
	s, _, clk, _ := testSensor(t, 0, 100)
	ip := "8.8.8.8"
	for _, proto := range []string{"ssh", "redis", "vnc"} {
		info := tcpInfo(ip, proto)
		info.Commands = 1
		if got := s.Alert(context.Background(), info, nil); got == ClassScan {
			t.Fatalf("%s classified scan too early", proto)
		}
		// 6 minutes apart: ssh is older than 10 minutes when vnc arrives.
		clk.Advance(6 * time.Minute)
	}
}

func TestScanRepeatedProtocolDoesNotCount(t *testing.T) {
	s, _, _, _ := testSensor(t, 0, 100)
	for range 10 {
		info := tcpInfo("8.8.8.8", "ssh")
		info.AuthAttempts = 1
		if got := s.Alert(context.Background(), info, nil); got != ClassAttack {
			t.Fatalf("class = %s, want attack", got)
		}
	}
}

func TestScanIgnoresNonGlobalSources(t *testing.T) {
	s, _, _, _ := testSensor(t, 0, 100)
	for _, proto := range []string{"ssh", "redis", "vnc"} {
		info := tcpInfo("10.0.0.5", proto)
		info.AuthAttempts = 1
		if got := s.Alert(context.Background(), info, nil); got == ClassScan {
			t.Errorf("private source classified scan")
		}
	}
	if s.scan.len() != 0 {
		t.Errorf("scan tracker has %d entries, want 0", s.scan.len())
	}
}

func TestScanTrackerCapEvictsOldest(t *testing.T) {
	clk := newFakeClock()
	tr := newScanTracker(scanWindow, scanProtocols, 5)
	tr.nowFunc = clk.Now
	for i := 0; i < 50; i++ {
		tr.Touch(testIP(i), "ssh")
		clk.Advance(time.Second)
		if tr.len() > 5 {
			t.Fatalf("size %d exceeds cap 5", tr.len())
		}
	}
	tr.mu.Lock()
	_, oldest := tr.entries[testIP(0)]
	_, newest := tr.entries[testIP(49)]
	invariant := tr.order.Len() == len(tr.entries)
	tr.mu.Unlock()
	if oldest {
		t.Error("oldest entry should have been evicted")
	}
	if !newest {
		t.Error("newest entry should be tracked")
	}
	if !invariant {
		t.Error("list and map sizes differ")
	}
}

func TestScanTrackerCleanupSweepsExpired(t *testing.T) {
	clk := newFakeClock()
	tr := newScanTracker(time.Minute, 3, 100)
	tr.nowFunc = clk.Now
	tr.Touch(testIP(1), "ssh")
	clk.Advance(30 * time.Second)
	tr.Touch(testIP(2), "ssh")
	clk.Advance(45 * time.Second)
	tr.cleanup()
	if tr.len() != 1 {
		t.Errorf("size = %d, want 1", tr.len())
	}
}

func TestScanTrackerFloodIsFast(t *testing.T) {
	clk := newFakeClock()
	tr := newScanTracker(time.Hour, 3, 1000)
	tr.nowFunc = clk.Now
	start := time.Now()
	for i := 0; i < 200000; i++ {
		tr.Touch("ip"+strconv.Itoa(i), "ssh")
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Errorf("200000 unique touches took %v, want well under 2s", elapsed)
	}
	if tr.len() != 1000 {
		t.Errorf("size = %d, want 1000", tr.len())
	}
}

func TestSessionEndProbeIsSubmittedAndAggregated(t *testing.T) {
	s, sink, _, _ := testSensor(t, time.Minute, 100)
	aggregated := s.SessionEnd(tcpInfo("8.8.8.8", "vnc"))
	if !aggregated {
		t.Error("probe session must be aggregated")
	}
	evs := sink.snapshot()
	if len(evs) != 1 || evs[0].Class != ClassProbe {
		t.Fatalf("events = %+v, want one probe event", evs)
	}
}

func TestSessionEndAggregationDisabled(t *testing.T) {
	s, _, _, _ := testSensor(t, 0, 100)
	if s.SessionEnd(tcpInfo("8.8.8.8", "vnc")) {
		t.Error("window 0 must keep per-session lines")
	}
}

func TestSessionEndAttackIsNotAggregated(t *testing.T) {
	s, sink, _, _ := testSensor(t, time.Minute, 100)
	info := tcpInfo("8.8.8.8", "ssh")
	info.AuthAttempts = 2
	if s.SessionEnd(info) {
		t.Error("attack session must keep full lines")
	}
	if evs := sink.snapshot(); len(evs) != 1 || evs[0].Class != ClassAttack {
		t.Fatalf("events = %+v, want one attack event", evs)
	}
}

func TestSessionEndDoesNotResubmitSameClass(t *testing.T) {
	s, sink, _, _ := testSensor(t, time.Minute, 100)
	info := tcpInfo("8.8.8.8", "ssh")
	info.AuthAttempts = 1
	class := s.Alert(context.Background(), info, nil)
	info.AlertedClass = class
	s.SessionEnd(info)
	if n := len(sink.snapshot()); n != 1 {
		t.Errorf("sink got %d events, want 1 (no duplicate at session end)", n)
	}
}

func TestSessionEndReportsEscalationAfterEarlyAlert(t *testing.T) {
	s, sink, _, _ := testSensor(t, time.Minute, 100)
	info := tcpInfo("8.8.8.8", "memcached")
	class := s.Alert(context.Background(), info, nil) // no counters yet: probe
	if class != ClassProbe {
		t.Fatalf("early class = %s, want probe", class)
	}
	info.AlertedClass = class
	info.Commands = 3
	s.SessionEnd(info)
	evs := sink.snapshot()
	if len(evs) != 2 || evs[1].Class != ClassAttack {
		t.Fatalf("events = %+v, want probe then attack", evs)
	}
}

func TestScanIsOwnAlertEvenIfTriggeringSessionWasProbe(t *testing.T) {
	s, sink, clk, _ := testSensor(t, time.Minute, 100)
	ip := "8.8.8.8"
	for _, proto := range []string{"ssh", "redis"} {
		info := tcpInfo(ip, proto)
		info.AuthAttempts = 1
		s.SessionEnd(info)
		clk.Advance(time.Second)
	}
	// The third session only connects and disconnects.
	aggregated := s.SessionEnd(tcpInfo(ip, "vnc"))
	if !aggregated {
		t.Error("the triggering probe session is still aggregated in the log")
	}
	evs := sink.snapshot()
	if len(evs) != 3 {
		t.Fatalf("got %d events, want 3", len(evs))
	}
	last := evs[2]
	if last.Class != ClassScan || last.Info.Protocol != "vnc" {
		t.Errorf("last event = %s/%s, want scan/vnc", last.Class, last.Info.Protocol)
	}
}

func TestSensorUDPSessionEndIsIgnored(t *testing.T) {
	s, sink, _, _ := testSensor(t, time.Minute, 100)
	info := SessionInfo{SourceIP: "8.8.8.8", Protocol: "dns", Transport: "udp"}
	if s.SessionEnd(info) {
		t.Error("UDP must not be aggregated")
	}
	if len(sink.snapshot()) != 0 {
		t.Error("UDP must never reach the sink")
	}
}

func TestSensorWithoutSink(t *testing.T) {
	buf := &lockedBuffer{}
	s := newSensor(SensorConfig{SummaryWindow: time.Minute}, nil, slog.New(slog.NewJSONHandler(buf, nil)))
	info := tcpInfo("8.8.8.8", "ssh")
	info.AuthAttempts = 1
	if got := s.Alert(context.Background(), info, nil); got != ClassAttack {
		t.Errorf("class = %s, want attack", got)
	}
	s.SessionEnd(info)
	s.Close() // must not panic without a sink
}

func TestSensorCloseClosesSinkAndFlushes(t *testing.T) {
	s, sink, _, buf := testSensor(t, time.Minute, 100)
	s.SessionEnd(tcpInfo("8.8.8.8", "vnc"))
	s.start()
	s.Close()
	s.Close() // idempotent
	if !sink.closed {
		t.Error("sink not closed")
	}
	if !strings.Contains(buf.String(), "probe summary") {
		t.Errorf("pending summary not flushed on Close: %q", buf.String())
	}
}

func summaryLines(t *testing.T, buf *lockedBuffer) []map[string]any {
	t.Helper()
	var out []map[string]any
	for _, line := range strings.Split(strings.TrimSpace(buf.String()), "\n") {
		if line == "" {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			t.Fatalf("bad log line %q: %v", line, err)
		}
		if m["action"] == "probe_summary" {
			out = append(out, m)
		}
	}
	return out
}

func TestProbeBurstProducesOneSummary(t *testing.T) {
	s, _, clk, buf := testSensor(t, time.Minute, 100)
	for range 500 {
		s.SessionEnd(tcpInfo("8.8.8.8", "vnc"))
		clk.Advance(10 * time.Millisecond)
	}
	if got := summaryLines(t, buf); len(got) != 0 {
		t.Fatalf("summary emitted before the window ended: %v", got)
	}
	clk.Advance(time.Minute)
	s.probes.flushDue()
	lines := summaryLines(t, buf)
	if len(lines) != 1 {
		t.Fatalf("got %d summary lines, want 1", len(lines))
	}
	l := lines[0]
	if l["sessions"] != float64(500) || l["source_ip"] != "8.8.8.8" || l["class"] != "probe" {
		t.Errorf("summary = %v", l)
	}
	protos, _ := l["protocols"].(map[string]any)
	if protos["vnc"] != float64(500) {
		t.Errorf("protocols = %v, want vnc=500", l["protocols"])
	}
}

func TestProbeSummaryPerIPAndProtocols(t *testing.T) {
	s, _, clk, buf := testSensor(t, time.Minute, 100)
	s.SessionEnd(tcpInfo("8.8.8.8", "vnc"))
	s.SessionEnd(tcpInfo("8.8.8.8", "ssh"))
	s.SessionEnd(tcpInfo("1.1.1.1", "vnc"))
	clk.Advance(2 * time.Minute)
	s.probes.flushDue()
	lines := summaryLines(t, buf)
	if len(lines) != 2 {
		t.Fatalf("got %d summary lines, want 2 (one per IP)", len(lines))
	}
}

func TestProbeLogNewWindowAfterExpiryWithoutFlush(t *testing.T) {
	s, _, clk, buf := testSensor(t, time.Minute, 100)
	s.SessionEnd(tcpInfo("8.8.8.8", "vnc"))
	clk.Advance(2 * time.Minute)
	s.SessionEnd(tcpInfo("8.8.8.8", "vnc")) // flushes the old window first
	if got := summaryLines(t, buf); len(got) != 1 || got[0]["sessions"] != float64(1) {
		t.Fatalf("summaries = %v, want one with 1 session", got)
	}
	s.probes.flushAll()
	if got := summaryLines(t, buf); len(got) != 2 {
		t.Fatalf("summaries = %d, want 2", len(got))
	}
}

func TestProbeLogCapFlushesOldestInsteadOfDropping(t *testing.T) {
	s, _, clk, buf := testSensor(t, time.Hour, 3)
	total := 0
	for i := 0; i < 10; i++ {
		s.SessionEnd(tcpInfo(testIP(i), "vnc"))
		clk.Advance(time.Second)
		s.probes.mu.Lock()
		if len(s.probes.entries) > 3 || s.probes.order.Len() != len(s.probes.entries) {
			s.probes.mu.Unlock()
			t.Fatalf("probe log size breaks cap 3")
		}
		s.probes.mu.Unlock()
	}
	s.probes.flushAll()
	for _, l := range summaryLines(t, buf) {
		total += int(l["sessions"].(float64))
	}
	if total != 10 {
		t.Errorf("summaries cover %d sessions, want 10 (no loss on eviction)", total)
	}
}

func TestSensorBackgroundFlusher(t *testing.T) {
	buf := &lockedBuffer{}
	s := NewSensor(SensorConfig{SummaryWindow: 20 * time.Millisecond}, nil, slog.New(slog.NewJSONHandler(buf, nil)))
	s.SessionEnd(tcpInfo("8.8.8.8", "vnc"))
	s.Close() // Close flushes pending summaries, so the test needs no sleeping
	if len(summaryLines(t, buf)) != 1 {
		t.Errorf("expected one summary after Close, got log %q", buf.String())
	}
}

// TestSensorToFakeLAPI runs the full path: sensor classification, class filter,
// cooldown and the wire format received by a fake LAPI.
func TestSensorToFakeLAPI(t *testing.T) {
	var mu sync.Mutex
	var received []csAlert
	srv := testServer(t, "ran", "secret", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var batch []csAlert
		_ = json.Unmarshal(body, &batch)
		mu.Lock()
		received = append(received, batch...)
		mu.Unlock()
		w.WriteHeader(200)
	})
	defer srv.Close()

	m := testMetrics(t)
	cfg := testConfig(srv.URL)
	cfg.Cooldown = 4 * time.Hour
	cs, err := NewCrowdSec(context.Background(), cfg, slog.New(slog.NewJSONHandler(&lockedBuffer{}, nil)), m)
	if err != nil {
		t.Fatal(err)
	}
	s := NewSensor(SensorConfig{SummaryWindow: time.Minute}, cs, slog.New(slog.NewJSONHandler(&lockedBuffer{}, nil)))
	ctx := context.Background()
	ip := "8.8.8.8"

	// 100 probe sessions: filtered (default BanOn), aggregated, never sent.
	for range 100 {
		s.SessionEnd(tcpInfo(ip, "vnc"))
	}
	// An attack session that alerts mid-session, repeatedly, then ends.
	atk := tcpInfo(ip, "ssh")
	atk.AuthAttempts = 1
	for range 5 {
		atk.AlertedClass = s.Alert(ctx, atk, map[string]string{"username": "root"})
	}
	s.SessionEnd(atk)
	// Two more protocols make the source a scanner.
	for _, proto := range []string{"redis", "mysql"} {
		info := tcpInfo(ip, proto)
		info.Commands = 1
		info.AlertedClass = s.Alert(ctx, info, nil)
		s.SessionEnd(info)
	}
	s.Close()

	mu.Lock()
	defer mu.Unlock()
	if len(received) != 2 {
		t.Fatalf("LAPI got %d alerts, want 2 (one attack, one scan): %+v", len(received), received)
	}
	classes := map[string]string{}
	for _, a := range received {
		if len(a.Decisions) != 0 || !a.Remediation || a.Source.Value != ip || a.Source.IP != ip {
			t.Errorf("bad alert shape: %+v", a)
		}
		for _, kv := range a.Events[0].Meta {
			if kv.Key == "class" {
				classes[a.Scenario] = kv.Value
			}
		}
	}
	if classes["custom/ran-ssh-trap"] != "attack" {
		t.Errorf("ssh alert class = %q, want attack (classes %v)", classes["custom/ran-ssh-trap"], classes)
	}
	var scanScenario string
	for sc, c := range classes {
		if c == "scan" {
			scanScenario = sc
		}
	}
	if scanScenario != "custom/ran-redis-trap" {
		t.Errorf("scan alert scenario = %q, want custom/ran-redis-trap (vnc, ssh and redis crossed the threshold)", scanScenario)
	}
	if got := pipelineCount(t, m, "vnc", "filtered"); got != 100 {
		t.Errorf("vnc filtered = %v, want 100", got)
	}
	if got := pipelineCount(t, m, "ssh", "cooldown"); got != 4 {
		t.Errorf("ssh cooldown = %v, want 4 (5 attack events, 1 sent)", got)
	}
}

// testIP returns the i-th test source address from the well-known public range
// 8.8.8.0/24. These are fixed, well-known addresses used only as inputs; they are
// not attacker data and no real source is ever derived from them.
func testIP(i int) string { return "8.8.8." + strconv.Itoa(i%256) }
