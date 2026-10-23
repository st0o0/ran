package alert

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
	"unicode/utf8"
)

// --- Meta bounds ---

func TestEventMetaBoundsOversizedValue(t *testing.T) {
	meta := eventMeta(Event{
		Class: ClassAttack,
		Info:  SessionInfo{Protocol: "http", DestPort: 80},
		Meta:  map[string]string{"path": strings.Repeat("A", 1<<20)},
	})
	if got := len(meta["path"]); got != maxMetaValueBytes {
		t.Errorf("path length = %d, want %d", got, maxMetaValueBytes)
	}
}

func TestEventMetaCapsKeysAndKeepsSensorKeys(t *testing.T) {
	trap := map[string]string{"class": "probe"}
	for i := 0; i < 200; i++ {
		trap["k"+strconv.Itoa(1000+i)] = "v"
	}
	meta := eventMeta(Event{Class: ClassAttack, Info: SessionInfo{Protocol: "ssh", DestPort: 22}, Meta: trap})
	if len(meta) != maxMetaKeys {
		t.Fatalf("got %d keys, want %d", len(meta), maxMetaKeys)
	}
	for k := range sensorMetaKeys {
		if _, ok := meta[k]; !ok {
			t.Errorf("sensor key %q dropped", k)
		}
	}
	if meta["class"] != "attack" {
		t.Errorf("class = %q, want attack", meta["class"])
	}
	// Surplus trap keys are dropped in sorted order: the smallest survive.
	if _, ok := meta["k1000"]; !ok {
		t.Error("smallest trap key must survive")
	}
	if _, ok := meta["k1199"]; ok {
		t.Error("largest trap key must be dropped")
	}
	again := eventMeta(Event{Class: ClassAttack, Info: SessionInfo{Protocol: "ssh", DestPort: 22}, Meta: trap})
	if len(again) != len(meta) {
		t.Error("bounding is not deterministic")
	}
	for k := range meta {
		if _, ok := again[k]; !ok {
			t.Errorf("key %q not stable across runs", k)
		}
	}
}

func TestSanitizeMetaControlChars(t *testing.T) {
	got := sanitizeMeta("a\nb\x00c\td\x7fe\r\n", 256)
	if got != "a b c d e  " {
		t.Errorf("got %q", got)
	}
}

func TestSanitizeMetaRuneBoundary(t *testing.T) {
	// Each euro sign is 3 bytes; 256 is not a multiple of 3, so the cut must
	// land on a rune boundary (255 bytes).
	got := sanitizeMeta(strings.Repeat("€", 200), 256)
	if !utf8.ValidString(got) {
		t.Fatalf("result is not valid UTF-8: %q", got)
	}
	if len(got) != 255 {
		t.Errorf("len = %d, want 255", len(got))
	}
	if bad := sanitizeMeta("a\xffb", 256); bad != "a?b" {
		t.Errorf("invalid byte: got %q, want a?b", bad)
	}
}

func TestBuildEventMetaIsBoundedAndIdempotent(t *testing.T) {
	in := map[string]string{"path": strings.Repeat("x", 5000), "a\nb": "v"}
	out := buildEventMeta(in)
	for _, m := range out {
		if len(m.Value) > maxMetaValueBytes || strings.ContainsAny(m.Key, "\n") {
			t.Errorf("unbounded entry %q", m.Key)
		}
	}
}

// --- Batch size cap ---

func TestCrowdSecBatchFlushesEarlyByBytes(t *testing.T) {
	var mu sync.Mutex
	var sizes []int
	var total int
	srv := testServer(t, "ran", "secret", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var batch []csAlert
		_ = json.Unmarshal(body, &batch)
		mu.Lock()
		sizes = append(sizes, len(body))
		total += len(batch)
		mu.Unlock()
		w.WriteHeader(200)
	})
	defer srv.Close()

	cfg := testConfig(srv.URL)
	cfg.BatchInterval = time.Hour
	cfg.BatchSize = 1000
	a, err := NewCrowdSec(context.Background(), cfg, slog.New(slog.NewJSONHandler(&lockedBuffer{}, nil)), testMetrics(t))
	if err != nil {
		t.Fatal(err)
	}
	big := map[string]string{}
	for i := 0; i < maxMetaKeys; i++ {
		big["key"+strconv.Itoa(100+i)] = strings.Repeat("v", 1<<16)
	}
	const alerts = 200
	for i := 0; i < alerts; i++ {
		e := ev(testIP(i%250+1), "http")
		e.Meta = big
		a.Submit(context.Background(), e)
	}
	a.Close()

	mu.Lock()
	defer mu.Unlock()
	if total != alerts {
		t.Fatalf("LAPI got %d alerts, want %d", total, alerts)
	}
	if len(sizes) < 2 {
		t.Errorf("got %d POSTs, want the batch split by size", len(sizes))
	}
	for _, s := range sizes {
		if s > maxBatchBytes {
			t.Errorf("POST body %d bytes exceeds the %d cap", s, maxBatchBytes)
		}
	}
}

// --- Failed POST releases the cooldown ---

func TestCrowdSecFailedPostReleasesCooldown(t *testing.T) {
	setPacing(t, 20*time.Millisecond, time.Hour)
	var posts atomic.Int32
	srv := testServer(t, "ran", "secret", func(w http.ResponseWriter, r *http.Request) {
		if posts.Add(1) == 1 {
			w.WriteHeader(503)
			return
		}
		w.WriteHeader(200)
	})
	defer srv.Close()

	m := testMetrics(t)
	cfg := testConfig(srv.URL)
	cfg.Cooldown = 4 * time.Hour
	a, err := NewCrowdSec(context.Background(), cfg, slog.New(slog.NewJSONHandler(&lockedBuffer{}, nil)), m)
	if err != nil {
		t.Fatal(err)
	}
	a.Submit(context.Background(), ev("8.8.8.8", "ssh"))
	deadline := time.Now().Add(5 * time.Second)
	for pipelineCount(t, m, "ssh", "released") < 1 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if got := pipelineCount(t, m, "ssh", "failed"); got != 1 {
		t.Fatalf("failed = %v, want 1", got)
	}
	if got := pipelineCount(t, m, "ssh", "released"); got != 1 {
		t.Fatalf("released = %v, want 1", got)
	}
	// The retry is not suppressed by the cooldown.
	a.Submit(context.Background(), ev("8.8.8.8", "ssh"))
	deadline = time.Now().Add(5 * time.Second)
	for pipelineCount(t, m, "ssh", "sent") < 1 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	a.Close()
	if got := pipelineCount(t, m, "ssh", "cooldown"); got != 0 {
		t.Errorf("cooldown = %v, want 0 after the failed push", got)
	}
	if got := posts.Load(); got != 2 {
		t.Errorf("POST count = %d, want 2", got)
	}
	if got := pipelineCount(t, m, "ssh", "sent"); got != 1 {
		t.Errorf("sent = %v, want 1", got)
	}
}

func TestCrowdSecSuccessKeepsCooldown(t *testing.T) {
	srv, _ := countingServer(t)
	m := testMetrics(t)
	cfg := testConfig(srv.URL)
	cfg.Cooldown = 4 * time.Hour
	a, err := NewCrowdSec(context.Background(), cfg, slog.New(slog.NewJSONHandler(&lockedBuffer{}, nil)), m)
	if err != nil {
		t.Fatal(err)
	}
	a.Submit(context.Background(), ev("8.8.8.8", "ssh"))
	a.Close()
	if got := pipelineCount(t, m, "ssh", "released"); got != 0 {
		t.Errorf("released = %v, want 0 after a successful push", got)
	}
}

// --- Sensor ---

func TestSensorCleanupRunsWithoutProbeWindow(t *testing.T) {
	s, _, clk, _ := testSensor(t, 0, 100)
	s.interval = 5 * time.Millisecond
	s.scan.Touch(testIP(1), "ssh")
	clk.Advance(scanWindow + time.Minute)
	s.start()
	deadline := time.Now().Add(5 * time.Second)
	for s.scan.len() != 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	s.Close()
	if n := s.scan.len(); n != 0 {
		t.Errorf("scan tracker has %d entries, want 0 (cleanup must run with window 0)", n)
	}
}

func TestSensorStragglerAfterCloseIsNotAggregated(t *testing.T) {
	s, _, _, buf := testSensor(t, time.Minute, 100)
	s.Close()
	if s.SessionEnd(tcpInfo("8.8.8.8", "vnc")) {
		t.Error("SessionEnd after Close must return false so the caller logs the session")
	}
	s.probes.mu.Lock()
	n := len(s.probes.entries)
	s.probes.mu.Unlock()
	if n != 0 {
		t.Errorf("orphan probe entries after Close: %d", n)
	}
	if len(summaryLines(t, buf)) != 0 {
		t.Error("no summary expected for a straggler")
	}
}

func TestProbeLogNormalizesMappedIPv4(t *testing.T) {
	s, _, clk, buf := testSensor(t, time.Minute, 100)
	s.SessionEnd(tcpInfo("::ffff:8.8.8.8", "vnc"))
	s.SessionEnd(tcpInfo("8.8.8.8", "vnc"))
	clk.Advance(2 * time.Minute)
	s.probes.flushDue()
	lines := summaryLines(t, buf)
	if len(lines) != 1 || lines[0]["sessions"] != float64(2) || lines[0]["source_ip"] != "8.8.8.8" {
		t.Fatalf("summaries = %v, want one line with 2 sessions for 8.8.8.8", lines)
	}
}

func TestSensorAlertIgnoresUDP(t *testing.T) {
	s, sink, _, _ := testSensor(t, 0, 100)
	for _, proto := range []string{"dns", "snmp", "ntp", "sip"} {
		info := SessionInfo{SourceIP: "8.8.8.8", Protocol: proto, Transport: "udp", AuthAttempts: 3, Commands: 1}
		if got := s.Alert(context.Background(), info, map[string]string{"a": "b"}); got != "" {
			t.Errorf("udp %s: class = %q, want empty", proto, got)
		}
	}
	if n := len(sink.snapshot()); n != 0 {
		t.Errorf("sink got %d events for UDP, want 0", n)
	}
	if s.scan.len() != 0 {
		t.Errorf("scan tracker touched by UDP: %d entries", s.scan.len())
	}
}

// --- Scan tracker boundaries ---

func TestScanTrackerExactWindowBoundary(t *testing.T) {
	clk := newFakeClock()
	tr := newScanTracker(scanWindow, scanProtocols, 100)
	tr.nowFunc = clk.Now
	ip := testIP(1)
	tr.Touch(ip, "ssh")
	clk.Advance(5 * time.Minute)
	tr.Touch(ip, "redis")
	// One nanosecond before the window ends ssh still counts.
	clk.Advance(scanWindow - 5*time.Minute - time.Nanosecond)
	if !tr.Touch(ip, "vnc") {
		t.Error("ssh is 10m-1ns old and must still count")
	}

	tr = newScanTracker(scanWindow, scanProtocols, 100)
	clk = newFakeClock()
	tr.nowFunc = clk.Now
	tr.Touch(ip, "ssh")
	clk.Advance(5 * time.Minute)
	tr.Touch(ip, "redis")
	// At exactly the window length the touch has expired (>= semantics).
	clk.Advance(scanWindow - 5*time.Minute)
	if tr.Touch(ip, "vnc") {
		t.Error("ssh is exactly 10m old and must have expired")
	}
}

func TestScanMappedAndPlainIPv4ShareState(t *testing.T) {
	s, _, _, _ := testSensor(t, 0, 100)
	forms := []struct{ ip, proto string }{
		{"::ffff:8.8.8.8", "ssh"},
		{"8.8.8.8", "redis"},
		{"::ffff:8.8.8.8", "vnc"},
	}
	var last Class
	for _, f := range forms {
		info := tcpInfo(f.ip, f.proto)
		info.AuthAttempts = 1
		last = s.Alert(context.Background(), info, nil)
	}
	if last != ClassScan {
		t.Errorf("class = %s, want scan (mapped and plain form are one source)", last)
	}
	if s.scan.len() != 1 {
		t.Errorf("scan tracker has %d entries, want 1", s.scan.len())
	}
}
