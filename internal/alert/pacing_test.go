package alert

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// setPacing swaps the failure hold and warning interval and restores them after
// the test. Set it before NewCrowdSec and let the alerter close before the restore.
func setPacing(t *testing.T, hold, logEvery time.Duration) {
	t.Helper()
	oldHold, oldLog := failHoldMin, failLogInterval
	failHoldMin, failLogInterval = hold, logEvery
	t.Cleanup(func() { failHoldMin, failLogInterval = oldHold, oldLog })
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(2 * time.Millisecond)
	}
}

func TestCrowdSecFailedPushIsPaced(t *testing.T) {
	const hold = 40 * time.Millisecond
	setPacing(t, hold, time.Hour)
	var posts atomic.Int32
	srv := testServer(t, "ran", "secret", func(w http.ResponseWriter, r *http.Request) {
		posts.Add(1)
		w.WriteHeader(503)
	})
	defer srv.Close()

	logs := &lockedBuffer{}
	m := testMetrics(t)
	cfg := testConfig(srv.URL)
	cfg.Cooldown = 4 * time.Hour
	a, err := NewCrowdSec(context.Background(), cfg, slog.New(slog.NewJSONHandler(logs, nil)), m)
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	for i := 0; i < 100; i++ {
		a.Submit(context.Background(), ev(wideIP(i), "ssh"))
	}
	waitFor(t, "first failed push", func() bool { return posts.Load() >= 1 })
	time.Sleep(3 * hold)
	got := int(posts.Load())
	elapsed := time.Since(start)
	// Every retry waits at least one hold, so the count has a hard upper bound.
	if limit := int(elapsed/hold) + 1; got > limit {
		t.Errorf("POSTs = %d in %v, want at most %d (paced)", got, elapsed, limit)
	}
	if got >= 100 {
		t.Errorf("POSTs = %d, want far fewer than the 100 sessions", got)
	}
	a.Close()
	if n := strings.Count(logs.String(), "push alert batch rejected"); n != 1 {
		t.Errorf("rejected warnings = %d, want 1 (rate limited)", n)
	}
	// Released slots stay released: the sources can be reported again after recovery.
	if rel := pipelineCount(t, m, "ssh", "released"); rel < 1 {
		t.Errorf("released = %v, want >= 1", rel)
	}
}

func TestCrowdSecWarningSuppressionCounter(t *testing.T) {
	setPacing(t, time.Millisecond, 30*time.Millisecond)
	srv := testServer(t, "ran", "secret", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(503) })
	defer srv.Close()
	logs := &lockedBuffer{}
	a, err := NewCrowdSec(context.Background(), testConfig(srv.URL), slog.New(slog.NewJSONHandler(logs, nil)), testMetrics(t))
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 10; i++ {
		a.Submit(context.Background(), ev(wideIP(i), "ssh"))
		time.Sleep(10 * time.Millisecond)
	}
	a.Close()
	if !strings.Contains(logs.String(), `"suppressed"`) {
		t.Errorf("no suppressed counter in logs: %s", logs.String())
	}
}

func TestCrowdSecReloginIsPaced(t *testing.T) {
	const hold = 40 * time.Millisecond
	setPacing(t, hold, time.Hour)
	var logins, posts atomic.Int32
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/watchers/login", func(w http.ResponseWriter, r *http.Request) {
		logins.Add(1)
		expire := time.Now().Add(time.Hour).Format(time.RFC3339)
		_ = json.NewEncoder(w).Encode(loginResponse{Token: "t", Expire: expire})
	})
	mux.HandleFunc("/v1/alerts", func(w http.ResponseWriter, r *http.Request) {
		posts.Add(1)
		w.WriteHeader(401)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	a, err := NewCrowdSec(context.Background(), testConfig(srv.URL), slog.New(slog.NewJSONHandler(&lockedBuffer{}, nil)), testMetrics(t))
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	for i := 0; i < 100; i++ {
		a.Submit(context.Background(), ev(wideIP(i), "ssh"))
	}
	waitFor(t, "first push", func() bool { return posts.Load() >= 2 })
	time.Sleep(3 * hold)
	relogins := int(logins.Load()) - 1
	if limit := int(time.Since(start)/hold) + 1; relogins > limit {
		t.Errorf("re-logins = %d, want at most %d", relogins, limit)
	}
	a.Close()
}

func TestCrowdSecCloseInterruptsHoldAndDropsWhenFull(t *testing.T) {
	setPacing(t, time.Hour, time.Hour)
	var posts atomic.Int32
	srv := testServer(t, "ran", "secret", func(w http.ResponseWriter, r *http.Request) {
		posts.Add(1)
		w.WriteHeader(503)
	})
	defer srv.Close()
	before := runtime.NumGoroutine()

	m := testMetrics(t)
	cfg := testConfig(srv.URL)
	cfg.Cooldown = 4 * time.Hour
	a, err := NewCrowdSec(context.Background(), cfg, slog.New(slog.NewJSONHandler(&lockedBuffer{}, nil)), m)
	if err != nil {
		t.Fatal(err)
	}
	a.Submit(context.Background(), ev(wideIP(0), "ssh"))
	waitFor(t, "first failure", func() bool { return pipelineCount(t, m, "ssh", "failed") >= 1 })
	// The worker is now held; the queue (256) fills and the rest is dropped.
	for i := 1; i <= 300; i++ {
		a.Submit(context.Background(), ev(wideIP(i), "ssh"))
	}
	if got := droppedCount(t, m, "ssh"); got != 300-256 {
		t.Errorf("dropped = %v, want %d", got, 300-256)
	}
	start := time.Now()
	a.Close()
	if d := time.Since(start); d > 2*time.Second {
		t.Errorf("Close took %v, the hold was not interrupted", d)
	}
	if got := posts.Load(); got != 2 {
		t.Errorf("POSTs = %d, want 2 (failed push + one final attempt; the rest fails without posting)", got)
	}
	if got := pipelineCount(t, m, "ssh", "failed"); got != 257 {
		t.Errorf("failed = %v, want 257", got)
	}

	a.client.CloseIdleConnections()
	srv.CloseClientConnections()
	waitFor(t, "goroutines to exit", func() bool { return runtime.NumGoroutine() <= before })
}

func TestCrowdSecBatchSizeCountsEscapedBytes(t *testing.T) {
	var mu sync.Mutex
	var sizes []int
	srv := testServer(t, "ran", "secret", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		mu.Lock()
		sizes = append(sizes, len(body))
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
	// '<' escapes to < (6x) and '"' to \" (2x) in JSON.
	meta := map[string]string{}
	for i := 0; i < maxMetaKeys; i++ {
		meta["k"+string(rune('a'+i%26))+string(rune('a'+i/26))] = strings.Repeat("<", maxMetaValueBytes/2) + strings.Repeat(`"`, maxMetaValueBytes/2)
	}
	for i := 0; i < 100; i++ {
		e := ev(testIP(i), "http")
		e.Meta = meta
		a.Submit(context.Background(), e)
	}
	a.Close()

	mu.Lock()
	defer mu.Unlock()
	if len(sizes) < 2 {
		t.Fatalf("got %d POSTs, want the batch split by size", len(sizes))
	}
	for _, s := range sizes {
		// Slack covers the brackets and the commas between alerts.
		if s > maxBatchBytes+1024 {
			t.Errorf("POST body %d bytes exceeds the %d cap", s, maxBatchBytes)
		}
	}
}

func TestSanitizeMetaFormatAndLineSeparators(t *testing.T) {
	got := sanitizeMeta("a\xe2\x80\xaeb\xe2\x80\x8bc\xe2\x80\xa8d\xe2\x80\xa9e\xef\xbb\xbf", 256)
	if got != "a b c d e " {
		t.Errorf("got %q", got)
	}
}

func TestBoundMetaSkipsEmptyKeys(t *testing.T) {
	out := boundMeta(map[string]string{"": "x", "ok": "y", "password": "z"})
	if _, ok := out[""]; ok {
		t.Error("empty key kept")
	}
	if out["ok"] != "y" || len(out) != 1 {
		t.Errorf("got %v", out)
	}
}

// wideIP returns a distinct public address for i < 65536.
func wideIP(i int) string {
	return "8.9." + strconv.Itoa(i/256%256) + "." + strconv.Itoa(i%256)
}
