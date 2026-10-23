package alert

import (
	"context"
	"log/slog"
	"net/http"
	"sync/atomic"
	"testing"
	"time"
)

func TestBoundMetaDropsSecretKeysCaseInsensitive(t *testing.T) {
	in := map[string]string{
		"password": "a", "Password": "b", "PASSWORD": "c", "pass": "d", "Passwd": "e",
		"secret": "f", "Token": "g", "AUTHORIZATION": "h", " token ": "i",
		"username": "alice", "command": "GET /",
	}
	out := boundMeta(in)
	for _, k := range []string{"password", "Password", "PASSWORD", "pass", "Passwd", "secret", "Token", "AUTHORIZATION", " token "} {
		if _, ok := out[k]; ok {
			t.Errorf("secret key %q survived boundMeta", k)
		}
	}
	if out["username"] != "alice" || out["command"] != "GET /" {
		t.Errorf("plain keys lost: %v", out)
	}
}

func TestCrowdSecCloseMakesFinalFlushAfterInterruptedHold(t *testing.T) {
	setPacing(t, time.Hour, time.Hour)
	var posts atomic.Int32
	srv := testServer(t, "ran", "secret", func(w http.ResponseWriter, r *http.Request) {
		// The first push fails and starts the hold; the LAPI is back afterwards.
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
	a.Submit(context.Background(), ev(wideIP(0), "ssh"))
	waitFor(t, "first failure", func() bool { return pipelineCount(t, m, "ssh", "failed") >= 1 })
	// Held now: these two are pending when Close arrives.
	a.Submit(context.Background(), ev(wideIP(1), "ssh"))
	a.Submit(context.Background(), ev(wideIP(2), "ssh"))

	start := time.Now()
	a.Close()
	if d := time.Since(start); d > 3*time.Second {
		t.Errorf("Close took %v", d)
	}
	// The final attempt succeeds, so the LAPI is back and the rest drains too
	// (a still failing LAPI is covered by TestCrowdSecCloseInterruptsHoldAndDropsWhenFull).
	if got := posts.Load(); got != 3 {
		t.Errorf("POSTs = %d, want 3 (failed push + two drained)", got)
	}
	if got := pipelineCount(t, m, "ssh", "sent"); got != 2 {
		t.Errorf("sent = %v, want 2", got)
	}
	if got := pipelineCount(t, m, "ssh", "failed"); got != 1 {
		t.Errorf("failed = %v, want 1 (the first push only)", got)
	}
}

func TestCrowdSecCloseContextHonorsDeadline(t *testing.T) {
	entered := make(chan struct{})
	release := make(chan struct{})
	var once atomic.Bool
	srv := testServer(t, "ran", "secret", func(w http.ResponseWriter, r *http.Request) {
		if once.CompareAndSwap(false, true) {
			close(entered)
		}
		<-release
		w.WriteHeader(200)
	})
	defer srv.Close()
	defer close(release)

	a, err := NewCrowdSec(context.Background(), testConfig(srv.URL), slog.New(slog.NewJSONHandler(&lockedBuffer{}, nil)), testMetrics(t))
	if err != nil {
		t.Fatal(err)
	}
	a.Submit(context.Background(), ev(wideIP(0), "ssh"))
	<-entered

	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	start := time.Now()
	a.CloseContext(ctx)
	if d := time.Since(start); d > 2*time.Second {
		t.Errorf("CloseContext took %v, want about the 300ms budget", d)
	}
}

func TestCrowdSecDrainIsCappedAtFlushTimeout(t *testing.T) {
	// A slow LAPI must not stretch the drain past flushTimeout: the flush
	// context is clamped to the drain deadline set by Close.
	a := &CrowdSecAlerter{}
	if got := a.drainBy.Load(); got != 0 {
		t.Fatalf("drainBy = %d before Close", got)
	}
	a.logger = slog.Default()
	a.stopCh = make(chan struct{})
	a.ch = make(chan alertMsg)
	before := time.Now()
	a.CloseContext(context.Background())
	by := time.Unix(0, a.drainBy.Load())
	if by.Before(before.Add(flushTimeout-time.Second)) || by.After(time.Now().Add(flushTimeout+time.Second)) {
		t.Errorf("drain deadline %v is not about flushTimeout (%v) from Close", by, flushTimeout)
	}
}
