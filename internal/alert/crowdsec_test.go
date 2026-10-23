package alert

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"log/slog"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/st0o0/ran/internal/metrics"
)

func testMetrics(t *testing.T) *metrics.Metrics {
	t.Helper()
	return metrics.New(prometheus.NewRegistry(), "test")
}

func testConfig(url string) CrowdSecConfig {
	return CrowdSecConfig{
		URL:           url,
		MachineID:     "ran",
		Password:      "secret",
		Cooldown:      0,
		BatchInterval: 0,
		BatchSize:     1,
	}
}

// ev builds an attack-class event for ip and protocol.
func ev(ip, protocol string) Event {
	return evClass(ip, protocol, ClassAttack)
}

func evClass(ip, protocol string, class Class) Event {
	return Event{
		Class: class,
		Info: SessionInfo{
			SourceIP:     ip,
			Protocol:     protocol,
			Transport:    "tcp",
			DestPort:     2222,
			AuthAttempts: 1,
		},
	}
}

func loginHandler(t *testing.T, machineID, password string) http.HandlerFunc {
	t.Helper()
	return func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var req loginRequest
		if err := json.Unmarshal(body, &req); err != nil {
			w.WriteHeader(400)
			return
		}
		if req.MachineID != machineID || req.Password != password {
			w.WriteHeader(403)
			return
		}
		expire := time.Now().Add(1 * time.Hour).Format(time.RFC3339)
		resp := loginResponse{Token: "test-jwt-token", Expire: expire}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}
}

func testServer(t *testing.T, machineID, password string, alertHandler http.HandlerFunc) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/watchers/login", loginHandler(t, machineID, password))
	mux.HandleFunc("/v1/alerts", alertHandler)
	return httptest.NewServer(mux)
}

func TestCrowdSecLogin(t *testing.T) {
	srv := testServer(t, "ran", "secret", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	})
	defer srv.Close()

	m := testMetrics(t)
	a, err := NewCrowdSec(context.Background(), testConfig(srv.URL), slog.Default(), m)
	if err != nil {
		t.Fatalf("NewCrowdSec failed: %v", err)
	}
	a.Close()
}

func TestCrowdSecLoginFailure(t *testing.T) {
	srv := testServer(t, "ran", "secret", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	})
	defer srv.Close()

	m := testMetrics(t)
	cfg := testConfig(srv.URL)
	cfg.Password = "wrong-password"
	_, err := NewCrowdSec(context.Background(), cfg, slog.Default(), m)
	if err == nil {
		t.Fatal("expected error for invalid credentials")
	}
}

// rawAlert mirrors the JSON sent to CrowdSec without going through csAlert, so
// the test checks the wire format (field presence and names).
type rawAlert map[string]any

func TestCrowdSecAlertFormat(t *testing.T) {
	var mu sync.Mutex
	var rawBody []byte
	var received []csAlert
	srv := testServer(t, "ran", "secret", func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if auth != "Bearer test-jwt-token" {
			t.Errorf("Authorization = %q, want Bearer test-jwt-token", auth)
		}
		if r.Header.Get("X-Api-Key") != "" {
			t.Error("X-Api-Key header should not be set")
		}
		body, _ := io.ReadAll(r.Body)
		mu.Lock()
		rawBody = body
		_ = json.Unmarshal(body, &received)
		mu.Unlock()
		w.WriteHeader(200)
	})
	defer srv.Close()

	m := testMetrics(t)
	a, err := NewCrowdSec(context.Background(), testConfig(srv.URL), slog.Default(), m)
	if err != nil {
		t.Fatalf("NewCrowdSec failed: %v", err)
	}
	e := ev("8.8.8.8", "ssh")
	e.Info.Commands = 2
	e.Info.PayloadBytes = 7
	e.Meta = map[string]string{"username": "root", "password": "admin", "class": "spoofed"}
	a.Submit(context.Background(), e)
	a.Close()

	mu.Lock()
	defer mu.Unlock()
	if len(received) != 1 {
		t.Fatalf("got %d alerts, want 1", len(received))
	}
	alert := received[0]
	if alert.Scenario != "custom/ran-ssh-trap" {
		t.Errorf("scenario = %q, want custom/ran-ssh-trap", alert.Scenario)
	}
	if alert.Source.Value != "8.8.8.8" || alert.Source.IP != "8.8.8.8" {
		t.Errorf("source value/ip = %q/%q, want 8.8.8.8 for both", alert.Source.Value, alert.Source.IP)
	}
	if alert.Source.Scope != "Ip" {
		t.Errorf("source.scope = %q, want Ip", alert.Source.Scope)
	}
	if len(alert.Decisions) != 0 {
		t.Errorf("got %d decisions, want none (profiles decide)", len(alert.Decisions))
	}
	if !alert.Remediation {
		t.Error("remediation = false, want true")
	}
	if alert.Simulated {
		t.Error("simulated = true, want false")
	}
	if alert.Capacity != 0 || alert.Leakspeed != "0" {
		t.Errorf("capacity/leakspeed = %d/%q, want 0/\"0\"", alert.Capacity, alert.Leakspeed)
	}
	if len(alert.Events) != 1 {
		t.Fatalf("got %d events, want 1", len(alert.Events))
	}
	meta := map[string]string{}
	for _, kv := range alert.Events[0].Meta {
		meta[kv.Key] = kv.Value
	}
	want := map[string]string{
		"username":      "root",
		"class":         "attack",
		"protocol":      "ssh",
		"dest_port":     "2222",
		"auth_attempts": "1",
		"commands":      "2",
		"payload_bytes": "7",
	}
	for k, v := range want {
		if meta[k] != v {
			t.Errorf("meta[%q] = %q, want %q", k, meta[k], v)
		}
	}
	if _, ok := meta["password"]; ok {
		t.Error("password must never be sent to CrowdSec")
	}
	if len(meta) != len(want) {
		t.Errorf("got %d meta keys, want %d: %v", len(meta), len(want), meta)
	}

	// Wire format: decisions must be an empty array, not null or absent.
	var raw []rawAlert
	if err := json.Unmarshal(rawBody, &raw); err != nil {
		t.Fatal(err)
	}
	d, ok := raw[0]["decisions"].([]any)
	if !ok || len(d) != 0 {
		t.Errorf("decisions = %v, want empty array", raw[0]["decisions"])
	}
	if raw[0]["remediation"] != true {
		t.Errorf("remediation = %v, want true", raw[0]["remediation"])
	}
}

func TestCrowdSecAlertMetaCountersWithoutTrapMeta(t *testing.T) {
	var mu sync.Mutex
	var received []csAlert
	srv := testServer(t, "ran", "secret", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		mu.Lock()
		_ = json.Unmarshal(body, &received)
		mu.Unlock()
		w.WriteHeader(200)
	})
	defer srv.Close()

	m := testMetrics(t)
	a, err := NewCrowdSec(context.Background(), testConfig(srv.URL), slog.Default(), m)
	if err != nil {
		t.Fatalf("NewCrowdSec failed: %v", err)
	}
	a.Submit(context.Background(), ev("1.1.1.1", "memcached"))
	a.Close()

	mu.Lock()
	defer mu.Unlock()
	if len(received) != 1 || len(received[0].Events) != 1 {
		t.Fatalf("got %+v, want one alert with one event", received)
	}
	if received[0].Events[0].Meta == nil {
		t.Fatal("events[0].meta is nil, want array")
	}
}

func TestCrowdSecIPv6AlertSetsIPAndValue(t *testing.T) {
	var mu sync.Mutex
	var received []csAlert
	srv := testServer(t, "ran", "secret", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		mu.Lock()
		_ = json.Unmarshal(body, &received)
		mu.Unlock()
		w.WriteHeader(200)
	})
	defer srv.Close()

	a, err := NewCrowdSec(context.Background(), testConfig(srv.URL), slog.Default(), testMetrics(t))
	if err != nil {
		t.Fatal(err)
	}
	a.Submit(context.Background(), ev("2606:4700:4700::1111", "ssh"))
	a.Close()

	mu.Lock()
	defer mu.Unlock()
	if len(received) != 1 {
		t.Fatalf("got %d alerts, want 1", len(received))
	}
	if s := received[0].Source; s.IP != "2606:4700:4700::1111" || s.Value != s.IP {
		t.Errorf("source = %+v, want ip and value 2606:4700:4700::1111", s)
	}
}

func TestCrowdSec401Retry(t *testing.T) {
	var pushCount atomic.Int32
	var loginCount atomic.Int32

	mux := http.NewServeMux()
	mux.HandleFunc("/v1/watchers/login", func(w http.ResponseWriter, r *http.Request) {
		n := loginCount.Add(1)
		token := "initial-token"
		if n > 1 {
			token = "refreshed-token"
		}
		expire := time.Now().Add(1 * time.Hour).Format(time.RFC3339)
		resp := loginResponse{Token: token, Expire: expire}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	})
	mux.HandleFunc("/v1/alerts", func(w http.ResponseWriter, r *http.Request) {
		n := pushCount.Add(1)
		auth := r.Header.Get("Authorization")
		if n == 1 && auth == "Bearer initial-token" {
			w.WriteHeader(401)
			return
		}
		if auth != "Bearer refreshed-token" {
			t.Errorf("retry Authorization = %q, want Bearer refreshed-token", auth)
		}
		w.WriteHeader(200)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	m := testMetrics(t)
	a, err := NewCrowdSec(context.Background(), testConfig(srv.URL), slog.Default(), m)
	if err != nil {
		t.Fatalf("NewCrowdSec failed: %v", err)
	}
	a.Submit(context.Background(), ev("8.8.8.8", "ssh"))
	a.Close()

	if got := pushCount.Load(); got != 2 {
		t.Errorf("push count = %d, want 2 (original + retry)", got)
	}
	if got := loginCount.Load(); got < 2 {
		t.Errorf("login count = %d, want >= 2 (initial + re-login)", got)
	}
}

func TestCrowdSecTokenRefresh(t *testing.T) {
	loginCount := atomic.Int32{}

	mux := http.NewServeMux()
	mux.HandleFunc("/v1/watchers/login", func(w http.ResponseWriter, r *http.Request) {
		loginCount.Add(1)
		expire := time.Now().Add(2 * time.Second).Format(time.RFC3339)
		resp := loginResponse{Token: "short-lived-token", Expire: expire}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	})
	mux.HandleFunc("/v1/alerts", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	m := testMetrics(t)
	a, err := NewCrowdSec(context.Background(), testConfig(srv.URL), slog.Default(), m)
	if err != nil {
		t.Fatalf("NewCrowdSec failed: %v", err)
	}

	// Wait for the refresh loop to trigger (80% of 2s = 1.6s)
	time.Sleep(2500 * time.Millisecond)
	a.Close()

	if got := loginCount.Load(); got < 2 {
		t.Errorf("login count = %d, want >= 2 (initial + refresh)", got)
	}
}

func TestCrowdSecChannelOverflow(t *testing.T) {
	release := make(chan struct{})
	srv := testServer(t, "ran", "secret", func(w http.ResponseWriter, r *http.Request) {
		<-release
		w.WriteHeader(200)
	})
	defer srv.Close()

	m := testMetrics(t)
	a, err := NewCrowdSec(context.Background(), testConfig(srv.URL), slog.Default(), m)
	if err != nil {
		t.Fatalf("NewCrowdSec failed: %v", err)
	}

	// The worker holds one message while blocked on the server, so 257 fill the
	// channel; keep sending until a drop is observed.
	for range 300 {
		a.Submit(context.Background(), ev("1.1.1.1", "ssh"))
	}
	if got := pipelineCount(t, m, "ssh", "dropped"); got < 1 {
		t.Errorf("dropped = %v, want >= 1", got)
	}
	if got := droppedCount(t, m, "ssh"); got < 1 {
		t.Errorf("ran_crowdsec_alerts_dropped_total = %v, want >= 1", got)
	}
	close(release)
	a.Close()
}

func TestCrowdSecFailureMetrics(t *testing.T) {
	srv := testServer(t, "ran", "secret", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(403)
	})
	defer srv.Close()

	m := testMetrics(t)
	a, err := NewCrowdSec(context.Background(), testConfig(srv.URL), slog.Default(), m)
	if err != nil {
		t.Fatalf("NewCrowdSec failed: %v", err)
	}
	a.Submit(context.Background(), ev("8.8.8.8", "http"))
	a.Close()
	if got := pipelineCount(t, m, "http", "failed"); got != 1 {
		t.Errorf("failed = %v, want 1", got)
	}
}

func TestCrowdSecGracefulDrain(t *testing.T) {
	var count atomic.Int32
	srv := testServer(t, "ran", "secret", func(w http.ResponseWriter, r *http.Request) {
		count.Add(1)
		w.WriteHeader(200)
	})
	defer srv.Close()

	m := testMetrics(t)
	a, err := NewCrowdSec(context.Background(), testConfig(srv.URL), slog.Default(), m)
	if err != nil {
		t.Fatalf("NewCrowdSec failed: %v", err)
	}
	a.Submit(context.Background(), ev("1.1.1.1", "ssh"))
	a.Submit(context.Background(), ev("8.8.8.8", "http"))
	a.Submit(context.Background(), ev(testIP(4), "mysql"))
	a.Close()

	if got := count.Load(); got != 3 {
		t.Errorf("drained %d alerts, want 3", got)
	}
}

func TestNoopAlerter(t *testing.T) {
	var a Alerter = NoopAlerter{}
	if c := a.Alert(context.Background(), SessionInfo{SourceIP: "8.8.8.8", Protocol: "ssh"}, map[string]string{"username": "root"}); c != "" {
		t.Errorf("class = %q, want empty", c)
	}
	if a.SessionEnd(SessionInfo{}) {
		t.Error("NoopAlerter must not claim to aggregate logs")
	}
	a.Close()
}

// --- Filter and cooldown integration tests ---

func countingServer(t *testing.T) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	var count atomic.Int32
	srv := testServer(t, "ran", "secret", func(w http.ResponseWriter, r *http.Request) {
		count.Add(1)
		w.WriteHeader(200)
	})
	t.Cleanup(srv.Close)
	return srv, &count
}

func TestCrowdSecFilteredByBanOn(t *testing.T) {
	srv, count := countingServer(t)
	m := testMetrics(t)
	a, err := NewCrowdSec(context.Background(), testConfig(srv.URL), slog.Default(), m) // default: attack, scan
	if err != nil {
		t.Fatal(err)
	}
	a.Submit(context.Background(), evClass("8.8.8.8", "vnc", ClassProbe))
	a.Close()

	if got := count.Load(); got != 0 {
		t.Errorf("POST count = %d, want 0 (probe not enabled)", got)
	}
	for stage, want := range map[string]float64{"received": 1, "filtered": 1, "queued": 0, "cooldown": 0} {
		if got := pipelineCount(t, m, "vnc", stage); got != want {
			t.Errorf("stage %s = %v, want %v", stage, got, want)
		}
	}
}

func TestCrowdSecBanOnProbeEnabled(t *testing.T) {
	srv, count := countingServer(t)
	cfg := testConfig(srv.URL)
	cfg.BanOn = []Class{ClassProbe, ClassAttack, ClassScan}
	a, err := NewCrowdSec(context.Background(), cfg, slog.Default(), testMetrics(t))
	if err != nil {
		t.Fatal(err)
	}
	a.Submit(context.Background(), evClass("8.8.8.8", "vnc", ClassProbe))
	a.Close()
	if got := count.Load(); got != 1 {
		t.Errorf("POST count = %d, want 1", got)
	}
}

func TestCrowdSecCooldown(t *testing.T) {
	srv, count := countingServer(t)
	m := testMetrics(t)
	cfg := testConfig(srv.URL)
	cfg.Cooldown = 4 * time.Hour
	a, err := NewCrowdSec(context.Background(), cfg, slog.Default(), m)
	if err != nil {
		t.Fatal(err)
	}
	for range 10 {
		a.Submit(context.Background(), ev("8.8.8.8", "ssh"))
	}
	a.Close()

	if got := count.Load(); got != 1 {
		t.Errorf("POST count = %d, want 1 (9 in cooldown)", got)
	}
	if got := pipelineCount(t, m, "ssh", "cooldown"); got != 9 {
		t.Errorf("cooldown = %v, want 9", got)
	}
	if got := pipelineCount(t, m, "ssh", "received"); got != 10 {
		t.Errorf("received = %v, want 10", got)
	}
}

func TestCrowdSecCooldownIsPerIPAndClassNotProtocol(t *testing.T) {
	srv, count := countingServer(t)
	cfg := testConfig(srv.URL)
	cfg.Cooldown = 4 * time.Hour
	a, err := NewCrowdSec(context.Background(), cfg, slog.Default(), testMetrics(t))
	if err != nil {
		t.Fatal(err)
	}
	a.Submit(context.Background(), ev("8.8.8.8", "ssh"))
	a.Submit(context.Background(), ev("1.1.1.1", "ssh"))  // other IP
	a.Submit(context.Background(), ev("8.8.8.8", "http")) // same IP and class, other protocol
	a.Close()
	if got := count.Load(); got != 2 {
		t.Errorf("POST count = %d, want 2", got)
	}
}

func TestCrowdSecClassEscalationBypassesCooldown(t *testing.T) {
	srv, count := countingServer(t)
	cfg := testConfig(srv.URL)
	cfg.Cooldown = 4 * time.Hour
	cfg.BanOn = []Class{ClassProbe, ClassAttack, ClassScan}
	a, err := NewCrowdSec(context.Background(), cfg, slog.Default(), testMetrics(t))
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	a.Submit(ctx, evClass("8.8.8.8", "ssh", ClassProbe))
	a.Submit(ctx, evClass("8.8.8.8", "ssh", ClassProbe)) // cooldown
	a.Submit(ctx, evClass("8.8.8.8", "ssh", ClassAttack))
	a.Submit(ctx, evClass("8.8.8.8", "ssh", ClassAttack))   // cooldown
	a.Submit(ctx, evClass("8.8.8.8", "ssh", ClassProbe))    // lower class, cooldown
	a.Submit(ctx, evClass("8.8.8.8", "redis", ClassScan))   // escalation
	a.Submit(ctx, evClass("8.8.8.8", "redis", ClassAttack)) // lower than scan, cooldown
	a.Close()
	if got := count.Load(); got != 3 {
		t.Errorf("POST count = %d, want 3 (probe, attack, scan)", got)
	}
}

// --- Batch integration tests ---

func TestCrowdSecBatch(t *testing.T) {
	var mu sync.Mutex
	var posts [][]csAlert
	srv := testServer(t, "ran", "secret", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var alerts []csAlert
		_ = json.Unmarshal(body, &alerts)
		mu.Lock()
		posts = append(posts, alerts)
		mu.Unlock()
		w.WriteHeader(200)
	})
	defer srv.Close()

	m := testMetrics(t)
	cfg := testConfig(srv.URL)
	cfg.BatchInterval = 50 * time.Millisecond
	cfg.BatchSize = 50
	a, err := NewCrowdSec(context.Background(), cfg, slog.Default(), m)
	if err != nil {
		t.Fatalf("NewCrowdSec failed: %v", err)
	}

	a.Submit(context.Background(), ev("1.1.1.1", "ssh"))
	a.Submit(context.Background(), ev("8.8.8.8", "http"))
	a.Submit(context.Background(), ev(testIP(4), "ftp"))

	time.Sleep(100 * time.Millisecond)
	a.Close()

	mu.Lock()
	defer mu.Unlock()
	if len(posts) != 1 {
		t.Fatalf("got %d POSTs, want 1 batch", len(posts))
	}
	if len(posts[0]) != 3 {
		t.Errorf("batch contained %d alerts, want 3", len(posts[0]))
	}
}

func TestCrowdSecBatchSizeFlush(t *testing.T) {
	var mu sync.Mutex
	var postCount int
	srv := testServer(t, "ran", "secret", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		postCount++
		mu.Unlock()
		w.WriteHeader(200)
	})
	defer srv.Close()

	m := testMetrics(t)
	cfg := testConfig(srv.URL)
	cfg.BatchInterval = 10 * time.Second
	cfg.BatchSize = 2
	a, err := NewCrowdSec(context.Background(), cfg, slog.Default(), m)
	if err != nil {
		t.Fatalf("NewCrowdSec failed: %v", err)
	}

	a.Submit(context.Background(), ev("1.1.1.1", "ssh"))
	a.Submit(context.Background(), ev("8.8.8.8", "ssh"))
	a.Submit(context.Background(), ev(testIP(4), "ssh"))

	time.Sleep(50 * time.Millisecond)
	a.Close()

	mu.Lock()
	defer mu.Unlock()
	if postCount < 2 {
		t.Errorf("POST count = %d, want >= 2 (batch size 2 with 3 alerts)", postCount)
	}
}

func TestCrowdSecBatchCloseFlush(t *testing.T) {
	var mu sync.Mutex
	var totalAlerts int
	srv := testServer(t, "ran", "secret", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var alerts []csAlert
		_ = json.Unmarshal(body, &alerts)
		mu.Lock()
		totalAlerts += len(alerts)
		mu.Unlock()
		w.WriteHeader(200)
	})
	defer srv.Close()

	m := testMetrics(t)
	cfg := testConfig(srv.URL)
	cfg.BatchInterval = 10 * time.Second
	cfg.BatchSize = 100
	a, err := NewCrowdSec(context.Background(), cfg, slog.Default(), m)
	if err != nil {
		t.Fatalf("NewCrowdSec failed: %v", err)
	}

	a.Submit(context.Background(), ev("1.1.1.1", "ssh"))
	a.Submit(context.Background(), ev("8.8.8.8", "http"))
	a.Close()

	mu.Lock()
	defer mu.Unlock()
	if totalAlerts != 2 {
		t.Errorf("total alerts flushed = %d, want 2", totalAlerts)
	}
}

func TestCrowdSecBatchImmediateMode(t *testing.T) {
	var count atomic.Int32
	srv := testServer(t, "ran", "secret", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var alerts []csAlert
		_ = json.Unmarshal(body, &alerts)
		if len(alerts) != 1 {
			t.Errorf("immediate mode: batch contained %d alerts, want 1", len(alerts))
		}
		count.Add(1)
		w.WriteHeader(200)
	})
	defer srv.Close()

	m := testMetrics(t)
	cfg := testConfig(srv.URL)
	cfg.BatchInterval = 0
	cfg.BatchSize = 1
	a, err := NewCrowdSec(context.Background(), cfg, slog.Default(), m)
	if err != nil {
		t.Fatalf("NewCrowdSec failed: %v", err)
	}

	a.Submit(context.Background(), ev("1.1.1.1", "ssh"))
	a.Submit(context.Background(), ev("8.8.8.8", "http"))
	a.Close()

	if got := count.Load(); got != 2 {
		t.Errorf("POST count = %d, want 2 (immediate mode)", got)
	}
}
