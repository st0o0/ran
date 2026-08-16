package alert

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"log/slog"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/st0o0/ran/internal/metrics"
)

func testMetrics(t *testing.T) *metrics.Metrics {
	t.Helper()
	return metrics.New(prometheus.NewRegistry())
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
	a, err := NewCrowdSec(srv.URL, "ran", "secret", 4*time.Hour, slog.Default(), m)
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
	_, err := NewCrowdSec(srv.URL, "ran", "wrong-password", 4*time.Hour, slog.Default(), m)
	if err == nil {
		t.Fatal("expected error for invalid credentials")
	}
}

func TestCrowdSecAlertFormat(t *testing.T) {
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
		_ = json.Unmarshal(body, &received)
		w.WriteHeader(200)
	})
	defer srv.Close()

	m := testMetrics(t)
	a, err := NewCrowdSec(srv.URL, "ran", "secret", 4*time.Hour, slog.Default(), m)
	if err != nil {
		t.Fatalf("NewCrowdSec failed: %v", err)
	}
	a.Alert(context.Background(), "1.2.3.4", "ssh", map[string]string{"username": "root", "password": "admin"})
	a.Close()

	if len(received) != 1 {
		t.Fatalf("got %d alerts, want 1", len(received))
	}
	alert := received[0]
	if alert.Scenario != "custom/ran-ssh-trap" {
		t.Errorf("scenario = %q, want custom/ran-ssh-trap", alert.Scenario)
	}
	if alert.Source.Value != "1.2.3.4" {
		t.Errorf("source = %q, want 1.2.3.4", alert.Source.Value)
	}
	if len(alert.Decisions) != 1 {
		t.Fatalf("got %d decisions, want 1", len(alert.Decisions))
	}
	if alert.Decisions[0].Duration != "4h0m0s" {
		t.Errorf("duration = %q, want 4h0m0s", alert.Decisions[0].Duration)
	}
	if alert.Decisions[0].Type != "ban" {
		t.Errorf("type = %q, want ban", alert.Decisions[0].Type)
	}
	if alert.Source.Scope != "Ip" {
		t.Errorf("source.scope = %q, want Ip", alert.Source.Scope)
	}
	if alert.Decisions[0].Scope != "Ip" {
		t.Errorf("decisions[0].scope = %q, want Ip", alert.Decisions[0].Scope)
	}
	if len(alert.Events) != 1 {
		t.Fatalf("got %d events, want 1", len(alert.Events))
	}
	if len(alert.Events[0].Meta) != 2 {
		t.Fatalf("got %d meta entries, want 2", len(alert.Events[0].Meta))
	}
	if alert.Events[0].Meta[0].Key != "password" || alert.Events[0].Meta[0].Value != "admin" {
		t.Errorf("meta[0] = %+v, want {password admin}", alert.Events[0].Meta[0])
	}
	if alert.Events[0].Meta[1].Key != "username" || alert.Events[0].Meta[1].Value != "root" {
		t.Errorf("meta[1] = %+v, want {username root}", alert.Events[0].Meta[1])
	}
}

func TestCrowdSecAlertNilMeta(t *testing.T) {
	var received []csAlert
	srv := testServer(t, "ran", "secret", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &received)
		w.WriteHeader(200)
	})
	defer srv.Close()

	m := testMetrics(t)
	a, err := NewCrowdSec(srv.URL, "ran", "secret", 4*time.Hour, slog.Default(), m)
	if err != nil {
		t.Fatalf("NewCrowdSec failed: %v", err)
	}
	a.Alert(context.Background(), "10.0.0.1", "memcached", nil)
	a.Close()

	if len(received) != 1 {
		t.Fatalf("got %d alerts, want 1", len(received))
	}
	alert := received[0]
	if len(alert.Events) != 1 {
		t.Fatalf("got %d events, want 1", len(alert.Events))
	}
	if alert.Events[0].Meta == nil {
		t.Fatal("events[0].meta is nil, want empty array")
	}
	if len(alert.Events[0].Meta) != 0 {
		t.Errorf("got %d meta entries, want 0", len(alert.Events[0].Meta))
	}
}

func TestCrowdSecPermanentBan(t *testing.T) {
	var received []csAlert
	srv := testServer(t, "ran", "secret", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &received)
		w.WriteHeader(200)
	})
	defer srv.Close()

	m := testMetrics(t)
	a, err := NewCrowdSec(srv.URL, "ran", "secret", 0, slog.Default(), m)
	if err != nil {
		t.Fatalf("NewCrowdSec failed: %v", err)
	}
	a.Alert(context.Background(), "5.6.7.8", "mysql", nil)
	a.Close()

	if len(received) != 1 {
		t.Fatalf("got %d alerts, want 1", len(received))
	}
	if received[0].Decisions[0].Duration != "0" {
		t.Errorf("duration = %q, want 0 (permanent)", received[0].Decisions[0].Duration)
	}
	if received[0].Scenario != "custom/ran-mysql-trap" {
		t.Errorf("scenario = %q, want custom/ran-mysql-trap", received[0].Scenario)
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
	a, err := NewCrowdSec(srv.URL, "ran", "secret", 4*time.Hour, slog.Default(), m)
	if err != nil {
		t.Fatalf("NewCrowdSec failed: %v", err)
	}
	a.Alert(context.Background(), "1.2.3.4", "ssh", map[string]string{"username": "root", "password": "admin"})
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
	a, err := NewCrowdSec(srv.URL, "ran", "secret", 4*time.Hour, slog.Default(), m)
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
	srv := testServer(t, "ran", "secret", func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(100 * time.Millisecond)
		w.WriteHeader(200)
	})
	defer srv.Close()

	m := testMetrics(t)
	a, err := NewCrowdSec(srv.URL, "ran", "secret", 4*time.Hour, slog.Default(), m)
	if err != nil {
		t.Fatalf("NewCrowdSec failed: %v", err)
	}

	for range 256 {
		a.Alert(context.Background(), "1.1.1.1", "ssh", nil)
	}
	// This should be dropped (channel full)
	a.Alert(context.Background(), "2.2.2.2", "ssh", nil)

	a.Close()
}

func TestCrowdSecFailureMetrics(t *testing.T) {
	srv := testServer(t, "ran", "secret", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(403)
	})
	defer srv.Close()

	reg := prometheus.NewRegistry()
	m := metrics.New(reg)
	a, err := NewCrowdSec(srv.URL, "ran", "secret", 4*time.Hour, slog.Default(), m)
	if err != nil {
		t.Fatalf("NewCrowdSec failed: %v", err)
	}
	a.Alert(context.Background(), "1.2.3.4", "http", nil)
	a.Close()
}

func TestCrowdSecGracefulDrain(t *testing.T) {
	var count atomic.Int32
	srv := testServer(t, "ran", "secret", func(w http.ResponseWriter, r *http.Request) {
		count.Add(1)
		w.WriteHeader(200)
	})
	defer srv.Close()

	m := testMetrics(t)
	a, err := NewCrowdSec(srv.URL, "ran", "secret", 4*time.Hour, slog.Default(), m)
	if err != nil {
		t.Fatalf("NewCrowdSec failed: %v", err)
	}
	a.Alert(context.Background(), "1.1.1.1", "ssh", nil)
	a.Alert(context.Background(), "2.2.2.2", "http", nil)
	a.Alert(context.Background(), "3.3.3.3", "mysql", nil)
	a.Close()

	if got := count.Load(); got != 3 {
		t.Errorf("drained %d alerts, want 3", got)
	}
}

func TestNoopAlerter(t *testing.T) {
	var a Alerter = NoopAlerter{}
	a.Alert(context.Background(), "1.2.3.4", "ssh", map[string]string{"username": "root", "password": "admin"})
	a.Close()
}
