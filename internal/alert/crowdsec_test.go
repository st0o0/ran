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

func TestCrowdSecAlertFormat(t *testing.T) {
	var received []csAlert
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Api-Key") != "testkey" {
			t.Errorf("X-Api-Key = %q, want testkey", r.Header.Get("X-Api-Key"))
		}
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &received)
		w.WriteHeader(200)
	}))
	defer srv.Close()

	m := testMetrics(t)
	a := NewCrowdSec(srv.URL, "testkey", 4*time.Hour, slog.Default(), m)
	a.Alert(context.Background(), "1.2.3.4", "ssh")
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
}

func TestCrowdSecPermanentBan(t *testing.T) {
	var received []csAlert
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &received)
		w.WriteHeader(200)
	}))
	defer srv.Close()

	m := testMetrics(t)
	a := NewCrowdSec(srv.URL, "key", 0, slog.Default(), m)
	a.Alert(context.Background(), "5.6.7.8", "mysql")
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

func TestCrowdSecChannelOverflow(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(100 * time.Millisecond)
		w.WriteHeader(200)
	}))
	defer srv.Close()

	m := testMetrics(t)
	a := NewCrowdSec(srv.URL, "key", 4*time.Hour, slog.Default(), m)

	// Fill the channel
	for range 256 {
		a.Alert(context.Background(), "1.1.1.1", "ssh")
	}
	// This should be dropped (channel full)
	a.Alert(context.Background(), "2.2.2.2", "ssh")

	a.Close()
}

func TestCrowdSecFailureMetrics(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(403)
	}))
	defer srv.Close()

	reg := prometheus.NewRegistry()
	m := metrics.New(reg)
	a := NewCrowdSec(srv.URL, "badkey", 4*time.Hour, slog.Default(), m)
	a.Alert(context.Background(), "1.2.3.4", "http")
	a.Close()
}

func TestCrowdSecGracefulDrain(t *testing.T) {
	var count atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		count.Add(1)
		w.WriteHeader(200)
	}))
	defer srv.Close()

	m := testMetrics(t)
	a := NewCrowdSec(srv.URL, "key", 4*time.Hour, slog.Default(), m)
	a.Alert(context.Background(), "1.1.1.1", "ssh")
	a.Alert(context.Background(), "2.2.2.2", "http")
	a.Alert(context.Background(), "3.3.3.3", "mysql")
	a.Close()

	if got := count.Load(); got != 3 {
		t.Errorf("drained %d alerts, want 3", got)
	}
}

func TestNoopAlerter(t *testing.T) {
	var a Alerter = NoopAlerter{}
	a.Alert(context.Background(), "1.2.3.4", "ssh")
	a.Close()
}
