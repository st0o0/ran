package trap

import (
	"context"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"log/slog"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/st0o0/ran/internal/alert"
	"github.com/st0o0/ran/internal/config"
	"github.com/st0o0/ran/internal/metrics"
)

func httpTestConfig(t *testing.T) *config.Config {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()

	return &config.Config{
		Traps:          []string{"http"},
		Addrs:          map[string]string{"http": addr},
		SessionTimeout: 5 * time.Second,
		MaxSessions:    100,
		MaxPerIP:       10,
	}
}

func TestHTTPLoginPage(t *testing.T) {
	cfg := httpTestConfig(t)
	reg := prometheus.NewRegistry()
	m := metrics.New(reg, "test")
	limiter := NewLimiter(cfg.MaxSessions, cfg.MaxPerIP)

	trap := NewHTTP(cfg, slog.Default(), m, limiter, alert.NoopAlerter{})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() { _ = trap.Start(ctx) }()
	time.Sleep(100 * time.Millisecond)

	resp, err := http.Get("http://" + cfg.TrapAddr("http") + "/wp-login.php")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != 200 {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}
	if !strings.Contains(string(body), "WordPress") {
		t.Error("body should contain WordPress")
	}
}

func TestHTTPCredentialCapture(t *testing.T) {
	cfg := httpTestConfig(t)
	reg := prometheus.NewRegistry()
	m := metrics.New(reg, "test")
	limiter := NewLimiter(cfg.MaxSessions, cfg.MaxPerIP)

	trap := NewHTTP(cfg, slog.Default(), m, limiter, alert.NoopAlerter{})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() { _ = trap.Start(ctx) }()
	time.Sleep(100 * time.Millisecond)

	resp, err := http.Post(
		"http://"+cfg.TrapAddr("http")+"/wp-login.php",
		"application/x-www-form-urlencoded",
		strings.NewReader("log=admin&pwd=secret123"),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}
}

func TestHTTPAdminPage(t *testing.T) {
	cfg := httpTestConfig(t)
	reg := prometheus.NewRegistry()
	m := metrics.New(reg, "test")
	limiter := NewLimiter(cfg.MaxSessions, cfg.MaxPerIP)

	trap := NewHTTP(cfg, slog.Default(), m, limiter, alert.NoopAlerter{})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() { _ = trap.Start(ctx) }()
	time.Sleep(100 * time.Millisecond)

	resp, err := http.Post(
		"http://"+cfg.TrapAddr("http")+"/admin",
		"application/x-www-form-urlencoded",
		strings.NewReader("username=admin&password=pass"),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	if !strings.Contains(string(body), "Invalid credentials") {
		t.Error("body should contain error message")
	}
}

func TestHTTPResponseHeaders(t *testing.T) {
	cfg := httpTestConfig(t)
	reg := prometheus.NewRegistry()
	m := metrics.New(reg, "test")
	limiter := NewLimiter(cfg.MaxSessions, cfg.MaxPerIP)

	trap := NewHTTP(cfg, slog.Default(), m, limiter, alert.NoopAlerter{})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() { _ = trap.Start(ctx) }()
	time.Sleep(100 * time.Millisecond)

	resp, err := http.Get("http://" + cfg.TrapAddr("http") + "/admin")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if got := resp.Header.Get("Server"); got != "Apache/2.4.62" {
		t.Errorf("Server header = %q, want Apache/2.4.62", got)
	}
}
