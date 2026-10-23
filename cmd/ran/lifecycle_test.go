package main

import (
	"bytes"
	"context"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/st0o0/ran/internal/config"
	"github.com/st0o0/ran/internal/metrics"
	"github.com/st0o0/ran/internal/trap"
)

func TestCheckConfig(t *testing.T) {
	env := func(m map[string]string) func(string) string {
		return func(k string) string { return m[k] }
	}
	var out, errb bytes.Buffer
	if code := checkConfig(env(map[string]string{"RAN_TRAPS": "ssh,http"}), &out, &errb); code != 0 {
		t.Fatalf("valid config: exit %d, stderr %q", code, errb.String())
	}
	if !strings.Contains(out.String(), "configuration ok") {
		t.Errorf("stdout = %q", out.String())
	}

	out.Reset()
	errb.Reset()
	if code := checkConfig(env(map[string]string{"RAN_TRAPS": "ssh", "RAN_SSH_ADDR": "bogus"}), &out, &errb); code != 1 {
		t.Fatalf("invalid config: exit %d, want 1", code)
	}
	if !strings.Contains(errb.String(), "RAN_SSH_ADDR") || !strings.Contains(errb.String(), "for example") {
		t.Errorf("stderr lacks a remedy: %q", errb.String())
	}

	if code := checkConfig(env(nil), &out, &errb); code != 1 {
		t.Errorf("missing RAN_TRAPS: exit %d, want 1", code)
	}
}

func TestHealthcheckFailsOnInvalidConfig(t *testing.T) {
	t.Setenv("RAN_TRAPS", "no-such-trap")
	if code := healthcheck(); code != 1 {
		t.Fatalf("healthcheck exit = %d, want 1", code)
	}
}

func TestRunMetricsListenFailure(t *testing.T) {
	busy, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer busy.Close()

	ft := &fakeTrap{started: make(chan struct{})}
	cfg, logger, m, _ := testSetup(t, []string{"test-ok"}, map[string]trap.Factory{
		"test-ok": func(*config.Config, *slog.Logger, *metrics.Metrics, *trap.Limiter, trap.Reporter) (trap.Trap, error) {
			return ft, nil
		},
	})
	err = run(context.Background(), cfg, logger, m, &http.Server{Addr: busy.Addr().String()})
	if err == nil || !strings.Contains(err.Error(), "metrics server") {
		t.Fatalf("run() = %v, want metrics server error", err)
	}
	select {
	case <-ft.started:
		t.Error("traps must not start when the metrics port cannot be bound")
	default:
	}
}

func TestRunShutsDownMetricsServer(t *testing.T) {
	ft := &fakeTrap{started: make(chan struct{})}
	cfg, logger, m, _ := testSetup(t, []string{"test-ok"}, map[string]trap.Factory{
		"test-ok": func(*config.Config, *slog.Logger, *metrics.Metrics, *trap.Limiter, trap.Reporter) (trap.Trap, error) {
			return ft, nil
		},
	})
	srv := &http.Server{Addr: "127.0.0.1:0", Handler: http.NewServeMux(), ReadHeaderTimeout: time.Second}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- run(ctx, cfg, logger, m, srv) }()
	select {
	case <-ft.started:
	case <-time.After(2 * time.Second):
		t.Fatal("trap did not start")
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("run() = %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("run() did not return")
	}
	if err := srv.ListenAndServe(); err != http.ErrServerClosed {
		t.Errorf("metrics server not shut down: %v", err)
	}
}

// stuckTrap never finishes Stop; run must give up after shutdownTimeout.
type stuckTrap struct{ fakeTrap }

func (s *stuckTrap) Stop(ctx context.Context) error {
	time.Sleep(10 * time.Second)
	return nil
}

func TestRunShutdownIsBounded(t *testing.T) {
	old := shutdownTimeout
	shutdownTimeout = 150 * time.Millisecond
	t.Cleanup(func() { shutdownTimeout = old })

	st := &stuckTrap{fakeTrap{started: make(chan struct{})}}
	cfg, logger, m, buf := testSetup(t, []string{"test-stuck"}, map[string]trap.Factory{
		"test-stuck": func(*config.Config, *slog.Logger, *metrics.Metrics, *trap.Limiter, trap.Reporter) (trap.Trap, error) {
			return st, nil
		},
	})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- run(ctx, cfg, logger, m, nil) }()
	<-st.started
	start := time.Now()
	cancel()
	select {
	case err := <-done:
		_ = err
	case <-time.After(3 * time.Second):
		t.Fatal("run() blocked on a stuck trap")
	}
	if time.Since(start) > 2*time.Second {
		t.Error("shutdown was not bounded")
	}
	if !strings.Contains(buf.String(), "shutdown timed out") {
		t.Error("expected a shutdown timeout warning")
	}
}
