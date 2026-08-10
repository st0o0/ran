package main

import (
	"bytes"
	"context"
	"log/slog"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/st0o0/ran/internal/alert"
	"github.com/st0o0/ran/internal/config"
	"github.com/st0o0/ran/internal/metrics"
	"github.com/st0o0/ran/internal/trap"
)

type fakeTrap struct {
	startErr error
	started  chan struct{}
}

func (f *fakeTrap) Start(ctx context.Context) error {
	if f.startErr != nil {
		return f.startErr
	}
	close(f.started)
	<-ctx.Done()
	return nil
}

func (f *fakeTrap) Stop(_ context.Context) error { return nil }

func freePort(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()
	return addr
}

func testSetup(t *testing.T, trapNames []string, factories map[string]trap.Factory) (*config.Config, *slog.Logger, *metrics.Metrics, *bytes.Buffer) {
	t.Helper()
	for name, f := range factories {
		trap.Registry[name] = f
	}
	t.Cleanup(func() {
		for name := range factories {
			delete(trap.Registry, name)
		}
	})

	cfg := &config.Config{
		Traps:          trapNames,
		Addrs:          map[string]string{},
		SessionTimeout: 5 * time.Second,
		MaxSessions:    100,
		MaxPerIP:       10,
	}

	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, nil))
	m := metrics.New(prometheus.NewRegistry())
	return cfg, logger, m, &buf
}

func TestRunAllTrapsSucceed(t *testing.T) {
	ft := &fakeTrap{started: make(chan struct{})}
	cfg, logger, m, _ := testSetup(t, []string{"test-ok"}, map[string]trap.Factory{
		"test-ok": func(cfg *config.Config, logger *slog.Logger, m *metrics.Metrics, limiter *trap.Limiter, alerter alert.Alerter) (trap.Trap, error) {
			return ft, nil
		},
	})

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- run(ctx, cfg, logger, m) }()

	select {
	case <-ft.started:
	case <-time.After(2 * time.Second):
		t.Fatal("trap did not start")
	}

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("run() returned error: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("run() did not return")
	}
}

func TestRunPartialFailure(t *testing.T) {
	okTrap := &fakeTrap{started: make(chan struct{})}
	failTrap := &fakeTrap{startErr: net.ErrClosed, started: make(chan struct{})}

	cfg, logger, m, buf := testSetup(t, []string{"test-ok", "test-fail"}, map[string]trap.Factory{
		"test-ok": func(cfg *config.Config, logger *slog.Logger, m *metrics.Metrics, limiter *trap.Limiter, alerter alert.Alerter) (trap.Trap, error) {
			return okTrap, nil
		},
		"test-fail": func(cfg *config.Config, logger *slog.Logger, m *metrics.Metrics, limiter *trap.Limiter, alerter alert.Alerter) (trap.Trap, error) {
			return failTrap, nil
		},
	})

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- run(ctx, cfg, logger, m) }()

	select {
	case <-okTrap.started:
	case <-time.After(2 * time.Second):
		t.Fatal("ok trap did not start")
	}

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("run() should not error on partial failure: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("run() did not return")
	}

	if !strings.Contains(buf.String(), "trap failed to start") {
		t.Error("expected error log for failed trap")
	}
}

func TestRunAllTrapsFail(t *testing.T) {
	fail1 := &fakeTrap{startErr: net.ErrClosed, started: make(chan struct{})}
	fail2 := &fakeTrap{startErr: net.ErrClosed, started: make(chan struct{})}

	cfg, logger, m, _ := testSetup(t, []string{"test-fail1", "test-fail2"}, map[string]trap.Factory{
		"test-fail1": func(cfg *config.Config, logger *slog.Logger, m *metrics.Metrics, limiter *trap.Limiter, alerter alert.Alerter) (trap.Trap, error) {
			return fail1, nil
		},
		"test-fail2": func(cfg *config.Config, logger *slog.Logger, m *metrics.Metrics, limiter *trap.Limiter, alerter alert.Alerter) (trap.Trap, error) {
			return fail2, nil
		},
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	err := run(ctx, cfg, logger, m)
	if err == nil {
		t.Fatal("run() should return error when all traps fail")
	}
	if !strings.Contains(err.Error(), "all 2 traps failed") {
		t.Errorf("unexpected error: %v", err)
	}
}
