package main

import (
	"context"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/st0o0/ran/internal/config"
	"github.com/st0o0/ran/internal/metrics"
	"github.com/st0o0/ran/internal/trap"
)

// quitTrap returns from Start at once without an error, like a listener that
// closed by itself.
type quitTrap struct{ fakeTrap }

func (q *quitTrap) Start(context.Context) error { return nil }

func TestRunFailsWhenAllTrapsExitCleanly(t *testing.T) {
	cfg, logger, m, buf := testSetup(t, []string{"test-quit"}, map[string]trap.Factory{
		"test-quit": func(*config.Config, *slog.Logger, *metrics.Metrics, *trap.Limiter, trap.Reporter) (trap.Trap, error) {
			return &quitTrap{}, nil
		},
	})
	done := make(chan error, 1)
	go func() { done <- run(context.Background(), cfg, logger, m, nil) }()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("run() returned nil although no trap is listening")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("run() did not return after all traps exited")
	}
	if !strings.Contains(buf.String(), "all traps exited") {
		t.Errorf("missing log line: %s", buf.String())
	}
}

func TestShutdownBudgetLeavesRoomForSink(t *testing.T) {
	// The trap phase plus the sink drain (flush timeout, 5s) must fit into the
	// budget, which in turn must stay under Docker's 10s stop grace period.
	if shutdownBudget >= 10*time.Second {
		t.Errorf("shutdownBudget = %v, want below 10s", shutdownBudget)
	}
	if shutdownTimeout+5*time.Second > shutdownBudget {
		t.Errorf("trap phase %v leaves no room for a 5s sink drain within %v", shutdownTimeout, shutdownBudget)
	}
}
