package main

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/st0o0/ran/internal/alert"
	"github.com/st0o0/ran/internal/config"
	"github.com/st0o0/ran/internal/metrics"
	"github.com/st0o0/ran/internal/trap"
)

func run(ctx context.Context, cfg *config.Config, logger *slog.Logger, m *metrics.Metrics) error {
	limiter := trap.NewLimiter(cfg.MaxSessions, cfg.MaxPerIP)

	var alerter alert.Alerter
	if cfg.CrowdSec {
		cs, err := alert.NewCrowdSec(cfg.CrowdSecURL, cfg.CrowdSecMachineID, cfg.CrowdSecPassword, cfg.CrowdSecBanDuration, logger, m)
		if err != nil {
			return fmt.Errorf("crowdsec: %w", err)
		}
		alerter = cs
		logger.Info("crowdsec alerter enabled", "url", cfg.CrowdSecURL, "ban_duration", cfg.CrowdSecBanDuration)
	} else {
		alerter = alert.NoopAlerter{}
	}
	defer alerter.Close()

	traps, err := trap.CreateTraps(cfg, logger, m, limiter, alerter)
	if err != nil {
		return err
	}

	names := cfg.EnabledTraps()
	errc := make(chan error, len(traps))
	for i, t := range traps {
		go func(i int, t trap.Trap) {
			if err := t.Start(ctx); err != nil {
				errc <- fmt.Errorf("%s: %w", names[i], err)
			}
		}(i, t)
	}

	// Listen failures return almost instantly; give traps time to bind.
	time.Sleep(250 * time.Millisecond)

	var failed int
	for {
		select {
		case err := <-errc:
			logger.Error("trap failed to start", "error", err)
			failed++
		default:
			goto drained
		}
	}
drained:

	if failed > 0 && failed == len(traps) {
		return fmt.Errorf("all %d traps failed to start", len(traps))
	}

	<-ctx.Done()
	logger.Info("shutting down")

	for _, t := range traps {
		_ = t.Stop(context.Background())
	}
	return nil
}
