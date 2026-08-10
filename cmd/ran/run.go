package main

import (
	"context"
	"log/slog"

	"github.com/st0o0/ran/internal/alert"
	"github.com/st0o0/ran/internal/config"
	"github.com/st0o0/ran/internal/metrics"
	"github.com/st0o0/ran/internal/trap"
)

func run(ctx context.Context, cfg *config.Config, logger *slog.Logger, m *metrics.Metrics) error {
	limiter := trap.NewLimiter(cfg.MaxSessions, cfg.MaxPerIP)

	var alerter alert.Alerter
	if cfg.CrowdSec {
		alerter = alert.NewCrowdSec(cfg.CrowdSecURL, cfg.CrowdSecAPIKey, cfg.CrowdSecBanDuration, logger, m)
		logger.Info("crowdsec alerter enabled", "url", cfg.CrowdSecURL, "ban_duration", cfg.CrowdSecBanDuration)
	} else {
		alerter = alert.NoopAlerter{}
	}
	defer alerter.Close()

	traps, err := trap.CreateTraps(cfg, logger, m, limiter, alerter)
	if err != nil {
		return err
	}

	errc := make(chan error, len(traps))
	for _, t := range traps {
		go func(t trap.Trap) {
			errc <- t.Start(ctx)
		}(t)
	}

	<-ctx.Done()
	logger.Info("shutting down")

	for _, t := range traps {
		_ = t.Stop(context.Background())
	}
	return nil
}
