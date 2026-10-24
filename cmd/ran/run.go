package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/st0o0/ran/internal/alert"
	"github.com/st0o0/ran/internal/config"
	"github.com/st0o0/ran/internal/metrics"
	"github.com/st0o0/ran/internal/trap"
)

// The whole shutdown shares one deadline of shutdownBudget, below Docker's
// default 10s stop grace period. Traps and the metrics server get
// shutdownTimeout of it; the alert sink then drains within whatever remains
// (about 5s, never more than the CrowdSec flush timeout). Variables so tests can
// shorten them.
var (
	shutdownBudget  = 9 * time.Second
	shutdownTimeout = 4 * time.Second
)

// trapResult is the outcome of one trap's Start call.
type trapResult struct {
	name string
	err  error
}

// run starts the traps and, if metricsSrv is not nil, the metrics server, and
// blocks until ctx is canceled, every trap failed, or the metrics server died.
// Whatever ends the run, all components are shut down before it returns.
func run(ctx context.Context, cfg *config.Config, logger *slog.Logger, m *metrics.Metrics, metricsSrv *http.Server) error {
	// A failing component cancels the context for all others.
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	trap.SetPasswordLogMode(cfg.LogPasswords)

	limiter := trap.NewLimiter(cfg.MaxSessions, cfg.MaxPerIP)

	for _, name := range cfg.RemovedEnvVars {
		logger.Warn("ignoring removed environment variable; ran no longer decides ban durations, use a CrowdSec profile", "variable", name)
	}

	if len(cfg.IgnoreIPs) > 0 {
		logger.Info("ignore list active; these sources are served and logged but never alert", "ignored_ranges", len(cfg.IgnoreIPs))
	}

	var sink alert.Sink
	if cfg.CrowdSec {
		banOn := make([]alert.Class, len(cfg.BanOn))
		for i, c := range cfg.BanOn {
			banOn[i] = alert.Class(c)
		}
		cs, err := alert.NewCrowdSec(ctx, alert.CrowdSecConfig{
			URL:           cfg.CrowdSecURL,
			MachineID:     cfg.CrowdSecMachineID,
			Password:      cfg.CrowdSecPassword,
			BanOn:         banOn,
			Cooldown:      cfg.AlertCooldown,
			BatchInterval: cfg.CrowdSecBatchInterval,
			BatchSize:     cfg.CrowdSecBatchSize,
			MaxTracked:    cfg.CrowdSecMaxTracked,
		}, logger, m)
		if err != nil {
			return fmt.Errorf("crowdsec: %w", err)
		}
		sink = cs
		logger.Info("crowdsec alerter enabled; ran does not ban by itself, a CrowdSec profile must create the decisions",
			"url", cfg.CrowdSecURL, "ban_on", cfg.BanOn, "alert_cooldown", cfg.AlertCooldown)
	}
	alerter := alert.NewSensor(alert.SensorConfig{
		MaxTracked:    cfg.CrowdSecMaxTracked,
		SummaryWindow: cfg.ProbeSummaryWindow,
		Metrics:       m,
		IgnoreIPs:     cfg.IgnoreIPs,
	}, sink, logger)
	// Runs last: traps are stopped first, so the final events still reach the
	// sink. The sink gets the remainder of the shared shutdown deadline.
	var deadline time.Time
	defer func() {
		if deadline.IsZero() {
			deadline = time.Now().Add(shutdownBudget)
		}
		cctx, ccancel := context.WithDeadline(context.Background(), deadline)
		defer ccancel()
		alerter.CloseContext(cctx)
	}()

	traps, err := trap.CreateTraps(cfg, logger, m, limiter, alerter)
	if err != nil {
		return err
	}

	// Listen first: a metrics port that cannot be bound is a startup error, and
	// no trap has been started yet.
	metricsErrc := make(chan error, 1)
	if metricsSrv != nil {
		ln, err := net.Listen("tcp", metricsSrv.Addr)
		if err != nil {
			return fmt.Errorf("metrics server: listen on %s: %w (change RAN_METRICS_ADDR)", metricsSrv.Addr, err)
		}
		logger.Info("metrics server listening", "addr", ln.Addr().String())
		go func() {
			if err := metricsSrv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
				metricsErrc <- err
			}
		}()
	}

	names := cfg.EnabledTraps()
	results := make(chan trapResult, len(traps))
	var started sync.WaitGroup
	for i, t := range traps {
		started.Add(1)
		go func(name string, t trap.Trap) {
			defer started.Done()
			err := t.Start(ctx)
			// Logged here, not in the wait loop below, so a failure is never
			// lost when shutdown wins the select first.
			if err != nil {
				logger.Error("trap failed to start", "trap", name, "error", err)
			}
			results <- trapResult{name: name, err: err}
		}(names[i], t)
	}

	var runErr error
	running, failed := len(traps), 0
wait:
	for running > 0 {
		select {
		case r := <-results:
			running--
			switch {
			case r.err != nil:
				failed++
			case ctx.Err() == nil:
				logger.Error("trap exited unexpectedly", "trap", r.name)
			}
			if failed == len(traps) {
				runErr = fmt.Errorf("all %d traps failed to start", len(traps))
				break wait
			}
		case err := <-metricsErrc:
			logger.Error("metrics server failed", "error", err)
			runErr = fmt.Errorf("metrics server: %w", err)
			break wait
		case <-ctx.Done():
			break wait
		}
	}

	// Every trap returned cleanly while nothing asked to stop: the sensor would
	// idle without listening, so fail loudly and let the runtime restart it.
	if running == 0 && runErr == nil && ctx.Err() == nil {
		logger.Error("all traps exited without being asked to stop; nothing is listening")
		runErr = errors.New("all traps exited unexpectedly")
	}

	logger.Info("shutting down")
	deadline = time.Now().Add(shutdownBudget)
	cancel()
	shutdown(logger, names, traps, metricsSrv)

	// Stopped traps return from Start; give their (failure) log lines a moment
	// so none is lost. Stuck traps are not waited for.
	startsDone := make(chan struct{})
	go func() {
		started.Wait()
		close(startsDone)
	}()
	select {
	case <-startsDone:
	case <-time.After(time.Second):
	}
	return runErr
}

// shutdown stops all traps in parallel and the metrics server, within
// shutdownTimeout. Components that do not stop in time are abandoned (and
// logged) so the process still exits before the container runtime kills it.
func shutdown(logger *slog.Logger, names []string, traps []trap.Trap, metricsSrv *http.Server) {
	ctx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()

	var wg sync.WaitGroup
	for i, t := range traps {
		wg.Add(1)
		go func(name string, t trap.Trap) {
			defer wg.Done()
			if err := t.Stop(ctx); err != nil {
				logger.Warn("trap stop failed", "trap", name, "error", err)
			}
		}(names[i], t)
	}
	if metricsSrv != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := metricsSrv.Shutdown(ctx); err != nil {
				logger.Warn("metrics server shutdown failed", "error", err)
				_ = metricsSrv.Close()
			}
		}()
	}

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-ctx.Done():
		logger.Warn("shutdown timed out; some components are still stopping", "timeout", shutdownTimeout)
	}
}
