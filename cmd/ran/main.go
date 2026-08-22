package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/st0o0/ran/internal/config"
	"github.com/st0o0/ran/internal/metrics"
)

var version = "dev"

func main() {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "healthcheck":
			os.Exit(healthcheck())
		case "version":
			fmt.Println(version)
			return
		}
	}

	cfg, err := config.Load(os.Getenv)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ran: %v\n", err)
		os.Exit(1)
	}

	logger := newLogger(cfg)
	slog.SetDefault(logger)

	startTime := time.Now()

	reg := prometheus.NewRegistry()
	m := metrics.New(reg, version)

	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.HandlerFor(reg, promhttp.HandlerOpts{}))
	mux.HandleFunc("/healthz", healthzHandler(version, startTime, cfg.EnabledTraps()))
	metricsSrv := &http.Server{Addr: cfg.MetricsAddr, Handler: mux}

	go func() {
		logger.Info("metrics server starting", "addr", cfg.MetricsAddr)
		if err := metricsSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Error("metrics server failed", "error", err)
			os.Exit(1)
		}
	}()

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()

	if err := run(ctx, cfg, logger, m); err != nil {
		logger.Error("fatal", "error", err)
		os.Exit(1)
	}

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer shutdownCancel()
	_ = metricsSrv.Shutdown(shutdownCtx)
}

func healthzHandler(ver string, startTime time.Time, traps []string) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(map[string]any{
			"status":  "ok",
			"version": ver,
			"uptime":  time.Since(startTime).Truncate(time.Second).String(),
			"traps":   traps,
		}); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	}
}

func newLogger(cfg *config.Config) *slog.Logger {
	opts := &slog.HandlerOptions{Level: cfg.LogLevel}
	if cfg.LogFormat == "text" {
		return slog.New(slog.NewTextHandler(os.Stdout, opts))
	}
	return slog.New(slog.NewJSONHandler(os.Stdout, opts))
}
