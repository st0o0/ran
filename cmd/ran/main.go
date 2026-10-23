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
	os.Exit(realMain(os.Args[1:]))
}

// realMain returns the exit code instead of calling os.Exit, so deferred
// cleanup always runs.
func realMain(args []string) int {
	if len(args) > 0 {
		switch args[0] {
		case "healthcheck":
			return healthcheck()
		case "check-config":
			return checkConfig(os.Getenv, os.Stdout, os.Stderr)
		case "version":
			fmt.Println(version)
			return 0
		}
	}

	cfg, err := config.Load(os.Getenv)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ran: invalid configuration: %v\n", err)
		return 1
	}

	logger := newLogger(cfg)
	slog.SetDefault(logger)

	startTime := time.Now()

	reg := prometheus.NewRegistry()
	m := metrics.New(reg, version)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()

	if err := run(ctx, cfg, logger, m, newMetricsServer(cfg.MetricsAddr, reg, startTime, cfg.EnabledTraps())); err != nil {
		logger.Error("fatal", "error", err)
		return 1
	}
	return 0
}

// newMetricsServer builds the metrics and health HTTP server with timeouts, so a
// slow or malicious client cannot hold connections open.
func newMetricsServer(addr string, reg *prometheus.Registry, startTime time.Time, traps []string) *http.Server {
	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.HandlerFor(reg, promhttp.HandlerOpts{}))
	mux.HandleFunc("/healthz", healthzHandler(version, startTime, traps))
	return &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    16 << 10,
	}
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
