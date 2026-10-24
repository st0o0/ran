package main

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/st0o0/ran/internal/config"
)

// healthcheck probes the local metrics server. It exits non-zero when the
// configuration is invalid, because a container that cannot start its traps is
// not healthy.
func healthcheck() int {
	cfg, err := config.Load(os.Getenv)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ran: unhealthy: invalid configuration: %v\n", err)
		return 1
	}
	return doHealthcheck(healthAddr(cfg.MetricsAddr))
}

func doHealthcheck(addr string) int {
	client := &http.Client{Timeout: 2 * time.Second}
	resp, err := client.Get("http://" + addr + "/healthz")
	if err != nil {
		fmt.Fprintln(os.Stderr, "ran: unhealthy")
		return 1
	}
	resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		fmt.Fprintln(os.Stderr, "ran: unhealthy")
		return 1
	}
	return 0
}

// healthAddr turns the metrics listen address into one that can be dialed from
// inside the container. An empty or wildcard host becomes 127.0.0.1 (never
// "localhost", which may resolve to ::1 while the server listens on IPv4 only).
func healthAddr(addr string) string {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return addr
	}
	if ip := net.ParseIP(host); host == "" || (ip != nil && ip.IsUnspecified()) {
		host = "127.0.0.1"
	}
	return net.JoinHostPort(host, port)
}

// checkConfig validates the environment and reports the result; it returns the
// process exit code (0 valid, 1 invalid).
func checkConfig(getenv func(string) string, stdout, stderr io.Writer) int {
	cfg, err := config.Load(getenv)
	if err != nil {
		fmt.Fprintf(stderr, "ran: invalid configuration: %v\n", err)
		return 1
	}
	for _, name := range cfg.RemovedEnvVars {
		fmt.Fprintf(stderr, "ran: warning: %s is removed and ignored; use a CrowdSec profile for ban durations\n", name)
	}
	if len(cfg.IgnoreIPs) > 0 {
		fmt.Fprintf(stdout, "ran: configuration ok (%d traps: %v, %d ignored ranges)\n", len(cfg.Traps), cfg.Traps, len(cfg.IgnoreIPs))
		return 0
	}
	fmt.Fprintf(stdout, "ran: configuration ok (%d traps: %v)\n", len(cfg.Traps), cfg.Traps)
	return 0
}
