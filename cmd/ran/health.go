package main

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
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
	for _, p := range config.WideIgnoreRanges(cfg.IgnoreIPs) {
		fmt.Fprintf(stderr, "ran: warning: RAN_IGNORE_IPS contains a very wide range %s; sessions from it never alert\n", p)
	}
	switch {
	case cfg.ProxyTrustedUnused():
		fmt.Fprintln(stderr, "ran: warning: RAN_PROXY_TRUSTED is set but RAN_PROXY_PROTOCOL is off; the list is ignored")
	case cfg.ProxyAny() && cfg.ProxyTrustAny:
		fmt.Fprintln(stderr, "ran: warning: RAN_PROXY_TRUSTED=any lets every peer forge the source address with a PROXY header")
	}
	for _, p := range config.WideIgnoreRanges(cfg.ProxyTrusted) {
		if cfg.ProxyAny() {
			fmt.Fprintf(stderr, "ran: warning: RAN_PROXY_TRUSTED contains a very wide range %s; any peer in it may forge the source address\n", p)
		}
	}
	fmt.Fprintf(stdout, "ran: configuration ok (%d traps: %v, %d ignored ranges)\n", len(cfg.Traps), cfg.Traps, len(cfg.IgnoreIPs))
	fmt.Fprintf(stdout, "ran: shun %s (repeat after %d alerts, repeat cooldown %s, alert cooldown %s)\n", onOff(cfg.Shun), cfg.RepeatAfter, cfg.EffectiveRepeatCooldown(), cfg.AlertCooldown)
	for _, w := range cfg.CrowdSecWarnings() {
		fmt.Fprintf(stderr, "ran: warning: %s\n", w)
	}
	for _, w := range cfg.CooldownWarnings() {
		fmt.Fprintf(stderr, "ran: warning: %s\n", w)
	}
	for _, name := range cfg.ProxyNotEnabled {
		fmt.Fprintf(stderr, "ran: warning: RAN_PROXY_PROTOCOL names %s, which is not in RAN_TRAPS; the entry has no effect\n", name)
	}
	if cfg.ProxyAny() {
		trusted := config.FormatPrefixes(cfg.ProxyTrusted)
		if cfg.ProxyTrustAny {
			trusted = "any"
		}
		fmt.Fprintf(stdout, "ran: PROXY protocol required on: %s (trusted peers: %s)\n", strings.Join(cfg.ProxyTrapNames(), ", "), trusted)
	} else {
		fmt.Fprintln(stdout, "ran: PROXY protocol off for all traps")
	}
	if len(cfg.HTTPFixtures) > 0 {
		fmt.Fprintf(stdout, "ran: RAN_HTTP_FIXTURES ok (%d operator fixtures)\n", len(cfg.HTTPFixtures))
	}
	return 0
}

func onOff(b bool) string {
	if b {
		return "on"
	}
	return "off"
}
