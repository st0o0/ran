package main

import (
	"fmt"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/st0o0/ran/internal/config"
)

func healthcheck() int {
	cfg, err := config.Load(os.Getenv)
	if err != nil {
		return 0
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

func healthAddr(addr string) string {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return addr
	}
	if host == "" {
		host = "localhost"
	}
	return net.JoinHostPort(host, port)
}
