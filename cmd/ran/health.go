package main

import (
	"fmt"
	"net"
	"os"
	"time"

	"github.com/st0o0/ran/internal/config"
)

func healthcheck() int {
	cfg, err := config.Load(os.Getenv)
	if err != nil {
		return 0
	}
	conn, err := net.DialTimeout("tcp", cfg.MetricsAddr, 2*time.Second)
	if err != nil {
		fmt.Fprintln(os.Stderr, "ran: unhealthy")
		return 1
	}
	conn.Close()
	return 0
}
