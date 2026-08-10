package trap

import (
	"bufio"
	"context"
	"fmt"
	"log/slog"
	"net"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/st0o0/ran/internal/alert"
	"github.com/st0o0/ran/internal/config"
	"github.com/st0o0/ran/internal/metrics"
)

func testIRCConfig(addr string) *config.Config {
	return &config.Config{
		Addrs:          map[string]string{"irc": addr},
		SessionTimeout: 5 * time.Second,
		MaxSessions:    100,
		MaxPerIP:       10,
	}
}

func TestIRCTrapConnection(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()

	cfg := testIRCConfig(addr)
	reg := prometheus.NewRegistry()
	m := metrics.New(reg)
	limiter := NewLimiter(cfg.MaxSessions, cfg.MaxPerIP)

	trap := NewIRC(cfg, slog.Default(), m, limiter, alert.NoopAlerter{})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go trap.Start(ctx)
	time.Sleep(100 * time.Millisecond)

	conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))

	reader := bufio.NewReader(conn)

	fmt.Fprint(conn, "PASS secret\r\n")
	fmt.Fprint(conn, "NICK testbot\r\n")
	fmt.Fprint(conn, "USER testbot 0 * :Test Bot\r\n")

	line, err := reader.ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	if line != ":server 001 testbot :Welcome to the IRC Network\r\n" {
		t.Errorf("welcome = %q, want %q", line, ":server 001 testbot :Welcome to the IRC Network\r\n")
	}

	fmt.Fprint(conn, "PING :server\r\n")
	line, err = reader.ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	if line != "PONG :server\r\n" {
		t.Errorf("PONG = %q, want %q", line, "PONG :server\r\n")
	}

	fmt.Fprint(conn, "QUIT :bye\r\n")
	line, err = reader.ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	if line[:5] != "ERROR" {
		t.Errorf("QUIT response = %q, want ERROR prefix", line)
	}

	cancel()
	trap.Stop(context.Background())
}
