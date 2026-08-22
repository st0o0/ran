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

func testPOP3Config(addr string) *config.Config {
	return &config.Config{
		Addrs:          map[string]string{"pop3": addr},
		SessionTimeout: 5 * time.Second,
		MaxSessions:    100,
		MaxPerIP:       10,
	}
}

func TestPOP3TrapConnection(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()

	cfg := testPOP3Config(addr)
	reg := prometheus.NewRegistry()
	m := metrics.New(reg, "test")
	limiter := NewLimiter(cfg.MaxSessions, cfg.MaxPerIP)

	trap := NewPOP3(cfg, slog.Default(), m, limiter, alert.NoopAlerter{})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() { _ = trap.Start(ctx) }()
	time.Sleep(100 * time.Millisecond)

	conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

	reader := bufio.NewReader(conn)

	line, err := reader.ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	if line != "+OK POP3 server ready\r\n" {
		t.Errorf("banner = %q, want %q", line, "+OK POP3 server ready\r\n")
	}

	fmt.Fprint(conn, "USER admin\r\n")
	line, err = reader.ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	if line != "+OK\r\n" {
		t.Errorf("USER response = %q, want %q", line, "+OK\r\n")
	}

	fmt.Fprint(conn, "PASS secret\r\n")
	line, err = reader.ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	if line != "-ERR [AUTH] Authentication failed\r\n" {
		t.Errorf("PASS response = %q, want %q", line, "-ERR [AUTH] Authentication failed\r\n")
	}

	fmt.Fprint(conn, "QUIT\r\n")
	line, err = reader.ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	if line != "+OK Bye\r\n" {
		t.Errorf("QUIT response = %q, want %q", line, "+OK Bye\r\n")
	}

	cancel()
	_ = trap.Stop(context.Background())
}
