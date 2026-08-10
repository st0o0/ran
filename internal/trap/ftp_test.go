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

func testFTPConfig(addr string) *config.Config {
	return &config.Config{
		Addrs:          map[string]string{"ftp": addr},
		SessionTimeout: 5 * time.Second,
		MaxSessions:    100,
		MaxPerIP:       10,
	}
}

func TestFTPTrapConnection(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()

	cfg := testFTPConfig(addr)
	reg := prometheus.NewRegistry()
	m := metrics.New(reg)
	limiter := NewLimiter(cfg.MaxSessions, cfg.MaxPerIP)

	trap := NewFTP(cfg, slog.Default(), m, limiter, alert.NoopAlerter{})
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
	if line != "220 FTP Server ready.\r\n" {
		t.Errorf("banner = %q, want %q", line, "220 FTP Server ready.\r\n")
	}

	fmt.Fprint(conn, "USER admin\r\n")
	line, err = reader.ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	if line != "331 Password required.\r\n" {
		t.Errorf("USER response = %q, want %q", line, "331 Password required.\r\n")
	}

	fmt.Fprint(conn, "PASS secret\r\n")
	line, err = reader.ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	if line != "530 Login incorrect.\r\n" {
		t.Errorf("PASS response = %q, want %q", line, "530 Login incorrect.\r\n")
	}

	fmt.Fprint(conn, "LIST\r\n")
	line, err = reader.ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	if line != "530 Please login with USER and PASS.\r\n" {
		t.Errorf("LIST response = %q, want %q", line, "530 Please login with USER and PASS.\r\n")
	}

	fmt.Fprint(conn, "QUIT\r\n")
	line, err = reader.ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	if line != "221 Goodbye.\r\n" {
		t.Errorf("QUIT response = %q, want %q", line, "221 Goodbye.\r\n")
	}

	cancel()
	_ = trap.Stop(context.Background())
}
