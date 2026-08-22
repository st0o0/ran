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

func testIMAPConfig(addr string) *config.Config {
	return &config.Config{
		Addrs:          map[string]string{"imap": addr},
		SessionTimeout: 5 * time.Second,
		MaxSessions:    100,
		MaxPerIP:       10,
	}
}

func TestIMAPTrapConnection(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()

	cfg := testIMAPConfig(addr)
	reg := prometheus.NewRegistry()
	m := metrics.New(reg, "test")
	limiter := NewLimiter(cfg.MaxSessions, cfg.MaxPerIP)

	trap := NewIMAP(cfg, slog.Default(), m, limiter, alert.NoopAlerter{})
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
	if line != "* OK IMAP4rev1 Server Ready\r\n" {
		t.Errorf("banner = %q, want %q", line, "* OK IMAP4rev1 Server Ready\r\n")
	}

	fmt.Fprint(conn, "a001 CAPABILITY\r\n")
	line, err = reader.ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	if line != "* CAPABILITY IMAP4rev1 AUTH=PLAIN LOGIN STARTTLS\r\n" {
		t.Errorf("CAPABILITY untagged = %q", line)
	}
	line, err = reader.ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	if line != "a001 OK CAPABILITY completed\r\n" {
		t.Errorf("CAPABILITY tagged = %q", line)
	}

	fmt.Fprint(conn, "a002 LOGIN admin password123\r\n")
	line, err = reader.ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	if line != "a002 NO [AUTHENTICATIONFAILED] Invalid credentials\r\n" {
		t.Errorf("LOGIN response = %q, want %q", line, "a002 NO [AUTHENTICATIONFAILED] Invalid credentials\r\n")
	}

	fmt.Fprint(conn, "a003 LOGOUT\r\n")
	line, err = reader.ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	if line != "* BYE IMAP4rev1 Server logging out\r\n" {
		t.Errorf("LOGOUT BYE = %q", line)
	}
	line, err = reader.ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	if line != "a003 OK LOGOUT completed\r\n" {
		t.Errorf("LOGOUT tagged = %q", line)
	}

	cancel()
	_ = trap.Stop(context.Background())
}
