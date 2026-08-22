package trap

import (
	"bufio"
	"context"
	"encoding/base64"
	"fmt"
	"net"
	"testing"
	"time"

	"log/slog"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/st0o0/ran/internal/alert"
	"github.com/st0o0/ran/internal/config"
	"github.com/st0o0/ran/internal/metrics"
)

func smtpTestConfig(t *testing.T) *config.Config {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()

	return &config.Config{
		Addrs:          map[string]string{"smtp": addr},
		SessionTimeout: 5 * time.Second,
		MaxSessions:    100,
		MaxPerIP:       10,
	}
}

func dialSMTP(t *testing.T, addr string) (net.Conn, *bufio.Reader) {
	t.Helper()
	conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	return conn, bufio.NewReader(conn)
}

func readLine(t *testing.T, r *bufio.Reader) string {
	t.Helper()
	line, err := r.ReadString('\n')
	if err != nil {
		t.Fatalf("read line: %v", err)
	}
	return line
}

func TestSMTPBanner(t *testing.T) {
	cfg := smtpTestConfig(t)
	reg := prometheus.NewRegistry()
	m := metrics.New(reg, "test")
	limiter := NewLimiter(cfg.MaxSessions, cfg.MaxPerIP)

	trap := NewSMTP(cfg, slog.Default(), m, limiter, alert.NoopAlerter{})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() { _ = trap.Start(ctx) }()
	time.Sleep(100 * time.Millisecond)

	conn, r := dialSMTP(t, cfg.TrapAddr("smtp"))
	defer conn.Close()

	banner := readLine(t, r)
	if banner != "220 mail.example.com ESMTP ready\r\n" {
		t.Errorf("banner = %q, want 220 mail.example.com ESMTP ready", banner)
	}

	cancel()
	_ = trap.Stop(context.Background())
}

func TestSMTPEHLO(t *testing.T) {
	cfg := smtpTestConfig(t)
	reg := prometheus.NewRegistry()
	m := metrics.New(reg, "test")
	limiter := NewLimiter(cfg.MaxSessions, cfg.MaxPerIP)

	trap := NewSMTP(cfg, slog.Default(), m, limiter, alert.NoopAlerter{})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() { _ = trap.Start(ctx) }()
	time.Sleep(100 * time.Millisecond)

	conn, r := dialSMTP(t, cfg.TrapAddr("smtp"))
	defer conn.Close()

	readLine(t, r) // banner

	fmt.Fprintf(conn, "EHLO test\r\n")
	line1 := readLine(t, r)
	line2 := readLine(t, r)
	line3 := readLine(t, r)

	if line1 != "250-mail.example.com\r\n" {
		t.Errorf("ehlo line1 = %q", line1)
	}
	if line2 != "250-AUTH LOGIN PLAIN\r\n" {
		t.Errorf("ehlo line2 = %q", line2)
	}
	if line3 != "250 OK\r\n" {
		t.Errorf("ehlo line3 = %q", line3)
	}

	cancel()
	_ = trap.Stop(context.Background())
}

func TestSMTPAuthLogin(t *testing.T) {
	cfg := smtpTestConfig(t)
	reg := prometheus.NewRegistry()
	m := metrics.New(reg, "test")
	limiter := NewLimiter(cfg.MaxSessions, cfg.MaxPerIP)

	trap := NewSMTP(cfg, slog.Default(), m, limiter, alert.NoopAlerter{})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() { _ = trap.Start(ctx) }()
	time.Sleep(100 * time.Millisecond)

	conn, r := dialSMTP(t, cfg.TrapAddr("smtp"))
	defer conn.Close()

	readLine(t, r) // banner

	fmt.Fprintf(conn, "EHLO test\r\n")
	readLine(t, r) // 250-mail.example.com
	readLine(t, r) // 250-AUTH LOGIN PLAIN
	readLine(t, r) // 250 OK

	fmt.Fprintf(conn, "AUTH LOGIN\r\n")
	prompt1 := readLine(t, r)
	if prompt1 != "334 VXNlcm5hbWU6\r\n" {
		t.Errorf("username prompt = %q", prompt1)
	}

	fmt.Fprintf(conn, "%s\r\n", base64.StdEncoding.EncodeToString([]byte("admin")))
	prompt2 := readLine(t, r)
	if prompt2 != "334 UGFzc3dvcmQ6\r\n" {
		t.Errorf("password prompt = %q", prompt2)
	}

	fmt.Fprintf(conn, "%s\r\n", base64.StdEncoding.EncodeToString([]byte("hunter2")))
	result := readLine(t, r)
	if result != "535 5.7.8 Authentication failed\r\n" {
		t.Errorf("auth result = %q", result)
	}

	fmt.Fprintf(conn, "QUIT\r\n")
	bye := readLine(t, r)
	if bye != "221 Bye\r\n" {
		t.Errorf("quit = %q", bye)
	}

	cancel()
	_ = trap.Stop(context.Background())
}

func TestSMTPAuthPlain(t *testing.T) {
	cfg := smtpTestConfig(t)
	reg := prometheus.NewRegistry()
	m := metrics.New(reg, "test")
	limiter := NewLimiter(cfg.MaxSessions, cfg.MaxPerIP)

	trap := NewSMTP(cfg, slog.Default(), m, limiter, alert.NoopAlerter{})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() { _ = trap.Start(ctx) }()
	time.Sleep(100 * time.Millisecond)

	conn, r := dialSMTP(t, cfg.TrapAddr("smtp"))
	defer conn.Close()

	readLine(t, r) // banner

	fmt.Fprintf(conn, "EHLO test\r\n")
	readLine(t, r)
	readLine(t, r)
	readLine(t, r)

	// AUTH PLAIN with inline payload: \0username\0password
	payload := base64.StdEncoding.EncodeToString([]byte("\x00admin\x00secret"))
	fmt.Fprintf(conn, "AUTH PLAIN %s\r\n", payload)
	result := readLine(t, r)
	if result != "535 5.7.8 Authentication failed\r\n" {
		t.Errorf("auth plain result = %q", result)
	}

	cancel()
	_ = trap.Stop(context.Background())
}

func TestSMTPMailFromWithoutAuth(t *testing.T) {
	cfg := smtpTestConfig(t)
	reg := prometheus.NewRegistry()
	m := metrics.New(reg, "test")
	limiter := NewLimiter(cfg.MaxSessions, cfg.MaxPerIP)

	trap := NewSMTP(cfg, slog.Default(), m, limiter, alert.NoopAlerter{})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() { _ = trap.Start(ctx) }()
	time.Sleep(100 * time.Millisecond)

	conn, r := dialSMTP(t, cfg.TrapAddr("smtp"))
	defer conn.Close()

	readLine(t, r) // banner

	fmt.Fprintf(conn, "MAIL FROM:<test@example.com>\r\n")
	result := readLine(t, r)
	if result != "530 5.7.1 Authentication required\r\n" {
		t.Errorf("mail from result = %q", result)
	}

	cancel()
	_ = trap.Stop(context.Background())
}
