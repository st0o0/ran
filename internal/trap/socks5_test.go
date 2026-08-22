package trap

import (
	"context"
	"log/slog"
	"net"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/st0o0/ran/internal/alert"
	"github.com/st0o0/ran/internal/config"
	"github.com/st0o0/ran/internal/metrics"
)

func testSOCKS5Config(addr string) *config.Config {
	return &config.Config{
		Addrs:          map[string]string{"socks5": addr},
		SessionTimeout: 5 * time.Second,
		MaxSessions:    100,
		MaxPerIP:       10,
	}
}

func TestSOCKS5TrapUserPassAuth(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()

	cfg := testSOCKS5Config(addr)
	reg := prometheus.NewRegistry()
	m := metrics.New(reg, "test")
	limiter := NewLimiter(cfg.MaxSessions, cfg.MaxPerIP)

	trap := NewSOCKS5(cfg, slog.Default(), m, limiter, alert.NoopAlerter{})
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

	// Greeting: version 5, 2 methods (no auth + user/pass)
	_, _ = conn.Write([]byte{0x05, 0x02, 0x00, 0x02})

	resp := make([]byte, 2)
	if _, err := conn.Read(resp); err != nil {
		t.Fatal(err)
	}
	if resp[0] != 0x05 || resp[1] != 0x02 {
		t.Fatalf("method selection = %x, want [05 02]", resp)
	}

	// Send username/password auth
	username := "admin"
	password := "hunter2"
	auth := []byte{0x01, byte(len(username))}
	auth = append(auth, []byte(username)...)
	auth = append(auth, byte(len(password)))
	auth = append(auth, []byte(password)...)
	_, _ = conn.Write(auth)

	authResp := make([]byte, 2)
	if _, err := conn.Read(authResp); err != nil {
		t.Fatal(err)
	}
	if authResp[0] != 0x01 || authResp[1] != 0x01 {
		t.Fatalf("auth response = %x, want [01 01] (failure)", authResp)
	}

	cancel()
	_ = trap.Stop(context.Background())
}

func TestSOCKS5TrapNoAuth(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()

	cfg := testSOCKS5Config(addr)
	reg := prometheus.NewRegistry()
	m := metrics.New(reg, "test")
	limiter := NewLimiter(cfg.MaxSessions, cfg.MaxPerIP)

	trap := NewSOCKS5(cfg, slog.Default(), m, limiter, alert.NoopAlerter{})
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

	// Greeting: version 5, 1 method (no auth only)
	_, _ = conn.Write([]byte{0x05, 0x01, 0x00})

	resp := make([]byte, 2)
	if _, err := conn.Read(resp); err != nil {
		t.Fatal(err)
	}
	if resp[0] != 0x05 || resp[1] != 0x00 {
		t.Fatalf("method selection = %x, want [05 00]", resp)
	}

	// Send connect request to 93.184.216.34:80
	req := []byte{
		0x05, 0x01, 0x00, 0x01, // VER, CMD=CONNECT, RSV, ATYP=IPv4
		93, 184, 216, 34, // IP address
		0x00, 0x50, // port 80
	}
	_, _ = conn.Write(req)

	connResp := make([]byte, 10)
	if _, err := conn.Read(connResp); err != nil {
		t.Fatal(err)
	}
	if connResp[0] != 0x05 || connResp[1] != 0x05 {
		t.Fatalf("connect response = %x, want reply=0x05 (general failure)", connResp[:2])
	}

	cancel()
	_ = trap.Stop(context.Background())
}

func TestSOCKS5TrapDomainConnect(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()

	cfg := testSOCKS5Config(addr)
	reg := prometheus.NewRegistry()
	m := metrics.New(reg, "test")
	limiter := NewLimiter(cfg.MaxSessions, cfg.MaxPerIP)

	trap := NewSOCKS5(cfg, slog.Default(), m, limiter, alert.NoopAlerter{})
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

	// Greeting: no auth only
	_, _ = conn.Write([]byte{0x05, 0x01, 0x00})

	resp := make([]byte, 2)
	if _, err := conn.Read(resp); err != nil {
		t.Fatal(err)
	}

	// Connect to domain name
	domain := "example.com"
	req := []byte{
		0x05, 0x01, 0x00, 0x03, // VER, CMD=CONNECT, RSV, ATYP=DOMAIN
		byte(len(domain)),
	}
	req = append(req, []byte(domain)...)
	req = append(req, 0x01, 0xBB) // port 443

	_, _ = conn.Write(req)

	connResp := make([]byte, 10)
	if _, err := conn.Read(connResp); err != nil {
		t.Fatal(err)
	}
	if connResp[1] != 0x05 {
		t.Fatalf("connect reply = 0x%02x, want 0x05 (general failure)", connResp[1])
	}

	cancel()
	_ = trap.Stop(context.Background())
}

func TestSOCKS5TrapPrefersUserPass(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()

	cfg := testSOCKS5Config(addr)
	reg := prometheus.NewRegistry()
	m := metrics.New(reg, "test")
	limiter := NewLimiter(cfg.MaxSessions, cfg.MaxPerIP)

	trap := NewSOCKS5(cfg, slog.Default(), m, limiter, alert.NoopAlerter{})
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

	// Offer both methods
	_, _ = conn.Write([]byte{0x05, 0x02, 0x00, 0x02})

	resp := make([]byte, 2)
	if _, err := conn.Read(resp); err != nil {
		t.Fatal(err)
	}
	// Should prefer user/pass (0x02) over no auth (0x00)
	if resp[1] != 0x02 {
		t.Fatalf("selected method = 0x%02x, want 0x02 (username/password)", resp[1])
	}

	cancel()
	_ = trap.Stop(context.Background())
}
