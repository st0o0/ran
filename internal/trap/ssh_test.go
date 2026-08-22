package trap

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/st0o0/ran/internal/alert"
	"github.com/st0o0/ran/internal/config"
	"github.com/st0o0/ran/internal/metrics"

	"log/slog"

	gossh "golang.org/x/crypto/ssh"
)

func testConfig(t *testing.T) *config.Config {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()

	return &config.Config{
		Traps:          []string{"ssh"},
		Addrs:          map[string]string{"ssh": addr},
		SSHHostKeyPath: "",
		SessionTimeout: 5 * time.Second,
		MaxSessions:    100,
		MaxPerIP:       10,
	}
}

func TestSSHTrapCaptures(t *testing.T) {
	cfg := testConfig(t)
	reg := prometheus.NewRegistry()
	m := metrics.New(reg, "test")
	limiter := NewLimiter(cfg.MaxSessions, cfg.MaxPerIP)
	logger := slog.Default()

	trap, err := NewSSH(cfg, logger, m, limiter, alert.NoopAlerter{})
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() { _ = trap.Start(ctx) }()
	time.Sleep(100 * time.Millisecond)

	clientCfg := &gossh.ClientConfig{
		User:            "root",
		Auth:            []gossh.AuthMethod{gossh.Password("admin123")},
		HostKeyCallback: gossh.InsecureIgnoreHostKey(),
		Timeout:         2 * time.Second,
	}

	conn, err := gossh.Dial("tcp", cfg.TrapAddr("ssh"), clientCfg)
	if err == nil {
		conn.Close()
	}

	time.Sleep(100 * time.Millisecond)
	cancel()
	_ = trap.Stop(context.Background())
}

func TestSSHHostKeyGeneration(t *testing.T) {
	logger := slog.Default()
	signer, err := loadOrGenerateHostKey("", logger)
	if err != nil {
		t.Fatalf("key generation failed: %v", err)
	}
	if signer == nil {
		t.Fatal("signer is nil")
	}
	if signer.PublicKey().Type() != "ssh-ed25519" {
		t.Errorf("key type = %s, want ssh-ed25519", signer.PublicKey().Type())
	}
}

func TestSSHBanner(t *testing.T) {
	cfg := testConfig(t)
	reg := prometheus.NewRegistry()
	m := metrics.New(reg, "test")
	limiter := NewLimiter(cfg.MaxSessions, cfg.MaxPerIP)
	logger := slog.Default()

	trap, err := NewSSH(cfg, logger, m, limiter, alert.NoopAlerter{})
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() { _ = trap.Start(ctx) }()
	time.Sleep(100 * time.Millisecond)

	conn, err := net.DialTimeout("tcp", cfg.TrapAddr("ssh"), 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	buf := make([]byte, 256)
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	banner := string(buf[:n])
	if len(banner) < 20 || banner[:8] != "SSH-2.0-" {
		t.Errorf("banner = %q, want SSH-2.0-... prefix", banner)
	}

	cancel()
	_ = trap.Stop(context.Background())
}
